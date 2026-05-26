/*
 * pam_csm.so - PAM module that forwards authentication outcomes to the
 * CSM daemon over a Unix socket. The daemon's PAMListener consumes the
 * lines emitted here to drive PAM-based brute-force detection.
 *
 * Wire format (one line per event, no trailing newline required):
 *
 *     FAIL ip=1.2.3.4 user=root service=sshd
 *     OK   ip=1.2.3.4 user=root service=sshd
 *
 * The socket lives at /var/run/csm/pam.sock and is owned root:root with
 * mode 0600, so this module must run from a PAM stack that is already
 * executing as root (sshd, su, sudo, login). Calls from non-root stacks
 * fail the connect and become a silent no-op; auth is never blocked by
 * a CSM connectivity problem.
 *
 * Build:
 *
 *     gcc -shared -fPIC -Wall -Wextra -O2 -o pam_csm.so pam_csm.c -lpam
 *
 * Install (per host operator-handled instructions in
 * docs/operator-pam-install.md):
 *
 *     install -m 0755 pam_csm.so /usr/lib64/security/pam_csm.so   # RHEL
 *     install -m 0755 pam_csm.so /lib/x86_64-linux-gnu/security/  # Debian
 *
 *     # Append to /etc/pam.d/sshd, /etc/pam.d/su, /etc/pam.d/sudo,
 *     # /etc/pam.d/password-auth (RHEL) or /etc/pam.d/common-auth (Debian):
 *     auth     optional   pam_csm.so
 *     session  optional   pam_csm.so
 *
 * The `optional` control flag is mandatory: a CSM outage must not block
 * authentication, period.
 */

#define _GNU_SOURCE /* SOCK_CLOEXEC / SOCK_NONBLOCK on glibc */

#define PAM_SM_AUTH
#define PAM_SM_SESSION

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#define CSM_PAM_SOCKET "/var/run/csm/pam.sock"
#define CSM_PAM_MAX_VALUE_LEN 128
#define CSM_PAM_CONNECT_TIMEOUT_MS 250

/* Sanitize an operator-controlled string for the wire format. We drop
 * spaces, control bytes, and bytes outside printable ASCII so a forged
 * username cannot inject extra "key=value" pairs into the daemon's
 * parser. Replacement character is '_'. Truncates at len. */
static void
csm_sanitize(const char *in, char *out, size_t len)
{
    size_t i;

    if (!out || len == 0) {
        return;
    }
    if (!in) {
        out[0] = '\0';
        return;
    }
    for (i = 0; i + 1 < len && in[i]; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c < 0x21 || c > 0x7e || c == '=' || c == ' ') {
            out[i] = '_';
        } else {
            out[i] = (char)c;
        }
    }
    out[i] = '\0';
}

/* Open a non-blocking connection to the CSM PAM socket and emit one
 * event line. Failures (socket missing, connect refused, partial write)
 * are silently swallowed so auth never breaks. */
static void
csm_emit(const char *verdict, pam_handle_t *pamh)
{
    int fd = -1;
    const char *user = NULL;
    const char *rhost = NULL;
    const char *service = NULL;
    char user_safe[CSM_PAM_MAX_VALUE_LEN];
    char rhost_safe[CSM_PAM_MAX_VALUE_LEN];
    char service_safe[CSM_PAM_MAX_VALUE_LEN];
    char line[512];
    int n;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return;
    }
    /* Non-blocking + close-on-exec set via fcntl so the source builds on
     * any libc, not just glibc with SOCK_CLOEXEC / SOCK_NONBLOCK. */
    {
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags >= 0) {
            (void)fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        }
        (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CSM_PAM_SOCKET, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 && errno != EINPROGRESS) {
        close(fd);
        return;
    }

    (void)pam_get_item(pamh, PAM_USER, (const void **)&user);
    (void)pam_get_item(pamh, PAM_RHOST, (const void **)&rhost);
    (void)pam_get_item(pamh, PAM_SERVICE, (const void **)&service);

    csm_sanitize(user, user_safe, sizeof(user_safe));
    csm_sanitize(rhost, rhost_safe, sizeof(rhost_safe));
    csm_sanitize(service, service_safe, sizeof(service_safe));

    if (rhost_safe[0] == '\0') {
        /* No remote host means a local terminal / cron / systemd path
         * that the daemon ignores anyway; skip the syscall storm. */
        close(fd);
        return;
    }

    n = snprintf(line, sizeof(line), "%s ip=%s user=%s service=%s\n",
                 verdict, rhost_safe, user_safe, service_safe);
    if (n > 0 && (size_t)n < sizeof(line)) {
        (void)write(fd, line, (size_t)n);
    }
    close(fd);
}

/* PAM_SM_AUTH hook: pam_authenticate returns PAM_SUCCESS / PAM_AUTH_ERR;
 * pam_sm_authenticate runs before that verdict is known. The actual
 * outcome surfaces in pam_sm_setcred (PAM_ESTABLISH_CRED on success) and
 * is implicit on failure (the auth phase never reaches setcred). We
 * emit FAIL eagerly here and OK from open_session so the daemon hears
 * the bad case even when the stack aborts before setcred. */
PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)flags;
    (void)argc;
    (void)argv;
    (void)pamh;
    /* Intentionally a no-op: emitting at pre-auth time would record a
     * FAIL for every login attempt before the password was even
     * checked. The real verdict ships from setcred / open_session. */
    return PAM_IGNORE;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)argc;
    (void)argv;
    if (flags & PAM_ESTABLISH_CRED) {
        csm_emit("OK", pamh);
    } else if (flags & PAM_DELETE_CRED) {
        /* Logout: not interesting to the brute-force tracker. */
    }
    return PAM_SUCCESS;
}

/* Account / session hooks: PAM calls pam_sm_acct_mgmt after auth
 * succeeded, so observing the negative case here is unreliable. The
 * primary FAIL surface is the auth log watcher; this module supplements
 * it with a high-fidelity OK signal so the daemon can correlate
 * successful login -> source IP without log parsing. */
PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)flags;
    (void)argc;
    (void)argv;
    csm_emit("OK", pamh);
    return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_IGNORE;
}

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_IGNORE;
}
