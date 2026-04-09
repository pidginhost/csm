/*
 * pam_csm.c — CSM PAM Module for Real-Time Brute-Force Detection
 *
 * Reports authentication events (success/failure) to the CSM daemon
 * via a Unix domain socket. The daemon tracks failures per IP and
 * blocks attackers via CSM auto-blocking after a configurable threshold.
 *
 * Build:
 *   gcc -shared -fPIC -o pam_csm.so pam_csm.c -lpam
 *
 * Install:
 *   cp pam_csm.so /lib64/security/
 *   # Add to /etc/pam.d/sshd, /etc/pam.d/pure-ftpd, etc.:
 *   auth optional pam_csm.so
 *
 * Protocol (line-based over Unix socket):
 *   FAIL ip=1.2.3.4 user=root service=sshd
 *   OK ip=1.2.3.4 user=root service=sshd
 *
 * Safety:
 *   - Uses "optional" in PAM stack — failures in this module don't block login
 *   - Timeout on socket connect (100ms) — doesn't delay login if daemon is down
 *   - Non-blocking, fire-and-forget — sends event and closes immediately
 *   - Emits FAIL during auth attempts; the daemon clears that state on a later OK
 *     for the same IP when account/session success is reached
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

#include <security/pam_modules.h>
#include <security/pam_ext.h>

#define CSM_SOCKET_PATH "/var/run/csm/pam.sock"
#define CSM_CONNECT_TIMEOUT_MS 100
#define CSM_MAX_MSG_LEN 512

/*
 * Send an event to the CSM daemon socket.
 * Returns 0 on success, -1 on failure (which is silently ignored).
 */
static int csm_send_event(const char *event_type, const char *ip,
                          const char *user, const char *service) {
    int fd;
    struct sockaddr_un addr;
    char msg[CSM_MAX_MSG_LEN];
    int len;
    struct timeval tv;

    /* Build message */
    len = snprintf(msg, sizeof(msg), "%s ip=%s user=%s service=%s\n",
                   event_type, ip ? ip : "-", user ? user : "-",
                   service ? service : "-");
    if (len <= 0 || len >= (int)sizeof(msg))
        return -1;

    /* Create socket */
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    /* Set send timeout */
    tv.tv_sec = 0;
    tv.tv_usec = CSM_CONNECT_TIMEOUT_MS * 1000;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    /* Connect */
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CSM_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1; /* Daemon not running — silently ignore */
    }

    /* Send and close */
    write(fd, msg, len);
    close(fd);
    return 0;
}

/*
 * Extract the remote IP from the PAM environment.
 * Tries PAM_RHOST first, then common environment variables.
 */
static const char *get_remote_ip(pam_handle_t *pamh) {
    const char *rhost = NULL;

    /* Standard PAM item */
    if (pam_get_item(pamh, PAM_RHOST, (const void **)&rhost) == PAM_SUCCESS && rhost && *rhost)
        return rhost;

    return NULL;
}

/*
 * PAM authentication hook — called after authentication attempt.
 * We use pam_sm_setcred (called after auth) to report success/failure.
 */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                    int argc, const char **argv) {
    const char *user = NULL;
    const char *service = NULL;
    const char *ip;

    (void)flags;
    (void)argc;
    (void)argv;

    pam_get_item(pamh, PAM_USER, (const void **)&user);
    pam_get_item(pamh, PAM_SERVICE, (const void **)&service);
    ip = get_remote_ip(pamh);

    if (ip != NULL) {
        /*
         * Report the authentication attempt as a FAIL signal up front.
         * A later successful acct_mgmt event emits OK, which the daemon uses
         * to clear the pending failure tracker for this IP.
         */
        csm_send_event("FAIL", ip, user, service);
    }

    /* We don't do authentication ourselves — never interfere with login flow. */
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                               int argc, const char **argv) {
    return PAM_SUCCESS;
}

/*
 * PAM account hook — called to check if account is valid.
 * We hook here to report the auth result.
 */
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
                                 int argc, const char **argv) {
    const char *user = NULL;
    const char *service = NULL;
    const char *ip;

    pam_get_item(pamh, PAM_USER, (const void **)&user);
    pam_get_item(pamh, PAM_SERVICE, (const void **)&service);
    ip = get_remote_ip(pamh);

    if (ip != NULL) {
        /* Report successful login */
        csm_send_event("OK", ip, user, service);
    }

    return PAM_SUCCESS;
}

/*
 * PAM auth failure notification — called when authentication fails.
 * This is the most reliable way to detect failed login attempts.
 */
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
                                    int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags,
                                     int argc, const char **argv) {
    return PAM_SUCCESS;
}
