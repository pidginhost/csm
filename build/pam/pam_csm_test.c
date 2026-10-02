/*
 * Behaviour test for pam_csm.so. Runs real libpam stacks against a build of
 * the module whose socket path points at a listener this program owns, and
 * checks the event lines the module writes.
 *
 * Needs root: libpam reads service files only from /etc/pam.d, so the test
 * writes its own csm-test-* services there and removes them on exit. Run it
 * through `make check` in a throwaway container or CI job.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include <security/pam_appl.h>

#ifndef CSM_PAM_SOCKET
#error "build with -DCSM_PAM_SOCKET pointing at the test socket"
#endif
#ifndef CSM_PAM_TEST_MODULE
#error "build with -DCSM_PAM_TEST_MODULE pointing at the test build of pam_csm.so"
#endif

#define MOD CSM_PAM_TEST_MODULE

/* Compile the emitter with an injected clock to exercise failures through
 * the real socket. The shared module still drives the libpam stack tests. */
static int fail_clock;

static int
test_clock_gettime(clockid_t clock_id, struct timespec *now)
{
    if (fail_clock) {
        now->tv_sec = 1790000000;
        now->tv_nsec = 123456789;
        errno = EINVAL;
        return -1;
    }
    return clock_gettime(clock_id, now);
}

#define clock_gettime test_clock_gettime
#define pam_sm_authenticate test_pam_sm_authenticate
#define pam_sm_setcred test_pam_sm_setcred
#define pam_sm_open_session test_pam_sm_open_session
#define pam_sm_close_session test_pam_sm_close_session
#define pam_sm_acct_mgmt test_pam_sm_acct_mgmt
#define pam_sm_chauthtok test_pam_sm_chauthtok
#include "pam_csm.c"
#undef clock_gettime
#undef pam_sm_authenticate
#undef pam_sm_setcred
#undef pam_sm_open_session
#undef pam_sm_close_session
#undef pam_sm_acct_mgmt
#undef pam_sm_chauthtok

/* The failure hook sits where the installer puts it: directly before the
 * terminal pam_deny.so, with the success jump widened over it. The first
 * module stands in for the password check. */
#define STACK(check)                                        \
    "auth [success=2 default=ignore] " check "\n"           \
    "auth optional " MOD " authfail\n"                      \
    "auth requisite pam_deny.so\n"                          \
    "auth required pam_permit.so\n"                         \
    "auth optional " MOD "\n"                               \
    "account required pam_permit.so\n"                      \
    "session optional " MOD "\n"

static const char *services[][2] = {
    {"csm-test-fail", STACK("pam_deny.so")},
    {"csm-test-pass", STACK("pam_permit.so")},
    {"csm-test-hook-setcred", "auth optional " MOD " authfail\nauth required pam_permit.so\n"},
    {"csm-test-spaced", "auth [success = 2 default = ignore] pam_permit.so\n"
                         "auth optional " MOD " authfail\nauth requisite pam_deny.so\n"
                         "auth required pam_permit.so\n"},
    {"csm-test-end-installed", "auth required pam_permit.so\n"
                               "auth [success=2 default=ignore] pam_permit.so\n"
                               "auth optional " MOD " authfail\nauth required pam_deny.so\n"},
    {"csm-test-end-removed", "auth required pam_permit.so\n"
                             "auth [success=1 default=ignore] pam_permit.so\n"
                             "auth required pam_deny.so\n"},
    {"csm-test-overshoot", "auth required pam_permit.so\n"
                           "auth [success=3 default=ignore] pam_permit.so\n"
                           "auth optional " MOD " authfail\nauth required pam_deny.so\n"},
    {"csm-test-missing", "auth [success=3 default=ignore] pam_permit.so\n"
                         "-auth optional pam_csm_nonexistent.so\n"
                         "auth optional " MOD " authfail\nauth requisite pam_deny.so\n"
                         "auth required pam_permit.so\n"},
    {"csm-test-bracketed", "auth optional " MOD " [authfail]\nauth requisite pam_deny.so\n"},
    {"csm-test-comment", "auth optional " MOD " #authfail\nauth requisite pam_deny.so\n"},
    {"csm-test-reset", "auth required pam_deny.so\n"
                       "auth [success=resetdefault=ignore] pam_permit.so\n"
                       "auth required pam_permit.so\n"},
};

static int listen_fd = -1;
static int failures;

static int
conv(int n, const struct pam_message **msg, struct pam_response **resp, void *data)
{
    (void)n;
    (void)msg;
    (void)resp;
    (void)data;
    return PAM_CONV_ERR;
}

static void
cleanup(void)
{
    char path[256];
    size_t i;

    for (i = 0; i < sizeof(services) / sizeof(services[0]); i++) {
        snprintf(path, sizeof(path), "/etc/pam.d/%s", services[i][0]);
        unlink(path);
    }
    if (listen_fd >= 0) {
        close(listen_fd);
    }
    unlink(CSM_PAM_SOCKET);
}

static void
die(const char *what)
{
    perror(what);
    cleanup();
    exit(2);
}

static void
setup(void)
{
    struct sockaddr_un addr;
    char path[256];
    size_t i;

    for (i = 0; i < sizeof(services) / sizeof(services[0]); i++) {
        FILE *f;
        snprintf(path, sizeof(path), "/etc/pam.d/%s", services[i][0]);
        f = fopen(path, "w");
        if (!f || fputs(services[i][1], f) == EOF || fclose(f) != 0) {
            die(path);
        }
    }

    unlink(CSM_PAM_SOCKET);
    listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        die("socket");
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CSM_PAM_SOCKET, sizeof(addr.sun_path) - 1);
    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 || listen(listen_fd, 16) < 0) {
        die("bind/listen");
    }
    if (fcntl(listen_fd, F_SETFL, O_NONBLOCK) < 0) {
        die("fcntl");
    }
}

/* Collect every event line the module wrote since the last call. Each event
 * is its own connection that the module has already closed. */
static void
drain(char *buf, size_t len)
{
    size_t off = 0;

    buf[0] = '\0';
    for (;;) {
        int fd = accept(listen_fd, NULL, NULL);
        if (fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            }
            die("accept");
        }
        for (;;) {
            ssize_t n = read(fd, buf + off, len - off - 1);
            if (n <= 0) {
                break;
            }
            off += (size_t)n;
        }
        buf[off] = '\0';
        close(fd);
    }
}

static struct timespec call_start;

/* normalize checks every " ts=<seconds>.<nine digits>" field lies between the
 * start of the PAM call and now, and replaces it with " ts=T" so the rest of
 * the line can be compared exactly. A field outside that window or of
 * another shape is left alone, so the comparison rejects it. */
static void
normalize(char *events)
{
    struct timespec now;
    char *p = events;

    clock_gettime(CLOCK_REALTIME, &now);
    while ((p = strstr(p, " ts=")) != NULL) {
        char *num = p + 4, *dot = num, *end;
        long long sec = 0;
        long nsec = 0;
        int digits = 0;

        while (*dot >= '0' && *dot <= '9') {
            sec = sec * 10 + (*dot - '0');
            dot++;
        }
        end = dot;
        if (*dot == '.') {
            for (end = dot + 1; *end >= '0' && *end <= '9'; end++, digits++) {
                nsec = nsec * 10 + (*end - '0');
            }
        }
        if (dot == num || *dot != '.' || digits != 9 ||
            sec < (long long)call_start.tv_sec || sec > (long long)now.tv_sec ||
            (sec == (long long)call_start.tv_sec && nsec < call_start.tv_nsec) ||
            (sec == (long long)now.tv_sec && nsec > now.tv_nsec)) {
            p = end;
            continue;
        }
        memmove(p + 5, end, strlen(end) + 1);
        memcpy(p, " ts=T", 5);
        p += 5;
    }
}

/* event builds an expected line: the module adds its pid and a timestamp. */
static const char *
event(const char *verdict, const char *ip, const char *user, const char *service)
{
    static char buf[512];

    snprintf(buf, sizeof(buf), "%s ip=%s user=%s service=%s pid=%ld ts=T\n", verdict, ip, user, service, (long)getpid());
    return buf;
}

static void
expect(const char *step, int got_rc, int want_rc, const char *got, const char *want)
{
    if (got_rc != want_rc) {
        fprintf(stderr, "FAIL %s: PAM result %d, want %d\n", step, got_rc, want_rc);
        failures++;
    }
    if (strcmp(got, want) != 0) {
        fprintf(stderr, "FAIL %s: events\n  got:  %s\n  want: %s\n", step, got[0] ? got : "(none)\n",
                want[0] ? want : "(none)\n");
        failures++;
    }
}

static pam_handle_t *
start(const char *service, const char *user, const char *rhost)
{
    static struct pam_conv pc = {conv, NULL};
    pam_handle_t *pamh = NULL;

    clock_gettime(CLOCK_REALTIME, &call_start);
    if (pam_start(service, user, &pc, &pamh) != PAM_SUCCESS) {
        die("pam_start");
    }
    if (rhost && pam_set_item(pamh, PAM_RHOST, rhost) != PAM_SUCCESS) {
        die("pam_set_item");
    }
    return pamh;
}

static int
authenticate(pam_handle_t *pamh)
{
    int rc = pam_authenticate(pamh, 0);
    return rc == PAM_SUCCESS ? PAM_SUCCESS : PAM_AUTH_ERR;
}

int
main(void)
{
    char events[4096];
    pam_handle_t *pamh;
    int rc;

    setup();

    /* A failed clock cannot supply provenance, but the event still counts
     * through the older, identity-free wire format. */
    pamh = start("csm-test-fail", "intruder", "192.0.2.15");
    fail_clock = 1;
    rc = csm_emit("FAIL", pamh);
    fail_clock = 0;
    drain(events, sizeof(events));
    expect("failed clock", rc, 1, events,
           "FAIL ip=192.0.2.15 user=intruder service=csm-test-fail\n");
    pam_end(pamh, PAM_SUCCESS);

    /* Maximum sanitized values plus provenance must fit without losing
     * the newline, so older listeners can still parse a complete record. */
    {
        char value[CSM_PAM_MAX_VALUE_LEN], want[512];

        memset(value, 'x', sizeof(value) - 1);
        value[sizeof(value) - 1] = '\0';
        pamh = start(value, value, value);
        rc = csm_emit("FAIL", pamh);
        drain(events, sizeof(events));
        normalize(events);
        snprintf(want, sizeof(want), "%s", event("FAIL", value, value, value));
        expect("maximum values", rc, 1, events, want);
        pam_end(pamh, PAM_SUCCESS);
    }

    /* A failed login reaches the failure hook once. */
    pamh = start("csm-test-fail", "intruder", "192.0.2.10");
    rc = authenticate(pamh);
    drain(events, sizeof(events));
    normalize(events);
    expect("failed login", rc, PAM_AUTH_ERR, events, event("FAIL", "192.0.2.10", "intruder", "csm-test-fail"));
    pam_end(pamh, rc);

    /* A successful login jumps over the failure hook; the plain line
     * reports it once, at setcred, and open_session stays quiet. */
    pamh = start("csm-test-pass", "alice", "192.0.2.11");
    rc = authenticate(pamh);
    drain(events, sizeof(events));
    expect("successful login, authenticate", rc, PAM_SUCCESS, events, "");
    rc = pam_setcred(pamh, PAM_ESTABLISH_CRED);
    drain(events, sizeof(events));
    normalize(events);
    expect("successful login, setcred", rc, PAM_SUCCESS, events, event("OK", "192.0.2.11", "alice", "csm-test-pass"));
    rc = pam_open_session(pamh, 0);
    drain(events, sizeof(events));
    expect("successful login, open_session", rc, PAM_SUCCESS, events, "");
    pam_end(pamh, rc);

    /* Without a remote host the attempt is local and never reported. */
    pamh = start("csm-test-fail", "intruder", NULL);
    rc = authenticate(pamh);
    drain(events, sizeof(events));
    expect("local failed login", rc, PAM_AUTH_ERR, events, "");
    pam_end(pamh, rc);

    /* The failure hook never reports a success, even when setcred walks
     * through it. */
    pamh = start("csm-test-hook-setcred", "alice", "192.0.2.12");
    rc = pam_setcred(pamh, PAM_ESTABLISH_CRED);
    drain(events, sizeof(events));
    expect("failure hook at setcred", rc, PAM_SUCCESS, events, "");
    pam_end(pamh, rc);

    /* These stacks match the editor's widened counts, including the exact
     * end target and the restored count after uninstall. Missing -auth
     * modules still count towards jumps in Linux-PAM. */
    {
        static const char *successful[] = {
            "csm-test-spaced", "csm-test-end-installed", "csm-test-end-removed",
            "csm-test-missing", "csm-test-reset",
        };
        size_t i;
        for (i = 0; i < sizeof(successful) / sizeof(successful[0]); i++) {
            pamh = start(successful[i], "alice", "192.0.2.13");
            rc = pam_authenticate(pamh, 0);
            drain(events, sizeof(events));
            expect(successful[i], rc, PAM_SUCCESS, events, "");
            pam_end(pamh, rc);
        }
    }

    /* Going past the end is an error, unlike landing exactly at the end. */
    pamh = start("csm-test-overshoot", "alice", "192.0.2.13");
    rc = pam_authenticate(pamh, 0);
    drain(events, sizeof(events));
    expect("jump past end", rc, PAM_PERM_DENIED, events, "");
    pam_end(pamh, rc);

    /* PAM strips brackets from grouped arguments and drops inline comments. */
    pamh = start("csm-test-bracketed", "intruder", "192.0.2.14");
    rc = authenticate(pamh);
    drain(events, sizeof(events));
    normalize(events);
    expect("bracketed authfail", rc, PAM_AUTH_ERR, events, event("FAIL", "192.0.2.14", "intruder", "csm-test-bracketed"));
    pam_end(pamh, rc);

    pamh = start("csm-test-comment", "intruder", "192.0.2.14");
    rc = authenticate(pamh);
    drain(events, sizeof(events));
    expect("commented authfail", rc, PAM_AUTH_ERR, events, "");
    pam_end(pamh, rc);

    cleanup();
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("pam_csm.so: all checks passed\n");
    return 0;
}
