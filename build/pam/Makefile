# Minimal Makefile for the CSM PAM module. The top-level `make build-pam`
# invokes this target, then copies pam_csm.so into dist/ for nFPM.
#
# Requires libpam-devel (RHEL) or libpam0g-dev (Debian) on the build
# host. CI installs the matching development package before invoking
# this target.

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -Wstrict-prototypes -fPIC
LDFLAGS ?= -shared
LIBS    ?= -lpam

TARGET = pam_csm.so
SRC    = pam_csm.c

# `make check` builds a copy of the module that talks to a test socket and
# drives it through real libpam stacks. It writes csm-test-* services under
# /etc/pam.d, so run it as root in a throwaway container or CI job.
CHECK_SOCKET ?= /tmp/csm-pam-check.sock
CHECK_MODULE  = $(CURDIR)/pam_csm_check.so

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIBS)

pam_csm_check.so: $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -DCSM_PAM_SOCKET='"$(CHECK_SOCKET)"' -o $@ $< $(LIBS)

pam_csm_test: pam_csm_test.c pam_csm_check.so
	$(CC) -O2 -Wall -Wextra -DCSM_PAM_SOCKET='"$(CHECK_SOCKET)"' \
		-DCSM_PAM_TEST_MODULE='"$(CHECK_MODULE)"' -o $@ pam_csm_test.c -lpam

check: pam_csm_test
	./pam_csm_test

clean:
	rm -f $(TARGET) pam_csm_check.so pam_csm_test

.PHONY: all check clean
