# Build the CSM PAM module.
# Requires libpam-devel (RHEL) or libpam0g-dev (Debian).

CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -Wstrict-prototypes -fPIC
LDFLAGS ?= -shared
LIBS ?= -lpam

all: pam_csm.so

pam_csm.so: pam_csm.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIBS)

install: pam_csm.so
	install -m 755 pam_csm.so /lib64/security/pam_csm.so
	@echo "Installed to /lib64/security/pam_csm.so"
	@echo ""
	@echo "Add to PAM configs (optional, after testing):"
	@echo "  echo 'auth optional pam_csm.so' >> /etc/pam.d/sshd"
	@echo "  echo 'session optional pam_csm.so' >> /etc/pam.d/sshd"

clean:
	rm -f pam_csm.so

.PHONY: all install clean
