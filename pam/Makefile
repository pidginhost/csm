# Build the CSM PAM module
# Requires: pam-devel package (yum install pam-devel)

CC = gcc
CFLAGS = -Wall -Wextra -O2 -fPIC
LDFLAGS = -shared -lpam

all: pam_csm.so

pam_csm.so: pam_csm.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

install: pam_csm.so
	install -m 755 pam_csm.so /lib64/security/pam_csm.so
	@echo "Installed to /lib64/security/pam_csm.so"
	@echo ""
	@echo "Add to PAM configs (optional, after testing):"
	@echo "  echo 'auth optional pam_csm.so' >> /etc/pam.d/sshd"
	@echo "  echo 'auth optional pam_csm.so' >> /etc/pam.d/pure-ftpd"

clean:
	rm -f pam_csm.so

.PHONY: all install clean
