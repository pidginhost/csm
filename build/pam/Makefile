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

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIBS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
