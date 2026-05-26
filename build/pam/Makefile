# Minimal Makefile for the CSM PAM module. The package build invokes
# `make -C build/pam` to produce pam_csm.so; the nfpm packaging glob
# picks it up from the same directory.
#
# Requires libpam-devel (RHEL) or libpam0g-dev (Debian) on the build
# host. The CI builder image already ships both because the runtime
# YARA-X cross-compile uses gcc anyway.

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
