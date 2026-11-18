package main

import "golang.org/x/sys/unix"

const getTerminalAttrs = unix.TIOCGETA
const setTerminalAttrs = unix.TIOCSETA
const flushTerminalAttrs = unix.TIOCSETAF
