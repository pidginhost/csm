package main

import "golang.org/x/sys/unix"

const getTerminalAttrs = unix.TCGETS
const setTerminalAttrs = unix.TCSETS
const flushTerminalAttrs = unix.TCSETSF
