package e2e

import "syscall"

var (
	sigCont = syscall.SIGCONT
	sigStop = syscall.SIGSTOP
)
