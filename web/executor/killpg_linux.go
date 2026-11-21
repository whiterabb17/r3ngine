//go:build linux

package main

import "syscall"

func killProcessGroupPID(pid int) error {
	return syscall.Kill(-pid, syscall.SIGKILL)
}
