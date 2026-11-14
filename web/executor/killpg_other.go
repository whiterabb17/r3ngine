//go:build !linux

package main

import (
	"fmt"
	"os"
)

func killProcessGroupPID(pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if err := proc.Kill(); err != nil {
		return fmt.Errorf("kill pid %d: %w", pid, err)
	}
	return nil
}
