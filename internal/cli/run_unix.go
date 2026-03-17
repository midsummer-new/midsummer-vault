//go:build !windows

package cli

import "syscall"

// execProcess replaces the current process with the given binary (unix only).
// Signals pass through automatically since we replace the process entirely.
func execProcess(binary string, args []string, env []string) error {
	return syscall.Exec(binary, args, env)
}
