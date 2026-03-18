//go:build windows

package cli

import (
	"os"
	"os/exec"
)

// execProcess runs the given binary as a child process on Windows.
// syscall.Exec is unix-only, so we use exec.Command and forward the exit code.
func execProcess(binary string, args []string, env []string) error {
	cmd := exec.Command(binary, args[1:]...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
