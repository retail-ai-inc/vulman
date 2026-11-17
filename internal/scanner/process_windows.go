package scanner

import (
	"context"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/sys/windows"
)

func configureProcess(cmd *exec.Cmd) {
	cmd.Cancel = func() error {
		// Cancel Git and scanner child processes along with the process we started.
		systemDir, err := windows.GetSystemDirectory()
		if err != nil {
			return cmd.Process.Kill()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// #nosec G204 -- The executable comes from Windows and the only variable argument is the child process's numeric PID.
		kill := exec.CommandContext(ctx, filepath.Join(systemDir, "taskkill.exe"), "/PID", strconv.Itoa(cmd.Process.Pid), "/T", "/F")
		kill.WaitDelay = time.Second
		if err := kill.Run(); err != nil {
			return cmd.Process.Kill()
		}
		return nil
	}
}
