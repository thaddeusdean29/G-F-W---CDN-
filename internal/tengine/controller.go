package tengine

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

type Controller struct {
	binary  string
	pidFile string
	conf    string
}

func NewController(binary, pidFile, conf string) *Controller {
	return &Controller{binary: binary, pidFile: pidFile, conf: conf}
}

// checkBinary returns a friendly error if the tengine binary is missing,
// so callers don't surface a raw "fork/exec: no such file or directory".
func (c *Controller) checkBinary() error {
	if _, err := os.Stat(c.binary); err != nil {
		return fmt.Errorf("Tengine 未安装或未找到可执行文件（%s），请检查安装日志", c.binary)
	}
	return nil
}

func (c *Controller) Test() (string, error) {
	if err := c.checkBinary(); err != nil {
		return "", err
	}
	cmd := exec.Command(c.binary, "-t", "-c", c.conf)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (c *Controller) Reload() error {
	pid, err := c.readPid()
	if err == nil {
		out, err := exec.Command("kill", "-HUP", strconv.Itoa(pid)).CombinedOutput()
		if err != nil {
			return fmt.Errorf("kill -HUP: %s: %w", string(out), err)
		}
		return nil
	}
	if err := c.checkBinary(); err != nil {
		return err
	}
	args := []string{"-s", "reload"}
	if c.conf != "" {
		args = append([]string{"-c", c.conf}, args...)
	}
	return exec.Command(c.binary, args...).Run()
}

// TestAndReload runs config test first; only reloads if test passes.
// If Tengine is not running, starts it instead of reloading.
func (c *Controller) TestAndReload() (string, error) {
	out, err := c.Test()
	if err != nil {
		return out, fmt.Errorf("config test failed: %w", err)
	}
	if c.Status() == "stopped" {
		if err := c.Start(); err != nil {
			return out, fmt.Errorf("start failed: %w", err)
		}
		return out, nil
	}
	if err := c.Reload(); err != nil {
		return out, fmt.Errorf("reload failed: %w", err)
	}
	return out, nil
}

func (c *Controller) Status() string {
	// 先检查二进制文件是否存在
	if err := c.checkBinary(); err != nil {
		return "not_installed"
	}
	pid, err := c.readPid()
	if err != nil {
		return "stopped"
	}
	// Check if process is actually running
	if err := exec.Command("kill", "-0", strconv.Itoa(pid)).Run(); err != nil {
		return "stopped"
	}
	return "running"
}

// CheckBinary 检查 Tengine 二进制文件是否存在
func (c *Controller) CheckBinary() error {
	return c.checkBinary()
}

func (c *Controller) Start() error {
	if err := c.checkBinary(); err != nil {
		return err
	}
	return exec.Command(c.binary, "-c", c.conf).Run()
}

func (c *Controller) Stop() error {
	if err := c.checkBinary(); err != nil {
		return err
	}
	return exec.Command(c.binary, "-s", "stop").Run()
}

func (c *Controller) readPid() (int, error) {
	data, err := os.ReadFile(c.pidFile)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("invalid pid file content: %w", err)
	}
	return pid, nil
}
