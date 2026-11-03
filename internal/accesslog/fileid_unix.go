//go:build !windows

package accesslog

import (
	"fmt"
	"os"
	"syscall"
)

func fileID(f *os.File) (string, error) {
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("unsupported log file identity")
	}
	return fmt.Sprintf("%d:%d", stat.Dev, stat.Ino), nil
}

func openLog(path string) (*os.File, error) { return os.Open(path) }
