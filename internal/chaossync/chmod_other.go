//go:build !windows

package chaossync

import "os"

func chmod0644(path string) error { return os.Chmod(path, 0o644) }
