//go:build windows

package chaossync

// На Windows POSIX-права неприменимы (защита ключа — через ACL/EFS,
// см. README-RUN.txt); тестовая проверка 0644 там не выполняется.
func chmod0644(path string) error { return nil }
