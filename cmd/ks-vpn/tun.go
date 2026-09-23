package main

// tunDevice — платформенная TUN-абстракция. Linux: /dev/net/tun (tun_linux.go).
// Windows: Wintun (tun_windows.go). Насос (main.go) использует только Read/Write.
type tunDevice interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
}
