//go:build !windows

package main

// fulltun_other.go — автонастройка маршрутов нужна только Windows-клиенту;
// на ноде (Linux) — no-op.
func setupFullTun(peerHost, tunCIDR string, listenPort int) func() { return func() {} }
