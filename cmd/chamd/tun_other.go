//go:build !windows

package main

import "fmt"

// TUN для не-Windows пока не реализован (клиентская ОС — Windows 11).
type TunDevice struct{ m *Manager }

func NewTun(m *Manager) *TunDevice        { return &TunDevice{m: m} }
func (t *TunDevice) SetSocks(addr string) {}
func (t *TunDevice) Start() error {
	return fmt.Errorf("TUN поддерживается только на Windows")
}
func (t *TunDevice) Stop() {}

// AddCoverBypass — стаб для не-Windows (обходной маршрут нужен только в TUN на Windows).
func (t *TunDevice) AddCoverBypass(ip string) {}
func RunTunProbe()                            {}
func SetSystemProxy(enable bool, addr string) error {
	return fmt.Errorf("системный прокси поддерживается только на Windows")
}
