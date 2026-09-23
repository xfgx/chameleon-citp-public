//go:build unix

package mobilecore

// Ручная сборка стека tun2socks БЕЗ engine.Start(): engine при любой ошибке
// вызывает log.Fatalf, что на Android убивает весь процесс приложения —
// отсюда были «вылеты» при нажатии «Подключиться». Здесь любая ошибка
// (включая панику gVisor) превращается в строку и возвращается в UI.

import (
	"fmt"
	"strconv"
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/xjasonlyu/tun2socks/v2/core"
	"github.com/xjasonlyu/tun2socks/v2/core/device"
	"github.com/xjasonlyu/tun2socks/v2/core/device/fdbased"
	"github.com/xjasonlyu/tun2socks/v2/core/option"
	"github.com/xjasonlyu/tun2socks/v2/proxy/socks5"
	"github.com/xjasonlyu/tun2socks/v2/tunnel"
)

var (
	vpnDev        device.Device
	vpnStack      *stack.Stack
	tunnelMu      sync.Mutex
	tunnelRunning bool
)

// startVPNStack поднимает gVisor-стек на fd туннеля и направляет весь
// трафик в локальный SOCKS5 (который уже умеет ходить через ноду).
func startVPNStack(tunFd int32) (err error) {
	var dev device.Device
	defer func() {
		if r := recover(); r != nil {
			if dev != nil {
				dev.Close()
			}
			err = fmt.Errorf("сбой сетевого стека: %v", r)
		}
	}()

	dev, err = fdbased.Open(strconv.Itoa(int(tunFd)), 1500, 0)
	if err != nil {
		return fmt.Errorf("tun-устройство: %w", err)
	}
	px, err := socks5.New("127.0.0.1:11080", "", "")
	if err != nil {
		dev.Close()
		return fmt.Errorf("proxy: %w", err)
	}

	tunnelMu.Lock()
	tunnel.T().SetProxy(px)
	if !tunnelRunning {
		tunnel.T().ProcessAsync()
		tunnelRunning = true
	}
	tunnelMu.Unlock()

	st, err := core.CreateStack(&core.Config{
		LinkEndpoint:     dev,
		TransportHandler: tunnel.T(),
		Options: []option.Option{
			option.WithTCPModerateReceiveBuffer(true),
			option.WithTCPSendBufferSize(4 << 20),
			option.WithTCPReceiveBufferSize(4 << 20),
		},
	})
	if err != nil {
		dev.Close()
		return fmt.Errorf("create stack: %w", err)
	}
	tunnelMu.Lock()
	vpnDev, vpnStack = dev, st
	tunnelMu.Unlock()
	dev = nil // ownership transferred to vpnDev
	return nil
}

func stopVPNStack() {
	defer func() { _ = recover() }()
	tunnelMu.Lock()
	defer tunnelMu.Unlock()

	if vpnStack != nil {
		vpnStack.Close()
		vpnStack.Wait()
		vpnStack = nil
	}
	if vpnDev != nil {
		vpnDev.Close()
		vpnDev = nil
	}
	tunnelRunning = false
}
