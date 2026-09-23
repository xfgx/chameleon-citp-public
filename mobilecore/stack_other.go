//go:build !unix

package mobilecore

// Заглушка для платформ без fd-based tun (Windows и пр.) — чтобы пакет
// собирался и проходил vet на десктопе. На Android используется stack_unix.go.

import "fmt"

func startVPNStack(tunFd int32) error {
	return fmt.Errorf("tun-стек на этой платформе не поддерживается")
}

func stopVPNStack() {}
