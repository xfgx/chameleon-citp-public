//go:build !windows && !linux

package main

// v6rotmgr_other.go — честный отказ на платформах без реализации менеджера
// адресов (v4-функции туннеля при этом не затрагиваются).

import (
	"errors"
	"net"
)

type v6mgrUnsupported struct{}

func newV6AddrMgr(ifname string) v6AddrMgr { return v6mgrUnsupported{} }

var errV6Unsupported = errors.New("v6rot: платформа не поддерживается (есть windows/linux)")

func (v6mgrUnsupported) Setup() (func(), error) { return nil, errV6Unsupported }
func (v6mgrUnsupported) Add(ip net.IP) error    { return errV6Unsupported }
func (v6mgrUnsupported) Prune(keep int) error   { return errV6Unsupported }
