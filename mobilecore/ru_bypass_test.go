package mobilecore

import (
	"net"
	"testing"
)

func TestRussianIPv4Lookup(t *testing.T) {
	if !isRussianIPv4(net.ParseIP("5.136.0.1")) {
		t.Fatal("known RU address not detected")
	}
	if isRussianIPv4(net.ParseIP("8.8.8.8")) {
		t.Fatal("non-RU address detected as RU")
	}
}

func TestDNSQuestionDomain(t *testing.T) {
	p := []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 6, 'y', 'a', 'n', 'd', 'e', 'x', 2, 'r', 'u', 0, 0, 1, 0, 1}
	if got := dnsQuestionDomain(p); got != "yandex.ru" {
		t.Fatalf("got %q", got)
	}
}
