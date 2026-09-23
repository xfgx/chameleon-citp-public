package chameleon

// cf_dns_epoch_test.go — Этап C3: анти-кэш DNS-маячка. Эпохальные метки
// (имя меняется каждую эпоху -> кэш резолвера не отдаёт прошлую эпоху) и
// минимальный TTL в ответе.

import (
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestDNSBeaconEpochAntiCache(t *testing.T) {
	beacon := NewDNSBeacon("127.0.0.1:0", "dd.phantom.lab", "c", 5)
	go func() { _ = beacon.Serve() }()
	addr := waitAddr(beacon.LocalAddr)
	defer func() { _ = beacon.Close() }()

	// Публикуем разные чанки под метками двух соседних эпох.
	labelE100 := DNSEpochLabel("c", 0, 100)
	labelE101 := DNSEpochLabel("c", 0, 101)
	if labelE100 == labelE101 {
		t.Fatal("метки соседних эпох обязаны различаться (иначе кэш отдаст старьё)")
	}
	beacon.PublishLabeled(labelE100, []byte("epoch-100-data"))
	beacon.PublishLabeled(labelE101, []byte("epoch-101-data"))

	h, p := hostPort(addr)
	reader := NewDNSBeaconReader(h, p, "dd.phantom.lab", "c")

	got100, err := reader.ReadChunkLabel(labelE100)
	if err != nil {
		t.Fatal(err)
	}
	got101, err := reader.ReadChunkLabel(labelE101)
	if err != nil {
		t.Fatal(err)
	}
	if string(got100) != "epoch-100-data" || string(got101) != "epoch-101-data" {
		t.Fatalf("эпохальные метки: got %q / %q", got100, got101)
	}

	// Обратная совместимость: числовой seq по-прежнему работает.
	beacon.Publish(7, []byte("legacy-seq"))
	if got, err := reader.ReadChunk(7); err != nil || string(got) != "legacy-seq" {
		t.Fatalf("legacy seq: got %q err=%v", got, err)
	}

	// TTL в ответе — минимальный (5), как задали: кэш не держит запись долго.
	name := labelE101 + ".dd.phantom.lab."
	query, err := buildDNSQuery(name)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP(h), Port: p})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write(query); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	var pr dnsmessage.Parser
	if _, err := pr.Start(buf[:n]); err != nil {
		t.Fatal(err)
	}
	if err := pr.SkipAllQuestions(); err != nil {
		t.Fatal(err)
	}
	hdr, err := pr.AnswerHeader()
	if err != nil {
		t.Fatal(err)
	}
	if hdr.TTL != 5 {
		t.Fatalf("TTL=%d, ожидался минимальный 5", hdr.TTL)
	}
	if !strings.HasSuffix(strings.ToLower(hdr.Name.String()), "dd.phantom.lab.") {
		t.Fatalf("ответ не из нашей зоны: %s", hdr.Name)
	}
}
