// Command citp-sim — бенчмарк и симулятор CITP v3.0 (CPI-Scatter + ZPL4).
//
// Симулирует генерацию N фантомных пакетов: 12 байт данных в полях TCP
// (Seq/Ack/TSval) при нулевом L7 payload, случайный публичный Destination IP
// на каждый пакет (CPI-Scatter), проверка целостности декодированием и замер
// энтропии Шеннона заголовков.
//
// Симулируется криптографический слой. Отправка сырых TCP-заголовков на
// провод (AF_PACKET/eBPF) — инфраструктурный слой, как и у refraction
// carrier, и здесь сознательно не выполняется.
package main

import (
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"time"

	"chameleon/internal/chameleon"
)

func main() {
	count := flag.Int("count", 100000, "количество пакетов симуляции")
	flag.Parse()

	fmt.Println("================================================================================")
	fmt.Println("   CITP v3.0 BENCHMARK & SIMULATOR (CPI-Scatter & ZPL4)")
	fmt.Println("================================================================================")
	fmt.Println(" 1. CPI-Scatter: каждый пакет — к случайному публичному IP, без единого server IP.")
	fmt.Println(" 2. ZPL4: 12 байт внутри TCP Seq/Ack/TSval, L7 payload = 0 байт.")
	fmt.Println("================================================================================")

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		fmt.Fprintln(os.Stderr, "rand:", err)
		os.Exit(1)
	}
	engine := chameleon.NewPhantomEngine(secret)

	fmt.Printf("\n[+] Генерация %d пакетов CPI-Scatter + ZPL4...\n", *count)
	start := time.Now()

	var decodedOK uint64
	distinctIPs := make(map[string]struct{})
	distinctPorts := make(map[uint16]struct{})
	headerBytes := make([]byte, 0, *count*12)

	for i := 0; i < *count; i++ {
		var chunk [12]byte
		binary.BigEndian.PutUint64(chunk[0:8], uint64(i+1000))
		binary.BigEndian.PutUint32(chunk[8:12], uint32(i*7))

		targetIP := chameleon.GenerateRandomIP(uint64(i))
		targetPort := uint16(53 + (i % 1000))

		hdr := engine.EncodeZPL4(chunk, nil, targetIP, targetPort)
		distinctIPs[hdr.DstIP.String()] = struct{}{}
		distinctPorts[hdr.DstPort] = struct{}{}

		// Декодирование на стороне сопряжённой ноды (seqNum синхронен)
		res, ok := engine.DecodeZPL4(hdr, uint64(i+1))
		if ok && binary.BigEndian.Uint64(res[0:8]) == uint64(i+1000) {
			decodedOK++
		}

		var w [12]byte
		binary.BigEndian.PutUint32(w[0:4], hdr.Seq)
		binary.BigEndian.PutUint32(w[4:8], hdr.Ack)
		binary.BigEndian.PutUint32(w[8:12], hdr.TSval)
		headerBytes = append(headerBytes, w[:]...)
	}

	elapsed := time.Since(start)
	pps := float64(*count) / elapsed.Seconds()
	mbps := float64(*count) * 12 * 8 / elapsed.Seconds() / 1e6
	entropy := chameleon.CalculateShannonEntropy(headerBytes)
	integrity := float64(decodedOK) / float64(*count) * 100

	fmt.Println()
	fmt.Println("РЕЗУЛЬТАТЫ СИМУЛЯЦИИ:")
	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Printf("• Пакетов обработано:            %d\n", *count)
	fmt.Printf("• Время выполнения:              %v\n", elapsed)
	fmt.Printf("• Скорость encode+decode:        %.0f пакетов/сек (%.2f Мбит/с полезных ZPL4-бит)\n", pps, mbps)
	fmt.Printf("• Целостность декодирования:     %.4f%%\n", integrity)
	fmt.Printf("• Уникальных Destination IP:     %d\n", len(distinctIPs))
	fmt.Printf("• Уникальных Destination портов: %d (порты 53-1052)\n", len(distinctPorts))
	fmt.Printf("• Энтропия Шеннона заголовков:   %.4f / 8.0000\n", entropy)
	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Println("Модельная оценка устойчивости к DPI/ТСПУ (симуляция, не замер на проводе):")
	fmt.Println("  - Destination IP: ротация на каждый пакет → статический IP-бан неприменим")
	fmt.Println("  - L7 payload: 0 байт → сигнатурному DPI не за что зацепиться")
	fmt.Println("  - TCP state: stateful-поток отсутствует → отслеживание Seq/Ack бессмысленно")
	fmt.Println("--------------------------------------------------------------------------------")

	if decodedOK != uint64(*count) {
		fmt.Fprintln(os.Stderr, "\n[!] ЦЕЛОСТНОСТЬ НАРУШЕНА — тест провален")
		os.Exit(1)
	}
	fmt.Println("\n[+] Тест завершен успешно: 100% пакетов декодированы и аутентифицированы.")
}
