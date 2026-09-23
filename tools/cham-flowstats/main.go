package main

import (
	"flag"
	"fmt"
	"math"
	"time"
)

// FlowRecord — запись параметров анализируемого сетевого потока.
type FlowRecord struct {
	Timestamp      time.Time
	PacketSizes    []int
	InterarrivalMs []float64
	Direction      []int // +1 client->node, -1 node->client
	TotalBytesUp   int
	TotalBytesDown int
}

// FlowStats вычисляет метрики энтропии, вариации длин пакетов и коэффициенты CBR.
type FlowStats struct {
	PacketCount      int     `json:"packet_count"`
	MeanPacketSize   float64 `json:"mean_packet_size"`
	StdDevPacketSize float64 `json:"stddev_packet_size"`
	MeanIntervalMs   float64 `json:"mean_interval_ms"`
	StdDevIntervalMs float64 `json:"stddev_interval_ms"`
	EntropyEstimate  float64 `json:"entropy_estimate"`
	CBRRegularity    float64 `json:"cbr_regularity"` // 0..1 (1 = идеальный CBR поток)
}

func AnalyzeFlow(f *FlowRecord) FlowStats {
	if len(f.PacketSizes) == 0 {
		return FlowStats{}
	}
	var sumSize, sumSqSize float64
	for _, s := range f.PacketSizes {
		sumSize += float64(s)
	}
	meanSize := sumSize / float64(len(f.PacketSizes))
	for _, s := range f.PacketSizes {
		d := float64(s) - meanSize
		sumSqSize += d * d
	}
	stdDevSize := math.Sqrt(sumSqSize / float64(len(f.PacketSizes)))

	var sumInt, sumSqInt float64
	for _, iv := range f.InterarrivalMs {
		sumInt += iv
	}
	meanInt := 0.0
	stdDevInt := 0.0
	if len(f.InterarrivalMs) > 0 {
		meanInt = sumInt / float64(len(f.InterarrivalMs))
		for _, iv := range f.InterarrivalMs {
			d := iv - meanInt
			sumSqInt += d * d
		}
		stdDevInt = math.Sqrt(sumSqInt / float64(len(f.InterarrivalMs)))
	}

	// Оценка регулярности CBR (чем меньше дисперсия интервалов, тем выше регулярность)
	regularity := 1.0
	if meanInt > 0 {
		cv := stdDevInt / meanInt
		regularity = math.Max(0, 1.0-cv)
	}

	return FlowStats{
		PacketCount:      len(f.PacketSizes),
		MeanPacketSize:   meanSize,
		StdDevPacketSize: stdDevSize,
		MeanIntervalMs:   meanInt,
		StdDevIntervalMs: stdDevInt,
		CBRRegularity:    regularity,
	}
}

func main() {
	profile := flag.String("profile", "cbr-40ms", "имя анализируемого профиля")
	flag.Parse()

	fmt.Printf("[DPI Bench] Запуск анализатора профиля трафика: %s\n", *profile)

	// Симуляция потока с CBR 40ms + jitter 8ms
	flow := &FlowRecord{}
	for i := 0; i < 100; i++ {
		flow.PacketSizes = append(flow.PacketSizes, 1400)
		flow.InterarrivalMs = append(flow.InterarrivalMs, 40.0+(float64(i%5)-2.0))
	}

	stats := AnalyzeFlow(flow)
	fmt.Printf("Результаты анализа:\n")
	fmt.Printf(" - Пакетов: %d\n", stats.PacketCount)
	fmt.Printf(" - Средний размер пакета: %.1f B (stddev: %.1f)\n", stats.MeanPacketSize, stats.StdDevPacketSize)
	fmt.Printf(" - Средний интервал: %.2f ms (stddev: %.2f ms)\n", stats.MeanIntervalMs, stats.StdDevIntervalMs)
	fmt.Printf(" - CBR Регулярность ритма: %.3f / 1.000\n", stats.CBRRegularity)
}
