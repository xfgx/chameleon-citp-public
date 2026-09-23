package chaossync

// multidim_test.go — Рычаг 1, этап B: транспортный уровень многомерного
// кодирования. Доказываем, что ЦЕЛЫЙ кадр (маркер+rep3+payload+tag+crc)
// проходит по K параллельным драйв-осям в одном хаос-потоке: биты кадра
// раскладываются round-robin по K каналам (K бит на символьное окно вместо 1),
// приёмник декодирует все K через ObserverStepMulti и собирает кадр обратно.
//
// Доказанный одноканальный Endpoint НЕ меняется — тест работает на уровне
// примитивов (DeriveField/DeriveDrives/ObserverStepMulti/Perturb) поверх
// идеального канала, замеряя сквозной round-trip и кратность ёмкости.

import (
	"bytes"
	"testing"
)

func TestMultidimFrameRoundtrip(t *testing.T) {
	master := bytes.Repeat([]byte{0x42}, 32)
	c := MustDecimal("0.85")
	delta := Fxp(oneRaw >> 8) // 2^-8
	S := 32
	payload := []byte("multidim-leverage1-payload-0123456789abcdef") // 43 байта

	for _, K := range []int{1, 2, 4} {
		epoch := uint64(777)
		field := DeriveField(master, epoch)
		drives := DeriveDrives(field, K)
		mod := Modulator{Delta: delta, S: S}

		// независимость осей: все различны
		seen := map[int]bool{}
		for _, d := range drives {
			if seen[d] {
				t.Fatalf("K=%d: драйв-оси не различны: %v", K, drives)
			}
			seen[d] = true
		}

		frameBits := buildFrame(master, epoch, payload)
		txX := EpochInit(master, epoch)
		rxX := EpochInit(master, epoch)
		parser := newFrameParser()

		var got []ParsedFrame
		pos := 0
		bitErr, bitTot := 0, 0

		// прогрев на idle (посадка наблюдателя) + кадр + запас на добивку
		for w := 0; w < 30000 && len(got) == 0; w++ {
			windowBits := make([]bool, K)
			for ch := 0; ch < K; ch++ {
				if w >= 16 && pos < len(frameBits) { // 16 окон прогрева на idle
					windowBits[ch] = frameBits[pos]
					pos++
				} else {
					windowBits[ch] = IdleBit(master, epoch, uint64(w))
				}
			}
			sumR := make([]Fxp, K)
			for s := 0; s < S; s++ {
				field.Step(&txX)
				for ch := 0; ch < K; ch++ {
					mod.Perturb(&txX, drives[ch], windowBits[ch])
				}
				y := make([]Fxp, K)
				for ch := 0; ch < K; ch++ {
					y[ch] = Dequantize16(Quantize16(txX[drives[ch]]))
				}
				r := field.ObserverStepMulti(&rxX, y, c, drives)
				for ch := 0; ch < K; ch++ {
					sumR[ch] = sumR[ch].Add(r[ch])
				}
			}
			for ch := 0; ch < K; ch++ {
				bit := sumR[ch] > 0
				if w >= 16 && bitTot < len(frameBits) {
					bitTot++
					if bit != windowBits[ch] {
						bitErr++
					}
				}
				parser.Feed(bit, epoch)
			}
			for {
				f := parser.Next()
				if f == nil {
					break
				}
				got = append(got, *f)
			}
		}

		ber := 0.0
		if bitTot > 0 {
			ber = float64(bitErr) / float64(bitTot)
		}
		ok := len(got) > 0 && bytes.Equal(got[0].Payload, payload)
		// кадры на 30000 окон: одноканальный k=1 тратит len(frameBits) окон;
		// K-канальный — len(frameBits)/K. кратность = K.
		t.Logf("K=%d: roundtrip_ok=%v ber=%.5f frame_windows=%d (vs %d при K=1) throughput=x%d",
			K, ok, ber, (len(frameBits)+K-1)/K, len(frameBits), K)
		if !ok {
			t.Errorf("K=%d: кадр не собран или payload не совпал (frames=%d, ber=%.5f)", K, len(got), ber)
		}
	}
}
