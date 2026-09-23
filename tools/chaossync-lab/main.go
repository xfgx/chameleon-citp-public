// chaossync-lab — лаборатория транспорта chaossync (этапы Э2/Э3/Э6).
//
// Subcommands:
//
//	selftest   печать канонического хэша ядра (Э1)
//	ber        BER окна vs S, δ, c, clip на идеальном канале (Э3)
//	sync       время до синхронизма и остаточная ошибка, loopback (Э2)
//	mutate     ре-синхронизация после мутаций vs T и потери (Э6а, эмуляция)
//	recon      окно реконструкции атакующего: стационарное vs мутирующее (Э6б)
//
// Всё чисто вычислительное (loopback/эмуляция), детерминированные сиды.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"time"

	"chameleon/internal/chaossync"
)

var labMaster = bytes.Repeat([]byte{0x42}, 32)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: chaossync-lab <selftest|ber|sync|mutate|recon> [flags]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "selftest":
		fmt.Println(chaossync.SelftestVector())
	case "ber":
		cmdBER(os.Args[2:])
	case "sync":
		cmdSync(os.Args[2:])
	case "mutate":
		cmdMutate(os.Args[2:])
	case "recon":
		cmdRecon(os.Args[2:])
	case "multidim":
		cmdMultidim(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "unknown subcommand:", os.Args[1])
		os.Exit(2)
	}
}

// --- Э3: BER vs параметры модуляции ---------------------------------------

// measureWinBER — доля ошибочно декодированных окон на идеальном канале:
// tx и rx с одинаковым полем; rx — наблюдатель Pecora–Carroll; декод = знак
// суммы residual за окно (с опциональным клиппингом ±clipK·δ).
func measureWinBER(S int, delta, coup chaossync.Fxp, clipK int, windows int, epoch uint64) float64 {
	p := chaossync.DeriveField(labMaster, epoch)
	txX := chaossync.EpochInit(labMaster, epoch)
	rxX := chaossync.EpochInit(labMaster, epoch+777) // чужое стартовое состояние
	mod := chaossync.Modulator{Delta: delta, S: S}
	var clip chaossync.Fxp
	if clipK > 0 {
		clip = delta.Mul(chaossync.FromInt(int64(clipK)))
	}
	errs, tot := 0, 0
	for w := 0; w < windows+16; w++ {
		bit := chaossync.IdleBit(labMaster, epoch, uint64(w))
		var acc chaossync.Fxp
		for k := 0; k < S; k++ {
			p.Step(&txX)
			mod.Perturb(&txX, p.Drive, bit)
			y := chaossync.Quantize16(txX[p.Drive])
			r := p.ObserverStep(&rxX, chaossync.Dequantize16(y), coup)
			if clipK > 0 {
				if r > clip {
					r = clip
				} else if r < -clip {
					r = -clip
				}
			}
			acc = acc.Add(r)
		}
		if w >= 16 { // пропуск транзиента захвата наблюдателя
			tot++
			if (acc > 0) != bit {
				errs++
			}
		}
	}
	return float64(errs) / float64(tot)
}

func cmdBER(args []string) {
	fs := flag.NewFlagSet("ber", flag.ExitOnError)
	windows := fs.Int("windows", 400, "окон на точку замера (после 16 транзиентных)")
	_ = fs.Parse(args)
	type named struct {
		name string
		v    chaossync.Fxp
	}
	Ss := []int{16, 32, 64, 128}
	deltas := []named{{"2^-8", chaossync.MustDecimal("0.00390625")}, {"2^-7", chaossync.MustDecimal("0.0078125")}, {"2^-6", chaossync.MustDecimal("0.015625")}}
	cs := []named{{"0.85", chaossync.MustDecimal("0.85")}, {"0.95", chaossync.MustDecimal("0.95")}}
	clips := []int{0, 3}
	fmt.Println("# BER доля ошибочных окон; идеальный канал; среднее по 3 полям")
	fmt.Println("S,delta,c,clipK,winBER")
	for _, S := range Ss {
		for _, d := range deltas {
			for _, c := range cs {
				for _, clip := range clips {
					ber := (measureWinBER(S, d.v, c.v, clip, *windows, 100) +
						measureWinBER(S, d.v, c.v, clip, *windows, 200) +
						measureWinBER(S, d.v, c.v, clip, *windows, 300)) / 3
					fmt.Printf("%d,%s,%s,%d,%.5f\n", S, d.name, c.name, clip, ber)
				}
			}
		}
	}
}

// --- Э2: захват на идеальном канале ----------------------------------------

func cmdSync(args []string) {
	fs := flag.NewFlagSet("sync", flag.ExitOnError)
	T := fs.Uint64("T", 32, "период мутации, сек")
	maxDG := fs.Int("maxdg", 3000, "макс. датаграмм")
	_ = fs.Parse(args)
	cfg := chaossync.Config{Master: labMaster, EpochSec: *T, Rate: 200, SymbolS: 32, Batch: 4, Coupling: chaossync.MustDecimal("0.85")}
	per := cfg.DatagramInterval()

	tx := chaossync.NewEndpoint(cfg, "c2s")
	rx := chaossync.NewEndpoint(cfg, "s2c")
	now := time.Unix(1_700_000_000, 0)
	lockAt, phaseAt := -1, -1
	var residAtLock float64
	for i := 0; i < *maxDG; i++ {
		dat := tx.NextDatagram(now)
		rx.HandleDatagram(dat, now)
		s := rx.Snapshot()
		if lockAt < 0 && rx.Locked() {
			lockAt = i
			residAtLock = s.ResidMS
		}
		if phaseAt < 0 && s.Phased {
			phaseAt = i
		}
		now = now.Add(per)
	}
	s := rx.Snapshot()
	fmt.Printf("lock_datagrams=%d phase_datagrams=%d resid_ms=%.8f final_mode=%s spikes=%d resyncs=%d sync_bad=%d/%d\n",
		lockAt, phaseAt, residAtLock, s.Mode, s.Spikes, s.Resyncs, s.SyncBad, s.SyncTot)

	// MockCensor-сторона: чужой ключ никогда не синхронизируется.
	spy := chaossync.NewEndpoint(chaossync.Config{Master: bytes.Repeat([]byte{0x99}, 32)}, "s2c")
	tx2 := chaossync.NewEndpoint(cfg, "c2s")
	now = time.Unix(1_700_000_000, 0)
	for i := 0; i < 2000; i++ {
		dat := tx2.NextDatagram(now)
		spy.HandleDatagram(dat, now)
		now = now.Add(per)
	}
	fmt.Printf("wrong_key_locked=%v (ожидается false)\n", spy.Locked())
}

// --- Э6а: ре-синхронизация после мутации vs T и потери (эмуляция) -----------

func cmdMutate(args []string) {
	fs := flag.NewFlagSet("mutate", flag.ExitOnError)
	epochsPer := fs.Int("epochs", 8, "эпох на точку замера")
	_ = fs.Parse(args)
	fmt.Println("# эмулированный канал (loopback + детерминированные потери), НЕ реальный UDP")
	fmt.Println("T,loss_pct,boundaries,adopted,rehunts,false_spikes,ber_est,max_catchup_datagrams")
	for _, T := range []uint64{4, 8, 16, 32} {
		for _, lossPct := range []float64{0, 1, 5, 10} {
			rng := rand.New(rand.NewSource(12345 + int64(T)*100))
			cfg := chaossync.Config{Master: labMaster, EpochSec: T, Rate: 200, SymbolS: 32, Batch: 4, Coupling: chaossync.MustDecimal("0.85")}
			tx := chaossync.NewEndpoint(cfg, "c2s")
			rx := chaossync.NewEndpoint(cfg, "s2c")
			now := time.Unix(1_700_000_000, 0)
			per := cfg.DatagramInterval()
			epLenDG := int(cfgEpochLen(cfg)) / cfg.Batch // датаграмм на эпоху
			totalDG := epLenDG * (*epochsPer)
			prevSpikes := uint64(0)
			catchup := 0
			maxCatchup := 0
			catching := false
			for i := 0; i < totalDG; i++ {
				dat := tx.NextDatagram(now)
				if rng.Float64()*100 >= lossPct {
					rx.HandleDatagram(dat, now)
				}
				// граница на TX: точно известна по счётчику сэмплов
				if i > 0 && i%epLenDG == 0 {
					catching = true
					catchup = 0
				}
				if catching {
					catchup++
					s := rx.Snapshot()
					if s.Spikes > prevSpikes {
						prevSpikes = s.Spikes
						catching = false
						if catchup > maxCatchup {
							maxCatchup = catchup
						}
					}
				}
				now = now.Add(per)
			}
			m := rx.MetricsSnapshot()
			ber := 0.0
			if m.BerDen > 0 {
				ber = float64(m.BerNum) / float64(m.BerDen)
			}
			fmt.Printf("%d,%.1f,%d,%d,%d,%d,%.4f,%d\n",
				T, lossPct, *epochsPer, m.Spikes, m.Resyncs, m.FalseSpikes, ber, maxCatchup)
		}
	}
}

func cfgEpochLen(cfg chaossync.Config) uint64 {
	return uint64(cfg.Rate) * cfg.EpochSec
}

// --- Э6б: окно реконструкции -------------------------------------------------

func cmdRecon(args []string) {
	fs := flag.NewFlagSet("recon", flag.ExitOnError)
	dim := fs.Int("dim", 6, "размерность вложения")
	lag := fs.Int("lag", 1, "задержка вложения")
	horizon := fs.Int("h", 1, "горизонт прогноза (сэмплов)")
	thresh := fs.Float64("thresh", 0.1, "порог NMSE для 'окна реконструкции'")
	total := fs.Int("n", 64000, "длина потока сэмплов")
	_ = fs.Parse(args)

	fmt.Println("# атакующий: delay-embedding + k=1 NN; NMSE прогноза на h шагов")
	fmt.Println("scenario,T_samples,window,nmse")

	stat := genStream(0, *total)
	for _, w := range []int{500, 1000, 2000, 4000, 8000, 16000, 32000, 64000} {
		if w > *total {
			break
		}
		nmse := chaossync.ReconNMSEH(stat[:w], *dim, *lag, *horizon)
		fmt.Printf("stationary,0,%d,%.4f\n", w, nmse)
	}
	for _, Ts := range []int{200, 400, 800, 1600, 3200, 6400} {
		mut := genStream(Ts, *total)
		for _, w := range []int{1000, 2000, 4000, 8000, 16000, 32000} {
			if w > *total {
				break
			}
			nmse := chaossync.ReconNMSEH(mut[:w], *dim, *lag, *horizon)
			fmt.Printf("mutating,%d,%d,%.4f\n", Ts, w, nmse)
		}
	}
	fmt.Printf("# порог 'реконструкция удалась': NMSE < %.3f\n", *thresh)
}

// genStream — поток квантованных сэмплов: T=0 → стационарное поле;
// T>0 → новая эпоха каждые T сэмплов.
func genStream(T int, n int) []uint16 {
	out := make([]uint16, n)
	if T <= 0 {
		p := chaossync.DeriveField(labMaster, 500)
		x := chaossync.EpochInit(labMaster, 500)
		for i := range out {
			p.Step(&x)
			out[i] = chaossync.Quantize16(x[p.Drive])
		}
		return out
	}
	for seg := 0; seg*T < n; seg++ {
		ep := uint64(9000 + seg)
		p := chaossync.DeriveField(labMaster, ep)
		x := chaossync.EpochInit(labMaster, ep)
		for i := 0; i < T && seg*T+i < n; i++ {
			p.Step(&x)
			out[seg*T+i] = chaossync.Quantize16(x[p.Drive])
		}
	}
	return out
}

// --- Рычаг 1: многомерное кодирование (гиперхаос, K параллельных драйв-осей) ---
//
// Замер прироста ёмкости числами на идеальном канале: per-channel BER (cross-talk),
// время захвата sync vs K, и честная проверка recon-стойкости — не даёт ли больше
// наблюдаемых осей преимущество атакующему (delay-embedding). Мутация (T) — главная
// защита; проверяем, что она держится и при K каналах.

func cmdMultidim(args []string) {
	fs := flag.NewFlagSet("multidim", flag.ExitOnError)
	windows := fs.Int("windows", 3000, "окон измерения BER на канал")
	syncMax := fs.Int("syncmax", 40000, "макс. сэмплов на захват sync")
	_ = fs.Parse(args)
	S := 32
	c := chaossync.MustDecimal("0.85")
	delta := chaossync.FromRaw(int64(1) << 40) // 2^-8 — дефолтная амплитуда модуляции
	syncThresh := chaossync.MustDecimal("0.00005")
	mod := chaossync.Modulator{Delta: delta, S: S}
	fmt.Println("# Рычаг 1: K параллельных осей в одном хаос-потоке (идеальный канал, loopback)")
	fmt.Println("K,sync_samples,ber_min,ber_mean,ber_max,recon_stat,recon_mut")
	for _, K := range []int{1, 2, 3, 4} {
		epoch := uint64(4242)
		field := chaossync.DeriveField(labMaster, epoch)
		drives := chaossync.DeriveDrives(field, K)

		// (а) время захвата sync: связь на K сайтов из чужого состояния, без модуляции.
		syncSamples := -1
		{
			txX := chaossync.EpochInit(labMaster, epoch)
			rxX := chaossync.EpochInit(labMaster, epoch+31337)
			for i := 0; i < *syncMax; i++ {
				field.Step(&txX)
				y := make([]chaossync.Fxp, K)
				for ch := 0; ch < K; ch++ {
					y[ch] = chaossync.Dequantize16(chaossync.Quantize16(txX[drives[ch]]))
				}
				r := field.ObserverStepMulti(&rxX, y, c, drives)
				maxAbs := chaossync.Fxp(0)
				for ch := 0; ch < K; ch++ {
					if r[ch].Abs() > maxAbs {
						maxAbs = r[ch].Abs()
					}
				}
				if maxAbs < syncThresh {
					syncSamples = i
					break
				}
			}
		}

		// (б) per-channel BER: K независимых битовых потоков после прогрева.
		ber := make([]float64, K)
		{
			txX := chaossync.EpochInit(labMaster, epoch)
			rxX := chaossync.EpochInit(labMaster, epoch)
			for i := 0; i < 2000; i++ { // прогрев до sync
				field.Step(&txX)
				y := make([]chaossync.Fxp, K)
				for ch := 0; ch < K; ch++ {
					y[ch] = chaossync.Dequantize16(chaossync.Quantize16(txX[drives[ch]]))
				}
				field.ObserverStepMulti(&rxX, y, c, drives)
			}
			rng := rand.New(rand.NewSource(int64(1000 + K)))
			errs := make([]int, K)
			bits := make([]bool, K)
			for w := 0; w < *windows; w++ {
				for ch := range bits {
					bits[ch] = rng.Intn(2) == 1
				}
				sumR := make([]chaossync.Fxp, K)
				for s2 := 0; s2 < S; s2++ {
					field.Step(&txX)
					for ch := 0; ch < K; ch++ {
						mod.Perturb(&txX, drives[ch], bits[ch])
					}
					y := make([]chaossync.Fxp, K)
					for ch := 0; ch < K; ch++ {
						y[ch] = chaossync.Dequantize16(chaossync.Quantize16(txX[drives[ch]]))
					}
					r := field.ObserverStepMulti(&rxX, y, c, drives)
					for ch := 0; ch < K; ch++ {
						sumR[ch] = sumR[ch].Add(r[ch])
					}
				}
				for ch := 0; ch < K; ch++ {
					if (sumR[ch] > 0) != bits[ch] {
						errs[ch]++
					}
				}
			}
			for ch := 0; ch < K; ch++ {
				ber[ch] = float64(errs[ch]) / float64(*windows)
			}
		}

		// (в) recon-стойкость канала 0: стационарное vs мутирующее поле.
		stat := genStreamK(K, 0, 16000)
		mut := genStreamK(K, 200, 16000)
		nStat := chaossync.ReconNMSEH(stat, 6, 1, 1)
		nMut := chaossync.ReconNMSEH(mut, 6, 1, 1)

		bmin, bmean, bmax := ber[0], 0.0, ber[0]
		for _, b := range ber {
			if b < bmin {
				bmin = b
			}
			if b > bmax {
				bmax = b
			}
			bmean += b
		}
		bmean /= float64(K)
		fmt.Printf("%d,%d,%.5f,%.5f,%.5f,%.4f,%.4f\n", K, syncSamples, bmin, bmean, bmax, nStat, nMut)
	}
	fmt.Println("# recon: NMSE<0.1 = реконструкция удалась; прирост ёмкости = xK")
}

// genStreamK — поток сэмплов наблюдаемого канала 0 в K-канальной системе, где все
// K драйв-сайтов пертурбируются независимым PN (реалистичный многоканальный трафик).
// T=0 → стационарное поле; T>0 → новая эпоха каждые T сэмплов (мутация).
func genStreamK(K, Tt, n int) []uint16 {
	out := make([]uint16, n)
	delta := chaossync.FromRaw(int64(1) << 40)
	mod := chaossync.Modulator{Delta: delta, S: 32}
	rng := rand.New(rand.NewSource(777))
	if Tt <= 0 {
		field := chaossync.DeriveField(labMaster, 500)
		drives := chaossync.DeriveDrives(field, K)
		x := chaossync.EpochInit(labMaster, 500)
		for i := range out {
			field.Step(&x)
			for ch := 0; ch < K; ch++ {
				mod.Perturb(&x, drives[ch], rng.Intn(2) == 1)
			}
			out[i] = chaossync.Quantize16(x[drives[0]])
		}
		return out
	}
	for seg := 0; seg*Tt < n; seg++ {
		ep := uint64(9000 + seg)
		field := chaossync.DeriveField(labMaster, ep)
		drives := chaossync.DeriveDrives(field, K)
		x := chaossync.EpochInit(labMaster, ep)
		for i := 0; i < Tt && seg*Tt+i < n; i++ {
			field.Step(&x)
			for ch := 0; ch < K; ch++ {
				mod.Perturb(&x, drives[ch], rng.Intn(2) == 1)
			}
			out[seg*Tt+i] = chaossync.Quantize16(x[drives[0]])
		}
	}
	return out
}
