package chameleon

// control_fabric.go — Control Fabric: the orchestrator for the ultra-narrow
// control channels described in protocol/control-fabric.md.
//
// Channels implemented here:
//   - CDNCacheStateChannel  (bulletin / object-store board)  — carries control frames
//   - DNSBeacon             (narrow TXT dead-drop)            — short beacons
//   - CARChannel            (censor-as-modulator)            — verdict bits
//   - BGPControlChannel     (read-only AS-path observation)   — entry liveness
//
// Purpose: bootstrap, carrier-profile switch, next-entry selection, fallback,
// session recovery. The main VPN payload stays on the existing data-plane
// (mux + carrier); Control Fabric never carries payload.
//
// Stage F (cf_schedule_runtime.go): when enabled via WithSchedule, control
// messages are bound to epochs (anti-replay), CAR frames start at an
// epoch-derived codebook offset, and channel poll order follows the
// epoch schedule. Both sides derive the same schedule from the shared seed
// and the canonical censor model — nothing is negotiated on the wire.
//
// Safe by design: operations needing real infrastructure (active BGP flapping,
// real censor triggering against foreign DPI, foreign-CDN priming) return
// ErrRequiresInfrastructure. The bulletin and DNS paths are functional but
// localhost/lab-scoped (in-memory stores; see LOCAL DATA comments).

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ControlFabric bundles the control channels and a session secret.
type ControlFabric struct {
	seed []byte

	mu    sync.Mutex
	cdn   *CDNCacheStateChannel
	car   *CARChannel
	dns   *DNSBeacon
	bgp   *BGPControlChannel
	sched *scheduleConfig // этап F: nil = legacy-формат без привязки к эпохам
}

// ControlChannel is the minimal interface every channel satisfies (for the
// README's abstraction and future carrier swaps).
type ControlChannel interface {
	Name() string
}

// NewControlFabric constructs a Control Fabric for the node side. Pass nil for
// channels you do not want to run on this host.
func NewControlFabric(seed []byte, cdn *CDNCacheStateChannel, car *CARChannel, dns *DNSBeacon, bgp *BGPControlChannel) *ControlFabric {
	return &ControlFabric{seed: seed, cdn: cdn, car: car, dns: dns, bgp: bgp}
}

// CDN returns the node-side bulletin channel (or nil).
func (cf *ControlFabric) CDN() *CDNCacheStateChannel { return cf.cdn }

// CAR returns the node-side verdict channel (or nil).
func (cf *ControlFabric) CAR() *CARChannel { return cf.car }

// DNS returns the node-side DNS beacon (or nil).
func (cf *ControlFabric) DNS() *DNSBeacon { return cf.dns }

// BGP returns the read-only BGP control-plane channel (or nil).
func (cf *ControlFabric) BGP() *BGPControlChannel { return cf.bgp }

// DoH returns a real DNS-over-HTTPS resolver (default: Cloudflare 1.1.1.1).
func (cf *ControlFabric) DoH(endpoint string) *DoHResolver { return NewDoHResolver(endpoint) }

// PickDecoy returns a real popular decoy origin (cover traffic).
func (cf *ControlFabric) PickDecoy(index int) string { return PickDecoy(index) }

// Profile runs the DPI auto-profiler (measurement only) and returns a
// CensorProfile. The profile's BlockSignatures can be fed to the CAR reader.
func (cf *ControlFabric) Profile(ctx context.Context, cfg ProfilerConfig) CensorProfile {
	return NewDPIProfiler(cfg).Run(ctx)
}

// Fabric is an alias used internally; ControlFabric is the public name.
type Fabric = ControlFabric

// SessionSecret returns the HKDF-derived 32-byte session secret.
func (cf *ControlFabric) SessionSecret() []byte {
	return DeriveSessionSecret(cf.seed)
}

// --- node side: publish a control message across channels ---

// PublishControl encrypts a control message and publishes it across the
// available node-side channels (CDN primary; DNS short beacon; CAR bits).
// При включённом этапе F сообщение привязывается к текущей эпохе (F3),
// CAR-кадр раскладывается со смещением окна из расписания (F2), а DNS-чанк
// публикуется под эпохальной меткой (C3).
// LOCAL DATA: published frames live in process memory on the node.
func (cf *ControlFabric) PublishControl(ctx context.Context, sessionID string, msg []byte) error {
	if len(msg) > MaxControlMessage {
		return errors.New("control-fabric: control message too large")
	}
	key := cf.SessionSecret()
	now := time.Now()
	body := cf.bindMessage(msg, now) // F3: привязка к эпохе (вкл. этап F)

	// 1) CDN board: AEAD-encrypted frames (primary control path).
	if cf.cdn != nil {
		frames := EncodeControlMessage(body, 180)
		for _, f := range frames {
			payload := append([]byte(nil), f.Payload...)
			enc, err := AEADEncrypt(key, payload)
			if err != nil {
				return err
			}
			cf.cdn.Publish(sessionID, enc)
		}
	}

	// 2) DNS beacon: маркер готовности на seq 0 + (если помещается в 180-байтный
	//    чанк) зашифрованная копия сообщения — узкая, но полноценная
	//    плоскость доставки короткой команды (этап D4). При включённом этапе F
	//    чанк публикуется под эпохальной меткой (C3) — кэш не отдаёт старьё.
	if cf.dns != nil {
		beacon := []byte("SID=" + sessionID + ";READY")
		if len(beacon) > 180 {
			beacon = beacon[:180]
		}
		cf.dns.Publish(0, beacon)
		if enc, err := AEADEncrypt(key, body); err == nil && len(enc) <= 180 {
			if _, sched := cf.scheduleNow(now); sched != nil {
				cf.dns.PublishLabeled(DNSEpochLabel("c", 1, sched.Epoch), enc)
			} else {
				cf.dns.Publish(1, enc)
			}
		}
	}

	// 3) CAR (этапы A+B+F2): сообщение целиком — AEAD-шифротекст кадрируется
	//    (SYNC+LEN+CRC16, repetition-FEC) и раскладывается по окнам кодовой
	//    книги из SessionSecret со смещением стартового окна из расписания
	//    эпохи. Клиент с тем же seed и моделью выводит ту же книгу и то же
	//    смещение — пути окон и смещение по сети не передаются.
	if cf.car != nil {
		if enc, err := AEADEncrypt(key, body); err == nil && len(enc) <= CARMaxPayload {
			book := cf.carCodebook(key, now)
			_ = cf.car.PublishFrame(book, enc, CARFrameRep)
		}
	}
	return nil
}

// --- client side: recover a control message ---

// RecoverControl pulls and decrypts the control message from the CDN board.
// При включённом этапе F проверяет привязку к эпохе (анти-replay).
func (cf *ControlFabric) RecoverControl(ctx context.Context, sessionID string, client *CDNCacheStateClient) ([]byte, error) {
	frames, err := client.Poll(sessionID)
	if err != nil {
		return nil, err
	}
	if len(frames) == 0 {
		return nil, errors.New("control-fabric: no frames yet")
	}
	key := cf.SessionSecret()
	pieces := make([][]byte, 0, len(frames))
	for _, enc := range frames {
		dec, err := AEADDecrypt(key, enc)
		if err != nil {
			return nil, err
		}
		pieces = append(pieces, dec)
	}
	// Reassemble: pieces are ordered by publish order; wrap as frames.
	fr := make([]ControlFrame, len(pieces))
	for i, p := range pieces {
		fr[i] = ControlFrame{Index: i, Total: len(pieces), Payload: p}
	}
	return cf.unbindMessage(DecodeControlMessage(fr), time.Now())
}

// ReadDNSBeacon reads the short DNS beacon (client side).
func (cf *ControlFabric) ReadDNSBeacon(reader *DNSBeaconReader, seq int) ([]byte, error) {
	return reader.ReadChunk(seq)
}

// ReadCARBits reads N verdict bits (client side).
func (cf *ControlFabric) ReadCARBits(reader *CARReader, start, count int) []uint8 {
	return reader.ReadBits(start, count)
}

// ReadControlCAR — клиентское чтение управляющего сообщения по CAR-каналу
// (этапы A2+B2+F2): кодовая книга выводится из SessionSecret (та же, что у
// ноды) со смещением окна из расписания эпохи; кадр читается двухфазно; при
// неисправимом шуме (CRC) перечитываем — состояние на ноде статично, каждая
// попытка даёт независимую шумовую выборку. Этап F3: привязка к эпохе
// проверяется после расшифровки.
func (cf *ControlFabric) ReadControlCAR(reader *CARReader, attempts int) ([]byte, error) {
	if reader == nil {
		return nil, errors.New("control-fabric: nil CAR reader")
	}
	if attempts < 1 {
		attempts = 1
	}
	now := time.Now()
	key := cf.SessionSecret()
	book := cf.carCodebook(key, now)
	var lastErr error
	for i := 0; i < attempts; i++ {
		blob, err := reader.ReadMessage(book, CARFrameRep)
		if err != nil {
			lastErr = err
			continue
		}
		dec, err := AEADDecrypt(key, blob)
		if err != nil {
			lastErr = err
			continue
		}
		out, err := cf.unbindMessage(dec, now)
		if err != nil {
			lastErr = err
			continue
		}
		return out, nil
	}
	if lastErr == nil {
		lastErr = errors.New("control-fabric: car: no attempts made")
	}
	return nil, lastErr
}

// RecoverControlAny — политика выбора канала (этапы D4+F2): порядок опроса
// берётся из расписания текущей эпохи (перестановка board/dns/car/ct) либо,
// в legacy-режиме, фиксированный board -> dns -> car -> ct. Возвращает
// сообщение и имя канала, по которому оно дошло. Критерий D4: при выключении
// любых двух каналов команда доходит по оставшимся.
func (cf *ControlFabric) RecoverControlAny(ctx context.Context, sessionID string, board *CDNCacheStateClient, dns *DNSBeaconReader, car *CARReader, ct *CTLogReader) ([]byte, string, error) {
	now := time.Now()
	for _, ch := range cf.channelOrder(now) {
		switch ch {
		case "board":
			if board != nil {
				if m, err := cf.RecoverControl(ctx, sessionID, board); err == nil {
					return m, "board", nil
				}
			}
		case "dns":
			if dns != nil {
				if m, err := cf.recoverDNS(dns, now); err == nil {
					return m, "dns", nil
				}
			}
		case "car":
			if car != nil {
				if m, err := cf.ReadControlCAR(car, 2); err == nil {
					return m, "car", nil
				}
			}
		case "ct":
			if ct != nil {
				if blob, err := ct.ReadMessage(ctx); err == nil {
					if dec, err := AEADDecrypt(cf.SessionSecret(), blob); err == nil {
						if m, err := cf.unbindMessage(dec, now); err == nil {
							return m, "ct", nil
						}
					}
				}
			}
		}
	}
	return nil, "", errors.New("control-fabric: все control-каналы недоступны")
}

// ObserveBGPRoutes reads AS-path state for a prefix (read-only).
func (cf *ControlFabric) ObserveBGPRoutes(ctx context.Context, prefix string) ([]BGPRoute, error) {
	if cf.bgp == nil {
		return nil, errors.New("control-fabric: no BGP channel configured")
	}
	return cf.bgp.ReadASPath(ctx, prefix)
}

// Names returns the channel names (for the ControlChannel abstraction).
func (cf *ControlFabric) Names() []string {
	var out []string
	if cf.cdn != nil {
		out = append(out, "cdn-cache-state")
	}
	if cf.dns != nil {
		out = append(out, "dns-beacon")
	}
	if cf.car != nil {
		out = append(out, "car-verdict")
	}
	if cf.bgp != nil {
		out = append(out, "bgp-control")
	}
	return out
}

// PublishControlSingle публикует управляющее сообщение ОДНИМ AEAD-кадром на
// произвольный идентификатор канала борда (слои 6/8: рассылка θ и карты
// дорогих зон). В отличие от PublishControl, сообщение не дробится на
// 180-байтные чанки: каждый кадр канала — самостоятельное сообщение, поэтому
// периодическая рассылка эпох в один канал не ломает сборку — клиент
// дешифрует кадры независимо и берёт последний валидный (PollChannelMessages).
func (cf *ControlFabric) PublishControlSingle(channelID string, msg []byte) error {
	if len(msg) > MaxControlMessage {
		return errors.New("control-fabric: control message too large")
	}
	cf.mu.Lock()
	cdn := cf.cdn
	cf.mu.Unlock()
	if cdn == nil {
		return errors.New("control-fabric: no bulletin channel")
	}
	enc, err := AEADEncrypt(cf.SessionSecret(), cf.bindMessage(msg, time.Now()))
	if err != nil {
		return err
	}
	cdn.Publish(channelID, enc)
	return nil
}
