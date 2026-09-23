package chaossync

// LABORATORY ONLY. Added to an isolated source copy, never to production.
// Ordinary Sender.Seal and the KS golden vector are unchanged.
import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

const LabForward uint64 = 8192
const labCheckpointBytes = 8 + Sites*8

var labCheckpointAAD = []byte("ks-recovery-lab-checkpoint-v1")

type labEntry struct {
	Key [ksKeyLen]byte
	Pos uint64
}
type LabStats struct {
	Slots    int    `json:"slots"`
	MaxSlots int    `json:"max_slots"`
	Steps    uint64 `json:"steps"`
	High     uint64 `json:"high"`
	Gen      uint64 `json:"gen"`
	Restores uint64 `json:"restores"`
}
type LabReceiver struct {
	kg                                 *KeyGen
	aad                                []byte
	checkpoint                         cipher.AEAD
	keys                               map[string]labEntry
	byPos                              map[uint64]string
	retired                            map[string]labEntry
	forward, history, high, gen, floor uint64
	retain                             bool
	lastCheckpoint                     bool
	stats                              LabStats
}

func labCheckpointCipher(master []byte, epoch uint64, dir string) cipher.AEAD {
	seed := epochSeed(master, cdtLabel("ks-recovery-lab-key-v1", dir), epoch)
	k := sha256.Sum256(append([]byte("ks-recovery-lab-domain-v1"), seed...))
	a, err := ksAEAD(SuiteChaCha20Poly1305, k[:])
	if err != nil {
		panic(err)
	}
	return a
}
func newLabReceiver(master []byte, epoch uint64, dir string, forward, history uint64, checkpoint, retain bool) *LabReceiver {
	r := &LabReceiver{kg: NewKeyGen(master, epoch, dir), aad: ksCstAAD(master, epoch, dir), keys: make(map[string]labEntry), byPos: make(map[uint64]string), retired: make(map[string]labEntry), forward: forward, history: history, floor: 1, retain: retain}
	if checkpoint {
		r.checkpoint = labCheckpointCipher(master, epoch, dir)
	}
	r.fill()
	return r
}
func (r *LabReceiver) updateStats() {
	r.stats.Slots = len(r.keys) + len(r.retired)
	if r.stats.Slots > r.stats.MaxSlots {
		r.stats.MaxSlots = r.stats.Slots
	}
	r.stats.High = r.high
	r.stats.Gen = r.gen
}
func (r *LabReceiver) fill() {
	for r.gen < r.high+r.forward {
		key, nonce := r.kg.next()
		r.gen++
		r.stats.Steps++
		n := string(nonce[:])
		r.keys[n] = labEntry{key, r.gen}
		r.byPos[r.gen] = n
	}
	r.updateStats()
}
func (r *LabReceiver) advance(pos uint64) {
	if pos > r.high {
		r.high = pos
	}
	target := uint64(1)
	if r.high >= r.history {
		target = r.high - r.history + 1
	}
	for r.floor < target {
		if n, ok := r.byPos[r.floor]; ok {
			delete(r.keys, n)
			delete(r.byPos, r.floor)
		}
		r.floor++
	}
	r.fill()
}
func (r *LabReceiver) Ingest(wire []byte) ([]byte, bool) {
	r.lastCheckpoint = false
	if len(wire) < KsNonceLen+16 {
		return nil, false
	}
	nonce, ct := wire[:KsNonceLen], wire[KsNonceLen:]
	n := string(nonce)
	entry, ok := r.keys[n]
	old := false
	if !ok {
		entry, ok = r.retired[n]
		old = ok
	}
	if ok {
		a, err := ksAEAD(SuiteChaCha20Poly1305, entry.Key[:])
		if err != nil {
			return nil, false
		}
		plain, err := a.Open(nil, nonce, ct, r.aad)
		if err != nil {
			return nil, false
		}
		if old {
			delete(r.retired, n)
			r.updateStats()
		} else {
			delete(r.keys, n)
			delete(r.byPos, entry.Pos)
			r.advance(entry.Pos)
		}
		return plain, true
	}
	if r.checkpoint == nil || len(wire) != KsNonceLen+labCheckpointBytes+16 {
		return nil, false
	}
	plain, err := r.checkpoint.Open(nil, nonce, ct, labCheckpointAAD)
	if err != nil || len(plain) != labCheckpointBytes {
		return nil, false
	}
	pos := binary.BigEndian.Uint64(plain[:8])
	// Only jump beyond the already-prepared interval; reject rollback and overflow.
	if pos <= r.gen || pos > (uint64(1)<<60) {
		return nil, false
	}
	var state [Sites]Fxp
	for i := range state {
		raw := int64(binary.BigEndian.Uint64(plain[8+i*8 : 16+i*8]))
		if raw < 0 || raw > oneRaw {
			return nil, false
		}
		state[i] = FromRaw(raw)
	}
	saved := make(map[string]labEntry)
	if r.retain {
		// One bounded retired segment. Consumed keys are absent and cannot be resurrected.
		lower := uint64(1)
		if r.high >= 64 {
			lower = r.high - 63
		}
		for p := lower; p <= r.high; p++ {
			if n, ok := r.byPos[p]; ok {
				saved[n] = r.keys[n]
			}
		}
	}
	r.retired = saved
	r.keys = make(map[string]labEntry)
	r.byPos = make(map[uint64]string)
	r.kg.state = state
	r.kg.ctr = pos
	r.gen = pos
	r.high = pos
	r.floor = pos + 1
	r.stats.Restores++
	r.lastCheckpoint = true
	r.fill()
	return nil, false // A checkpoint is not an application payload.
}
func (r *LabReceiver) stateDigest() string {
	// Test-only digest; never serializes secret state to a report.
	names := make([]string, 0, len(r.keys))
	for n := range r.keys {
		names = append(names, n)
	}
	sort.Strings(names)
	oldNames := make([]string, 0, len(r.retired))
	for n := range r.retired {
		oldNames = append(oldNames, n)
	}
	sort.Strings(oldNames)
	h := sha256.New()
	fmt.Fprintf(h, "%d/%d/%d/%d/%v", r.high, r.gen, r.floor, r.kg.ctr, r.kg.state)
	for _, n := range names {
		e := r.keys[n]
		h.Write([]byte(n))
		h.Write(e.Key[:])
		fmt.Fprintf(h, "/%d", e.Pos)
	}
	h.Write([]byte("retired"))
	for _, n := range oldNames {
		e := r.retired[n]
		h.Write([]byte(n))
		h.Write(e.Key[:])
		fmt.Fprintf(h, "/%d", e.Pos)
	}
	return hex.EncodeToString(h.Sum(nil))
}
func LabCheckpoint(s *Sender) []byte {
	p := make([]byte, labCheckpointBytes)
	binary.BigEndian.PutUint64(p[:8], s.kg.ctr)
	for i := range s.kg.state {
		binary.BigEndian.PutUint64(p[8+i*8:16+i*8], uint64(s.kg.state[i].Raw()))
	}
	nonce := make([]byte, KsNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	a := labCheckpointCipher(s.master, s.epoch, s.dir)
	return append(nonce, a.Seal(nil, nonce, p, labCheckpointAAD)...)
}

type LabVariant struct {
	Name     string
	legacy   *Receiver
	modern   *LabReceiver
	maxSlots int
}

func LabVariants(master []byte, epoch uint64, dir string) []*LabVariant {
	a, b := NewReceiver(master, epoch, dir), NewReceiver(master, epoch, dir)
	b.window = 16384
	return []*LabVariant{
		{Name: "legacy-8192", legacy: a}, {Name: "legacy-16384", legacy: b},
		{Name: "frontier", modern: newLabReceiver(master, epoch, dir, 8192, 128, false, false)},
		{Name: "checkpoint-reset", modern: newLabReceiver(master, epoch, dir, 8192, 128, true, false)},
		{Name: "checkpoint-retain", modern: newLabReceiver(master, epoch, dir, 8192, 64, true, true)},
	}
}
func (v *LabVariant) Ingest(wire []byte) ([]byte, bool, bool) {
	if v.legacy != nil {
		p, ok := v.legacy.Ingest(wire)
		return p, ok, false
	}
	p, ok := v.modern.Ingest(wire)
	return p, ok, v.modern.lastCheckpoint
}
func (v *LabVariant) Stats() LabStats {
	if v.modern != nil {
		v.modern.updateStats()
		return v.modern.stats
	}
	n := len(v.legacy.cur.ahead)
	if n > v.maxSlots {
		v.maxSlots = n
	}
	return LabStats{Slots: n, MaxSlots: v.maxSlots, Steps: v.legacy.cur.gen, Gen: v.legacy.cur.gen}
}
func LabSourceCharacterization(master []byte, epoch uint64) map[string]bool {
	a, b := NewSender(master, epoch, "c2n"), NewSender(master, epoch, "c2n")
	x, y := a.Seal([]byte("first fresh message")), b.Seal([]byte("different new message"))
	r := NewReceiver(master, epoch, "c2n")
	_, first := r.Ingest(x)
	_, again := r.Ingest(x)
	restarted := NewReceiver(master, epoch, "c2n")
	_, afterRestart := restarted.Ingest(x)
	return map[string]bool{"same_epoch_restart_repeats_nonce": string(x[:KsNonceLen]) == string(y[:KsNonceLen]), "initial_packet_accepted": first, "same_instance_replay_rejected": !again, "new_instance_accepts_old_packet": afterRestart}
}
func LabStatsJSON(v []*LabVariant) json.RawMessage {
	m := map[string]LabStats{}
	for _, x := range v {
		m[x.Name] = x.Stats()
	}
	b, _ := json.Marshal(m)
	return b
}
