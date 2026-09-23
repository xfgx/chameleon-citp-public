package chameleon

// cf_dns.go — DNS control-plane beacon (narrow dead-drop).
//
// Node side: a minimal authoritative DNS server (UDP, TXT records) for a
// private zone. A short control beacon (session id + frame count) is served
// under a rotating label like <base><seq>.<zone>.
//
// Client side: queries that authoritative server and parses TXT records back
// into the beacon.
//
// Этап C3 (анти-кэш): нода может публиковать под эпохальной меткой
// (DNSEpochLabel), меняющейся каждую эпоху, — кэши публичных резолверов не
// отдают старьё, т.к. имя новое; TTL выставляется минимальным (конфигурация,
// у cham-server это 5 секунд).
//
// Lab scope: the in-memory zone table is LOCAL DATA. The channel carries only
// short beacons (<=180 bytes per label) and is rate-limited. Real-deployment
// constraints (TXT payload limits, UDP 512-byte cap, TTL/caching, NXDOMAIN
// negative caching) are documented in protocol/control-fabric.md.

import (
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// DNSBeacon is the node-side authoritative TXT server.
type DNSBeacon struct {
	addr      string
	zone      string // e.g. "dd.phantom.lab"
	labelBase string // e.g. "c"
	ttl       uint32

	mu      sync.Mutex
	records map[string][]byte // LOCAL DATA: in-memory beacon chunks keyed by first label
	conn    *net.UDPConn
}

// NewDNSBeacon creates a node-side DNS beacon.
func NewDNSBeacon(addr, zone, labelBase string, ttl uint32) *DNSBeacon {
	return &DNSBeacon{addr: addr, zone: zone, labelBase: labelBase, ttl: ttl, records: make(map[string][]byte)}
}

// Publish sets the chunk for a given seq (label <base><seq>). LOCAL DATA.
func (d *DNSBeacon) Publish(seq int, chunk []byte) {
	d.PublishLabeled(fmt.Sprintf("%s%d", d.labelBase, seq), chunk)
}

// PublishLabeled sets the chunk under an arbitrary first label — в т.ч.
// эпохальную метку DNSEpochLabel (этап C3, анти-кэш). LOCAL DATA.
func (d *DNSBeacon) PublishLabeled(label string, chunk []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.records[strings.ToLower(label)] = append([]byte(nil), chunk...)
}

// DNSEpochLabel — эпохальная метка маячка: <base><seq>e<младшие 24 бита эпохи
// в hex>. Имя меняется каждую эпоху -> кэш публичного резолвера физически не
// может отдать прошлую эпоху (этап C3). Обе стороны вычисляют метку
// одинаково из общего расписания (этап F).
func DNSEpochLabel(base string, seq int, epoch uint64) string {
	return fmt.Sprintf("%s%de%06x", base, seq, epoch&0xFFFFFF)
}

// Serve starts the UDP DNS server. Blocks until Close.
func (d *DNSBeacon) Serve() error {
	addr, err := net.ResolveUDPAddr("udp", d.addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	d.mu.Lock()
	d.conn = conn
	d.mu.Unlock()
	buf := make([]byte, 4096)
	for {
		n, peer, err := conn.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		d.handlePacket(buf[:n], peer)
	}
}

// Close stops the server.
func (d *DNSBeacon) Close() error {
	d.mu.Lock()
	conn := d.conn
	d.mu.Unlock()
	if conn == nil {
		return nil
	}
	return conn.Close()
}

// LocalAddr returns the listening UDP address once Serve has bound the socket.
func (d *DNSBeacon) LocalAddr() string {
	d.mu.Lock()
	conn := d.conn
	d.mu.Unlock()
	if conn == nil {
		return ""
	}
	return conn.LocalAddr().String()
}

func (d *DNSBeacon) handlePacket(msg []byte, peer *net.UDPAddr) {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		return
	}
	q, err := p.Question()
	if err != nil {
		return
	}
	out := d.buildResponse(h.ID, q)
	if len(out) > 0 {
		_, _ = d.conn.WriteToUDP(out, peer)
	}
}

// buildResponse constructs a well-formed DNS response with one TXT answer.
func (d *DNSBeacon) buildResponse(id uint16, q dnsmessage.Question) []byte {
	label := d.labelFromName(q.Name.String())
	d.mu.Lock()
	chunk := d.records[label]
	d.mu.Unlock()
	if chunk == nil {
		chunk = []byte{}
	}
	txt := base64.StdEncoding.EncodeToString(chunk)

	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID: id, Response: true, Authoritative: true,
	})
	b.EnableCompression()
	_ = b.StartQuestions()
	_ = b.Question(q)
	_ = b.StartAnswers()
	_ = b.TXTResource(dnsmessage.ResourceHeader{
		Name:  q.Name,
		Type:  dnsmessage.TypeTXT,
		Class: dnsmessage.ClassINET,
		TTL:   d.ttl,
	}, dnsmessage.TXTResource{TXT: []string{txt}})
	out, err := b.Finish()
	if err != nil {
		return d.buildRefused(id, q)
	}
	return out
}

func (d *DNSBeacon) buildRefused(id uint16, q dnsmessage.Question) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID: id, Response: true, Authoritative: true, RCode: dnsmessage.RCodeRefused,
	})
	b.EnableCompression()
	_ = b.StartQuestions()
	_ = b.Question(q)
	out, err := b.Finish()
	if err != nil {
		return nil
	}
	return out
}

// labelFromName извлекает первый (самый левый) label имени, если имя в нашей
// зоне: "c12.dd.phantom.lab." -> "c12". Чужие имена -> "".
func (d *DNSBeacon) labelFromName(name string) string {
	zoneFull := strings.TrimSuffix(d.zone, ".") + "."
	name = strings.ToLower(name)
	if !strings.HasSuffix(name, zoneFull) {
		return ""
	}
	prefix := strings.TrimSuffix(name, zoneFull)
	return strings.Split(prefix, ".")[0]
}

// DNSBeaconReader is the client-side resolver for the beacon.
type DNSBeaconReader struct {
	serverHost string
	serverPort int
	zone       string
	labelBase  string
}

// NewDNSBeaconReader points at the authoritative DNS server.
func NewDNSBeaconReader(serverHost string, serverPort int, zone, labelBase string) *DNSBeaconReader {
	return &DNSBeaconReader{serverHost: serverHost, serverPort: serverPort, zone: zone, labelBase: labelBase}
}

// ReadChunk queries the label for seq and returns the decoded beacon bytes.
func (r *DNSBeaconReader) ReadChunk(seq int) ([]byte, error) {
	return r.ReadChunkLabel(fmt.Sprintf("%s%d", r.labelBase, seq))
}

// ReadChunkLabel читает чанк под произвольной меткой — в т.ч. эпохальной
// (DNSEpochLabel, этап C3).

// ReadChunkEpoch читает чанк по эпохальной метке (этап C3) с собственной базой
// меток ридера: при включённом этапе F сообщение живёт под меткой текущей
// эпохи, и кэши резолверов не отдают прошлую эпоху.
func (r *DNSBeaconReader) ReadChunkEpoch(seq int, epoch uint64) ([]byte, error) {
	return r.ReadChunkLabel(DNSEpochLabel(r.labelBase, seq, epoch))
}

func (r *DNSBeaconReader) ReadChunkLabel(label string) ([]byte, error) {
	name := fmt.Sprintf("%s.%s", label, strings.TrimSuffix(r.zone, "."))
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	query, err := buildDNSQuery(name)
	if err != nil {
		return nil, err
	}
	addr := &net.UDPAddr{IP: net.ParseIP(r.serverHost), Port: r.serverPort}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return parseTXTResponse(buf[:n])
}

func buildDNSQuery(name string) ([]byte, error) {
	dn, err := dnsmessage.NewName(name)
	if err != nil {
		return nil, err
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x1234, Response: false})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{Name: dn, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	return b.Finish()
}

func parseTXTResponse(msg []byte) ([]byte, error) {
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil {
		return nil, err
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, err
	}
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, err
		}
		if h.Type != dnsmessage.TypeTXT {
			_ = p.SkipAnswer()
			continue
		}
		txt, err := p.TXTResource()
		if err != nil {
			return nil, err
		}
		joined := strings.Join(txt.TXT, "")
		if joined == "" {
			return []byte{}, nil
		}
		return base64.StdEncoding.DecodeString(joined)
	}
	return nil, nil
}
