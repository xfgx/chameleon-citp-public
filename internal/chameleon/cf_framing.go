package chameleon

// cf_framing.go — Control Fabric message framing.
//
// Control messages are tiny (next-entry address, carrier-profile id, session
// resume hint). They are length-prefixed, Reed-Solomon-style chunked into
// small transport pieces, and AEAD-encrypted before being placed on a channel.

import "encoding/binary"

// MaxControlMessage is the hard cap on a single control message (1 KiB).
// Control Fabric never carries VPN payload; payload stays on the data-plane.
const MaxControlMessage = 1024

// ControlFrame is one transport piece of a control message.
type ControlFrame struct {
	Index   int    `json:"i"`
	Total   int    `json:"t"`
	Payload []byte `json:"p"`
}

// EncodeControlMessage chunks a control message into frames of pieceSize.
func EncodeControlMessage(msg []byte, pieceSize int) []ControlFrame {
	if pieceSize <= 0 {
		pieceSize = 180
	}
	var frames []ControlFrame
	for i := 0; i < len(msg); i += pieceSize {
		end := i + pieceSize
		if end > len(msg) {
			end = len(msg)
		}
		frames = append(frames, ControlFrame{
			Index:   i / pieceSize,
			Total:   0, // filled after
			Payload: append([]byte(nil), msg[i:end]...),
		})
	}
	if len(frames) == 0 {
		frames = []ControlFrame{{Index: 0, Total: 1, Payload: []byte{}}}
	}
	for i := range frames {
		frames[i].Total = len(frames)
	}
	return frames
}

// DecodeControlMessage reassembles frames back into the original message.
func DecodeControlMessage(frames []ControlFrame) []byte {
	if len(frames) == 0 {
		return nil
	}
	// sort-stable by index
	out := make([]byte, 0, len(frames)*len(frames[0].Payload))
	seen := make(map[int]bool, len(frames))
	for {
		// find next unseen smallest index
		next := -1
		for _, f := range frames {
			if seen[f.Index] {
				continue
			}
			if next == -1 || f.Index < next {
				next = f.Index
			}
		}
		if next == -1 {
			break
		}
		for _, f := range frames {
			if f.Index == next {
				out = append(out, f.Payload...)
				seen[f.Index] = true
				break
			}
		}
	}
	return out
}

// LenPrefixedFrame writes a 4-byte big-endian length followed by the payload.
func LenPrefixedFrame(data []byte) []byte {
	out := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(out, uint32(len(data)))
	copy(out[4:], data)
	return out
}
