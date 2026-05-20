package tapfd

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

// PortMetadata is the per-port information vswitch-ctl sends alongside the
// tap fd via SCM_RIGHTS. The wire format is a single line of space-separated
// key=value pairs terminated by a NUL byte:
//
//	port=1 mac=02:00:00:00:80:01 mtu=1500 ip=169.254.1.1 fd=1\0
//
// Field semantics:
//
//	port  1-based port number (slot_id + 1)
//	mac   per-port MAC the sandbox/VMM must configure on its virtio-net device
//	mtu   MTU of the tap netdev (kernel default 1500 unless overridden)
//	ip    sandbox inner IP that was assigned by 'attach' (open-port requires attached)
//	fd    number of file descriptors included in the SCM_RIGHTS ancillary
//	      (v1 is always 1; reserved for future multi-queue support)
//
// Receivers should:
//  1. recvmsg with a buffer of at least 512 bytes and an SCM_RIGHTS ancillary
//     buffer sized for the expected fd count.
//  2. Scan for the first NUL byte; everything before it is the metadata line.
//  3. Split on whitespace, then on '=', into key/value pairs.
//  4. Extract the file descriptor(s) from the SCM_RIGHTS control message.
type PortMetadata struct {
	Port    uint32
	MAC     string // canonical "xx:xx:xx:xx:xx:xx"
	MTU     uint32
	InnerIP string // dotted-quad
	FDCount uint8  // number of fds delivered alongside (v1: 1)
}

// MaxPayloadSize bounds the on-wire metadata so receivers can size their
// recvmsg buffer safely. v1 payloads are well under 128 bytes; we round up to
// 512 for slack.
const MaxPayloadSize = 512

// Marshal serializes the metadata into the wire format (key=value pairs,
// space-separated, NUL-terminated). Returns the byte slice ready to be passed
// to SendFd as the data payload.
func (m *PortMetadata) Marshal() ([]byte, error) {
	if m.MAC == "" {
		return nil, fmt.Errorf("PortMetadata.MAC is required")
	}
	if m.InnerIP == "" {
		return nil, fmt.Errorf("PortMetadata.InnerIP is required")
	}
	if m.FDCount == 0 {
		return nil, fmt.Errorf("PortMetadata.FDCount must be at least 1")
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "port=%d mac=%s mtu=%d ip=%s fd=%d",
		m.Port, m.MAC, m.MTU, m.InnerIP, m.FDCount)
	b.WriteByte(0)
	if b.Len() > MaxPayloadSize {
		return nil, fmt.Errorf("metadata payload size %d exceeds MaxPayloadSize=%d", b.Len(), MaxPayloadSize)
	}
	return b.Bytes(), nil
}

// ParsePayload parses a wire-format metadata payload (key=value space-separated,
// NUL-terminated). Unknown keys are ignored so receivers built against this
// version don't break when v1.x adds fields.
func ParsePayload(buf []byte) (*PortMetadata, error) {
	end := bytes.IndexByte(buf, 0)
	if end < 0 {
		// No NUL — accept the whole buffer (lenient for receivers that strip).
		end = len(buf)
	}
	line := string(buf[:end])

	var m PortMetadata
	for _, tok := range strings.Fields(line) {
		eq := strings.IndexByte(tok, '=')
		if eq < 0 {
			return nil, fmt.Errorf("malformed token %q (expected key=value)", tok)
		}
		key, val := tok[:eq], tok[eq+1:]
		switch key {
		case "port":
			v, err := strconv.ParseUint(val, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("port=%q: %w", val, err)
			}
			m.Port = uint32(v)
		case "mac":
			m.MAC = val
		case "mtu":
			v, err := strconv.ParseUint(val, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("mtu=%q: %w", val, err)
			}
			m.MTU = uint32(v)
		case "ip":
			m.InnerIP = val
		case "fd":
			v, err := strconv.ParseUint(val, 10, 8)
			if err != nil {
				return nil, fmt.Errorf("fd=%q: %w", val, err)
			}
			m.FDCount = uint8(v)
		default:
			// Unknown keys silently ignored — forward compat.
		}
	}
	return &m, nil
}
