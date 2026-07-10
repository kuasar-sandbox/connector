package tapfd

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

// PortMetadata is the per-port information connector-ctl vswitch sends alongside the
// tap fd via SCM_RIGHTS. The wire format is a single line of space-separated
// key=value pairs terminated by a NUL byte:
//
//	port=1 mac=02:00:00:00:80:01 ip=169.254.1.1 fd=1\0
//
// When the provider also delivers the tap's network namespace fd, a netns_fd
// key is appended and one extra fd rides at the END of the SCM_RIGHTS array:
//
//	port=1 mac=02:00:00:00:80:01 ip=169.254.1.1 fd=1 netns_fd=1\0
//
// Field semantics:
//
//	port      1-based port number (slot_id + 1)
//	mac       per-port MAC the sandbox/VMM must configure on its virtio-net device
//	ip        sandbox inner IP that was assigned by 'attach' (open-port requires attached)
//	fd        number of tap-queue file descriptors included in the SCM_RIGHTS
//	          ancillary (always 1 today; reserved for future multi-queue support)
//	netns_fd  number of trailing netns fds appended after the tap fds (0 or 1;
//	          omitted/0 means none). When present, the netns fd(s) are the LAST
//	          fd(s) in the ancillary, so the total fd count is fd + netns_fd.
//
// Receivers should:
//  1. recvmsg with a buffer of at least 512 bytes and an SCM_RIGHTS ancillary
//     buffer sized for the expected fd count.
//  2. Scan for the first NUL byte; everything before it is the metadata line.
//  3. Split on whitespace, then on '=', into key/value pairs.
//  4. Extract the file descriptor(s) from the SCM_RIGHTS control message; the
//     first fd are the tap fds and the trailing netns_fd ones are netns fds.
type PortMetadata struct {
	Port    uint32
	MAC     string // canonical "xx:xx:xx:xx:xx:xx"
	InnerIP string // dotted-quad
	FDCount uint8  // number of tap-queue fds delivered alongside (1 today)
	// NetnsFDCount is the number of netns fds appended after the tap fds
	// (0 or 1). 0 means the provider sent no netns fd; the key is omitted from
	// the wire in that case, so a consumer that didn't request it sees the
	// plain payload.
	NetnsFDCount uint8
}

// MaxPayloadSize bounds the on-wire metadata so receivers can size their
// recvmsg buffer safely. Payloads are well under 128 bytes; we round up to
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
	fmt.Fprintf(&b, "port=%d mac=%s ip=%s fd=%d",
		m.Port, m.MAC, m.InnerIP, m.FDCount)
	// netns_fd is emitted only when nonzero; a consumer that didn't request the
	// netns fd receives the plain payload with no extra key or fd.
	if m.NetnsFDCount > 0 {
		fmt.Fprintf(&b, " netns_fd=%d", m.NetnsFDCount)
	}
	b.WriteByte(0)
	if b.Len() > MaxPayloadSize {
		return nil, fmt.Errorf("metadata payload size %d exceeds MaxPayloadSize=%d", b.Len(), MaxPayloadSize)
	}
	return b.Bytes(), nil
}

// ParsePayload parses a wire-format metadata payload (key=value space-separated,
// NUL-terminated). Unknown keys are ignored so receivers don't break when new
// fields are added.
func ParsePayload(buf []byte) (*PortMetadata, error) {
	end := bytes.IndexByte(buf, 0)
	if end < 0 {
		// No NUL — accept the whole buffer (lenient for receivers that strip).
		end = len(buf)
	}
	line := string(buf[:end])

	var m PortMetadata
	for tok := range strings.FieldsSeq(line) {
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
		case "ip":
			m.InnerIP = val
		case "fd":
			v, err := strconv.ParseUint(val, 10, 8)
			if err != nil {
				return nil, fmt.Errorf("fd=%q: %w", val, err)
			}
			m.FDCount = uint8(v)
		case "netns_fd":
			v, err := strconv.ParseUint(val, 10, 8)
			if err != nil {
				return nil, fmt.Errorf("netns_fd=%q: %w", val, err)
			}
			m.NetnsFDCount = uint8(v)
		default:
			// Unknown keys silently ignored — forward compat.
		}
	}
	return &m, nil
}
