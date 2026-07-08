package tapfd

import (
	"bytes"
	"fmt"
	"strings"
)

const (
	RequestVersion     = "TAPFD/1"
	RequestOpOpen      = "OPEN"
	ResponseStatusOK   = "OK"
	ResponseStatusERR  = "ERR"
	RequestMaxLineSize = 512

	ErrorCodeBadRequest       = "BAD_REQUEST"
	ErrorCodeSwitchMismatch   = "SWITCH_MISMATCH"
	ErrorCodePortInvalid      = "PORT_INVALID"
	ErrorCodePortUnavailable  = "PORT_UNAVAILABLE"
	ErrorCodeProviderInternal = "PROVIDER_INTERNAL"
)

// Request is the small request line used by the persistent tapfd provider
// socket. It is deliberately separate from the fd-response payload: successful
// responses still use PortMetadata + SCM_RIGHTS.
type Request struct {
	Version   string
	Op        string
	WantNetns bool
	Fields    map[string]string
}

// BuildOKResponse wraps a successful metadata payload with the TAPFD/1 OK
// response prefix used by persistent socket providers. The returned payload is
// still sent together with SCM_RIGHTS, and the metadata remains NUL-terminated.
func BuildOKResponse(payload []byte) ([]byte, error) {
	if len(payload) == 0 {
		return nil, fmt.Errorf("empty tapfd payload")
	}
	if !bytes.Contains(payload, []byte{0}) {
		return nil, fmt.Errorf("tapfd payload is not NUL-terminated")
	}
	prefix := []byte(RequestVersion + " " + ResponseStatusOK + " ")
	if len(prefix)+len(payload) > MaxPayloadSize {
		return nil, fmt.Errorf("tapfd OK response size %d exceeds MaxPayloadSize=%d", len(prefix)+len(payload), MaxPayloadSize)
	}
	out := make([]byte, 0, len(prefix)+len(payload))
	out = append(out, prefix...)
	out = append(out, payload...)
	return out, nil
}

// StripOKResponse removes the optional TAPFD/1 OK prefix from a successful
// response payload. Bare metadata is accepted for the exec handoff path and
// for older helpers.
func StripOKResponse(payload []byte) ([]byte, error) {
	prefix := []byte(RequestVersion + " " + ResponseStatusOK + " ")
	if !bytes.HasPrefix(payload, prefix) {
		return payload, nil
	}
	rest := payload[len(prefix):]
	if len(rest) == 0 {
		return nil, fmt.Errorf("empty TAPFD/1 OK response")
	}
	return rest, nil
}

// BuildOpenRequest builds a single-line socket-mode request. extra is a
// provider-specific list of key=value tokens, for example "switch=sw0 port=1".
func BuildOpenRequest(extra string, wantNetns bool) ([]byte, error) {
	extra = strings.TrimSpace(extra)
	if strings.ContainsAny(extra, "\r\n\x00") {
		return nil, fmt.Errorf("tapfd request contains a line break or NUL")
	}
	line := RequestVersion + " " + RequestOpOpen
	if wantNetns {
		line += " want_netns=1"
	}
	if extra != "" {
		line += " " + extra
	}
	if len(line)+1 > RequestMaxLineSize {
		return nil, fmt.Errorf("tapfd request line too long: %d > %d", len(line)+1, RequestMaxLineSize)
	}
	return []byte(line + "\n"), nil
}

// ParseRequestLine parses one TAPFD/1 request line without the trailing
// newline. Unknown key=value fields are retained for provider-specific use.
func ParseRequestLine(line string) (*Request, error) {
	line = strings.TrimRight(strings.TrimSpace(line), "\r")
	if line == "" {
		return nil, fmt.Errorf("empty request")
	}
	if len(line)+1 > RequestMaxLineSize {
		return nil, fmt.Errorf("request line too long: %d > %d", len(line)+1, RequestMaxLineSize)
	}
	toks := strings.Fields(line)
	if len(toks) < 2 {
		return nil, fmt.Errorf("malformed request %q", line)
	}
	if toks[0] != RequestVersion {
		return nil, fmt.Errorf("unsupported request version %q", toks[0])
	}
	if toks[1] != RequestOpOpen {
		return nil, fmt.Errorf("unsupported request op %q", toks[1])
	}
	req := &Request{
		Version: toks[0],
		Op:      toks[1],
		Fields:  make(map[string]string, len(toks)-2),
	}
	for _, tok := range toks[2:] {
		key, val, ok := strings.Cut(tok, "=")
		if !ok || key == "" {
			return nil, fmt.Errorf("malformed request token %q", tok)
		}
		if key == "want_netns" || key == "TAPFD_WANT_NETNS" {
			req.WantNetns = isTruthy(val)
			continue
		}
		req.Fields[key] = val
	}
	return req, nil
}

// BuildErrorResponse builds a single-line error response for socket-mode
// providers. The message is sanitized into one token to keep the v1 grammar
// whitespace-free.
func BuildErrorResponse(code, message string) []byte {
	code = sanitizeToken(code)
	if code == "" {
		code = ErrorCodeProviderInternal
	}
	message = sanitizeToken(message)
	if message == "" {
		message = "error"
	}
	return []byte(fmt.Sprintf("%s %s code=%s message=%s\n", RequestVersion, ResponseStatusERR, code, message))
}

// ParseErrorResponse parses a TAPFD/1 ERR line and reports whether the payload
// was such a line. Non-error payloads return ok=false.
func ParseErrorResponse(payload []byte) (code, message string, ok bool, err error) {
	line := strings.TrimSpace(string(payload))
	if line == "" || !strings.HasPrefix(line, RequestVersion+" "+ResponseStatusERR) {
		return "", "", false, nil
	}
	toks := strings.Fields(line)
	if len(toks) < 3 || toks[0] != RequestVersion || toks[1] != ResponseStatusERR {
		return "", "", true, fmt.Errorf("malformed error response %q", line)
	}
	for _, tok := range toks[2:] {
		key, val, has := strings.Cut(tok, "=")
		if !has || key == "" {
			return "", "", true, fmt.Errorf("malformed error token %q", tok)
		}
		switch key {
		case "code":
			code = val
		case "message":
			message = val
		}
	}
	if code == "" {
		code = ErrorCodeProviderInternal
	}
	return code, message, true, nil
}

func isTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func sanitizeToken(v string) string {
	v = strings.TrimSpace(v)
	var b strings.Builder
	for _, r := range v {
		switch {
		case r == '=' || r == '\x00' || r == '\n' || r == '\r':
			b.WriteByte('_')
		case r == ' ' || r == '\t':
			b.WriteByte('_')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
