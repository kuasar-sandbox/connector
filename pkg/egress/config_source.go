package egress

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// YAML and its JSON subset share one schema and validation path.
func decodeSource(raw []byte, value any) error {
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	var root yaml.Node
	if err := decoder.Decode(&root); err != nil {
		return err
	}
	if len(root.Content) != 1 || root.Content[0].Kind != yaml.MappingNode {
		return errors.New("expected a YAML/JSON object")
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("expected one complete YAML/JSON document")
	}
	if err := checkSourceNode(root.Content[0], 0); err != nil {
		return err
	}
	var data any
	if err := root.Decode(&data); err != nil {
		return err
	}
	normalized, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return decodeJSON(normalized, value)
}
func checkSourceNode(n *yaml.Node, depth int) error {
	if depth > 64 {
		return errors.New("configuration nesting exceeds 64 levels")
	}
	if n.Kind == yaml.AliasNode {
		return checkSourceNode(n.Alias, depth+1)
	}
	if n.Kind == yaml.MappingNode {
		keys := map[string]bool{}
		for i := 0; i < len(n.Content); i += 2 {
			key, v := n.Content[i], n.Content[i+1]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" && key.Tag != "!!merge" {
				return errors.New("configuration keys must be strings")
			}
			name := strings.ToLower(key.Value)
			if keys[name] {
				return fmt.Errorf("duplicate configuration member %q", key.Value)
			}
			keys[name] = true
			if name == "routes" && v.Tag == "!!null" {
				return errors.New("routes must be omitted or an array, not null")
			}
			if err := checkSourceNode(v, depth+1); err != nil {
				return err
			}
		}
	} else if n.Kind == yaml.SequenceNode {
		for _, v := range n.Content {
			if err := checkSourceNode(v, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

// StringSet is written as one string or a list, without parallel field names.
type StringSet []string

func (s *StringSet) UnmarshalJSON(raw []byte) error {
	if len(raw) > 0 && raw[0] == '"' {
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return err
		}
		*s = []string{value}
		return nil
	}
	if bytes.Equal(raw, []byte("null")) {
		return errors.New("expected a value or list, not null")
	}
	var values []string
	if err := json.Unmarshal(raw, &values); err != nil {
		return err
	}
	*s = values
	return nil
}
func (s StringSet) MarshalJSON() ([]byte, error) {
	if len(s) == 1 {
		return json.Marshal(s[0])
	}
	return json.Marshal([]string(s))
}

type portRange struct{ first, last uint16 }

func (p *portRange) UnmarshalJSON(raw []byte) error {
	var value string
	if len(raw) > 0 && raw[0] == '"' {
		if err := json.Unmarshal(raw, &value); err != nil {
			return err
		}
	} else {
		value = string(raw)
	}
	parts := strings.Split(value, "-")
	if len(parts) > 2 {
		return errors.New("invalid port range")
	}
	first, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 16)
	if err != nil || first == 0 {
		return fmt.Errorf("invalid port %q", value)
	}
	last := first
	if len(parts) == 2 {
		last, err = strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 16)
		if err != nil || last < first {
			return fmt.Errorf("invalid port range %q", value)
		}
	}
	p.first, p.last = uint16(first), uint16(last)
	return nil
}
func (p portRange) MarshalJSON() ([]byte, error) {
	if p.first == p.last {
		return json.Marshal(p.first)
	}
	return json.Marshal(fmt.Sprintf("%d-%d", p.first, p.last))
}

type portSet []portRange

func (p *portSet) UnmarshalJSON(raw []byte) error {
	if len(raw) > 0 && raw[0] == '[' {
		var values []portRange
		if err := json.Unmarshal(raw, &values); err != nil {
			return err
		}
		*p = values
		return nil
	}
	var value portRange
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	*p = []portRange{value}
	return nil
}
func (p portSet) MarshalJSON() ([]byte, error) {
	if len(p) == 1 {
		return json.Marshal(p[0])
	}
	return json.Marshal([]portRange(p))
}
func (p portSet) normalized() portSet {
	values := append(portSet{}, p...)
	sort.Slice(values, func(i, j int) bool { return values[i].first < values[j].first })
	result := portSet{}
	for _, value := range values {
		n := len(result)
		if n > 0 && uint32(value.first) <= uint32(result[n-1].last)+1 {
			if value.last > result[n-1].last {
				result[n-1].last = value.last
			}
		} else {
			result = append(result, value)
		}
	}
	return result
}

type addressRange struct{ first, last uint32 }

func addressNumber(a netip.Addr) uint32 { value := a.As4(); return binary.BigEndian.Uint32(value[:]) }
func numberAddress(n uint32) netip.Addr {
	var value [4]byte
	binary.BigEndian.PutUint32(value[:], n)
	return netip.AddrFrom4(value)
}
func parseAddressRange(value string) (addressRange, error) {
	value = strings.TrimSpace(value)
	if strings.Contains(value, "/") {
		network, err := prefix(value)
		if err != nil {
			return addressRange{}, err
		}
		first := addressNumber(network.Addr())
		last := uint32(uint64(first) + (uint64(1) << uint(32-network.Bits())) - 1)
		return addressRange{first, last}, nil
	}
	parts := strings.Split(value, "-")
	if len(parts) > 2 {
		return addressRange{}, fmt.Errorf("invalid IPv4 range %q", value)
	}
	first, err := netip.ParseAddr(strings.TrimSpace(parts[0]))
	if err != nil || !first.Is4() {
		return addressRange{}, fmt.Errorf("invalid IPv4 address %q", value)
	}
	last := first
	if len(parts) == 2 {
		last, err = netip.ParseAddr(strings.TrimSpace(parts[1]))
		if err != nil || !last.Is4() || last.Less(first) {
			return addressRange{}, fmt.Errorf("invalid IPv4 range %q", value)
		}
	}
	return addressRange{addressNumber(first), addressNumber(last)}, nil
}
func addressRanges(values []string) ([]addressRange, error) {
	ranges := []addressRange{}
	for _, value := range values {
		r, err := parseAddressRange(value)
		if err != nil {
			return nil, err
		}
		ranges = append(ranges, r)
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].first < ranges[j].first })
	result := []addressRange{}
	for _, value := range ranges {
		n := len(result)
		if n > 0 && uint64(value.first) <= uint64(result[n-1].last)+1 {
			if value.last > result[n-1].last {
				result[n-1].last = value.last
			}
		} else {
			result = append(result, value)
		}
	}
	return result, nil
}
func rangePrefixes(r addressRange) []string {
	result := []string{}
	for first := uint64(r.first); first <= uint64(r.last); {
		size := bits.TrailingZeros32(uint32(first))
		remaining := bits.Len64(uint64(r.last)-first+1) - 1
		if size > remaining {
			size = remaining
		}
		result = append(result, netip.PrefixFrom(numberAddress(uint32(first)), 32-size).String())
		first += uint64(1) << size
	}
	return result
}
func addressPrefixes(values []string) ([]string, error) {
	ranges, err := addressRanges(values)
	if err != nil {
		return nil, err
	}
	result := []string{}
	for _, r := range ranges {
		result = append(result, rangePrefixes(r)...)
	}
	return result, nil
}

// Source rules keep concise sets. The compiler emits scalar native rules in
// original rule order, so expanding a set never changes first-match priority.
type sourceMatch struct {
	Destination StringSet `json:"destination,omitempty"`
	Protocol    StringSet `json:"protocol,omitempty"`
	Ports       portSet   `json:"ports,omitempty"`
}
type sourceACL struct {
	sourceMatch
	Action string `json:"action"`
}
type sourceDNAT struct {
	sourceMatch
	Pool       string `json:"pool"`
	Target     string `json:"target"`
	TargetPort uint16 `json:"target_port,omitempty"`
}
type sourceRoute struct {
	Destination StringSet `json:"destination"`
	Pool        string    `json:"pool"`
}
type sourceArea struct {
	VNI    uint32         `json:"vni"`
	Pools  []Pool         `json:"pools"`
	ACL    []sourceACL    `json:"acl,omitempty"`
	DNAT   []sourceDNAT   `json:"dnat,omitempty"`
	Routes *[]sourceRoute `json:"routes,omitempty"`
}

func (m sourceMatch) expand(dnat bool) ([]Match, error) {
	destinations := m.Destination
	if destinations == nil {
		destinations = StringSet{"0.0.0.0/0"}
	}
	networks, err := addressPrefixes(destinations)
	if err != nil {
		return nil, err
	}
	protocols := m.Protocol
	if protocols == nil {
		if dnat || m.Ports != nil {
			protocols = StringSet{"tcp", "udp"}
		} else {
			protocols = StringSet{"any"}
		}
	}
	ports := m.Ports
	if ports == nil {
		ports = portSet{{0, 0}}
	} else {
		ports = ports.normalized()
	}
	if len(networks) == 0 || len(protocols) == 0 || len(ports) == 0 {
		return nil, errors.New("match sets must not be empty; omit a match to allow any value")
	}
	result := []Match{}
	seen := map[Match]bool{}
	for _, network := range networks {
		for _, proto := range protocols {
			for _, port := range ports {
				match := Match{Destination: network, Protocol: proto, PortFirst: port.first, PortLast: port.last}
				if err := match.validate(); err != nil {
					return nil, err
				}
				if dnat && proto != "tcp" && proto != "udp" {
					return nil, errors.New("DNAT requires TCP or UDP")
				}
				if !seen[match] {
					result = append(result, match)
					seen[match] = true
				}
			}
		}
	}
	return result, nil
}
func matchSource(m Match) sourceMatch {
	result := sourceMatch{}
	if m.Destination != "" && m.Destination != "0.0.0.0/0" {
		result.Destination = StringSet{m.Destination}
	}
	if m.Protocol != "" {
		result.Protocol = StringSet{m.Protocol}
	}
	if m.PortFirst != 0 || m.PortLast != 0 {
		result.Ports = portSet{{m.PortFirst, m.PortLast}}
	}
	return result
}
func (a *Area) UnmarshalJSON(raw []byte) error {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return err
	}
	for key, value := range members {
		if strings.EqualFold(key, "routes") && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return errors.New("routes must be omitted or an array, not null")
		}
	}
	var source sourceArea
	if err := decodeJSON(raw, &source); err != nil {
		return err
	}
	result := Area{VNI: source.VNI, Pools: source.Pools, ACL: []ACL{}, DNAT: []DNAT{}}
	for _, rule := range source.ACL {
		matches, err := rule.sourceMatch.expand(false)
		if err != nil {
			return err
		}
		for _, match := range matches {
			result.ACL = append(result.ACL, ACL{Match: match, Action: rule.Action})
		}
	}
	for _, rule := range source.DNAT {
		matches, err := rule.sourceMatch.expand(true)
		if err != nil {
			return err
		}
		for _, match := range matches {
			result.DNAT = append(result.DNAT, DNAT{Match: match, Pool: rule.Pool, Target: rule.Target, TargetPort: rule.TargetPort})
		}
	}
	if source.Routes != nil {
		result.Routes = []Route{}
		for _, rule := range *source.Routes {
			if len(rule.Destination) == 0 {
				return errors.New("route requires destination addresses")
			}
			// Explicit route prefix lengths carry LPM priority: do not coalesce
			// adjacent CIDRs into a less-specific route with different precedence.
			for _, value := range rule.Destination {
				r, err := parseAddressRange(value)
				if err != nil {
					return err
				}
				for _, network := range rangePrefixes(r) {
					result.Routes = append(result.Routes, Route{Destination: network, Pool: rule.Pool})
				}
			}
		}
	}
	*a = result
	return nil
}
func (a Area) MarshalJSON() ([]byte, error) {
	source := sourceArea{VNI: a.VNI, Pools: a.Pools}
	for _, rule := range a.ACL {
		source.ACL = append(source.ACL, sourceACL{sourceMatch: matchSource(rule.Match), Action: rule.Action})
	}
	for _, rule := range a.DNAT {
		source.DNAT = append(source.DNAT, sourceDNAT{sourceMatch: matchSource(rule.Match), Pool: rule.Pool, Target: rule.Target, TargetPort: rule.TargetPort})
	}
	if a.Routes != nil {
		routes := []sourceRoute{}
		for _, rule := range a.Routes {
			routes = append(routes, sourceRoute{Destination: StringSet{rule.Destination}, Pool: rule.Pool})
		}
		source.Routes = &routes
	}
	return json.Marshal(source)
}

func (a *Area) normalize() error {
	for i := range a.Pools {
		p := &a.Pools[i]
		ranges, err := addressRanges(p.Addresses)
		if err != nil {
			return err
		}
		addresses := StringSet{}
		for _, r := range ranges {
			// Reject non-unicast ranges before expansion, including ranges whose
			// endpoints alone would hide an unusable interval in the middle.
			for _, blocked := range []addressRange{{0, 0}, {0x7f000000, 0x7fffffff}, {0xe0000000, 0xefffffff}, {0xffffffff, 0xffffffff}} {
				if r.first <= blocked.last && blocked.first <= r.last {
					return errors.New("Pool address range contains non-unicast addresses")
				}
			}
			for ip := uint64(r.first); ip <= uint64(r.last); ip++ {
				addresses = append(addresses, numberAddress(uint32(ip)).String())
			}
		}
		p.Addresses = addresses
	}
	for i := range a.ACL {
		if a.ACL[i].Destination == "" {
			a.ACL[i].Destination = "0.0.0.0/0"
		}
		if a.ACL[i].Protocol == "" {
			a.ACL[i].Protocol = "any"
		}
	}
	if a.Routes == nil {
		switch len(a.Pools) {
		case 0:
			a.Routes = []Route{}
		case 1:
			a.Routes = []Route{{Destination: "0.0.0.0/0", Pool: a.Pools[0].Name}}
		default:
			return errors.New("multiple Pools require explicit routes; use [] for no ordinary exit")
		}
	}
	routes := []Route{}
	seen := map[Route]bool{}
	for _, route := range a.Routes {
		if !seen[route] {
			routes = append(routes, route)
			seen[route] = true
		}
	}
	a.Routes = routes
	return nil
}
