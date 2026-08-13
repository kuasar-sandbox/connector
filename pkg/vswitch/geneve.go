package vswitch

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/kuasar-sandbox/connector/pkg/internal/bpf"
)

const (
	// DefaultGenevePortBase preserves the legacy per-slot UDP port layout.
	DefaultGenevePortBase uint16 = 50000

	// GeneveStandardPort is used by the fixed-port VNI and TLV locators.
	GeneveStandardPort = bpf.GenevePort

	// MaxGeneveOptsLen is the maximum number of bytes after the GENEVE base
	// header, including the generated TLV locator when configured.
	MaxGeneveOptsLen = bpf.MaxGeneveOptsLen

	geneveTLVLocatorWireLen = 8
)

// GeneveLocator identifies where the zero-based slot_id is encoded on wire.
// The zero value is GeneveLocatorPort so old switch_config padding remains the
// legacy wire format.
type GeneveLocator uint8

const (
	GeneveLocatorPort GeneveLocator = iota
	GeneveLocatorVNI
	GeneveLocatorTLV
)

// Parse updates l from its user-facing name.
func (l *GeneveLocator) Parse(value string) error {
	parsed, err := ParseGeneveLocator(value)
	if err != nil {
		return err
	}
	*l = parsed
	return nil
}

// ParseGeneveLocator parses port, vni, or tlv. Empty input selects the legacy
// port default and is useful for omitted file configuration.
func ParseGeneveLocator(value string) (GeneveLocator, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "port":
		return GeneveLocatorPort, nil
	case "vni":
		return GeneveLocatorVNI, nil
	case "tlv":
		return GeneveLocatorTLV, nil
	default:
		return 0, fmt.Errorf("unknown GENEVE locator %q (want port, vni, or tlv)", value)
	}
}

// String returns the canonical user-facing name.
func (l GeneveLocator) String() string {
	switch l {
	case GeneveLocatorPort:
		return "port"
	case GeneveLocatorVNI:
		return "vni"
	case GeneveLocatorTLV:
		return "tlv"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(l))
	}
}

func (l GeneveLocator) valid() bool {
	return l >= GeneveLocatorPort && l <= GeneveLocatorTLV
}

// MarshalJSON encodes a locator as its stable string name.
func (l GeneveLocator) MarshalJSON() ([]byte, error) {
	if !l.valid() {
		return nil, fmt.Errorf("invalid GENEVE locator value %d", l)
	}
	return json.Marshal(l.String())
}

// UnmarshalJSON accepts the stable string form.
func (l *GeneveLocator) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("GENEVE locator must be a string: %w", err)
	}
	return l.Parse(value)
}

// GeneveTLVLocator identifies the exact class and 8-bit wire type of the
// generated slot locator. Type includes the critical bit and is never changed.
type GeneveTLVLocator struct {
	Class uint16
	Type  uint8
}

// ParseGeneveTLVLocator parses CLASS:TYPE hexadecimal wire values.
func ParseGeneveTLVLocator(value string) (GeneveTLVLocator, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return GeneveTLVLocator{}, fmt.Errorf("invalid GENEVE TLV locator %q (want CLASS:TYPE)", value)
	}
	class, err := parseHexUint(parts[0], 16, "class")
	if err != nil {
		return GeneveTLVLocator{}, fmt.Errorf("invalid GENEVE TLV locator %q: %w", value, err)
	}
	typeValue, err := parseHexUint(parts[1], 8, "type")
	if err != nil {
		return GeneveTLVLocator{}, fmt.Errorf("invalid GENEVE TLV locator %q: %w", value, err)
	}
	return GeneveTLVLocator{Class: uint16(class), Type: uint8(typeValue)}, nil
}

// String returns zero-padded lowercase hexadecimal wire values.
func (l GeneveTLVLocator) String() string {
	return fmt.Sprintf("%04x:%02x", l.Class, l.Type)
}

func (l GeneveTLVLocator) MarshalJSON() ([]byte, error) {
	return json.Marshal(l.String())
}

func (l *GeneveTLVLocator) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("GENEVE TLV locator must be a string: %w", err)
	}
	parsed, err := ParseGeneveTLVLocator(value)
	if err != nil {
		return err
	}
	*l = parsed
	return nil
}

// GeneveOption is one caller-defined opaque option. Data is emitted verbatim.
type GeneveOption struct {
	Class uint16
	Type  uint8
	Data  []byte
}

// ParseGeneveOption parses CLASS:TYPE:DATA. The final colon is required even
// for the protocol-valid zero-length data form.
func ParseGeneveOption(value string) (GeneveOption, error) {
	parts := strings.SplitN(value, ":", 3)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return GeneveOption{}, fmt.Errorf("invalid GENEVE option %q (want CLASS:TYPE:DATA)", value)
	}
	class, err := parseHexUint(parts[0], 16, "class")
	if err != nil {
		return GeneveOption{}, fmt.Errorf("invalid GENEVE option %q: %w", value, err)
	}
	typeValue, err := parseHexUint(parts[1], 8, "type")
	if err != nil {
		return GeneveOption{}, fmt.Errorf("invalid GENEVE option %q: %w", value, err)
	}
	data, err := hex.DecodeString(parts[2])
	if err != nil {
		return GeneveOption{}, fmt.Errorf("invalid GENEVE option %q data: %w", value, err)
	}
	if len(data)%4 != 0 {
		return GeneveOption{}, fmt.Errorf("invalid GENEVE option %q: data length %d is not a multiple of 4 bytes", value, len(data))
	}
	return GeneveOption{Class: uint16(class), Type: uint8(typeValue), Data: data}, nil
}

// ParseGeneveOptions parses a comma-separated TAPFD value using the same
// parser as the repeatable CLI option. Empty input means no options.
func ParseGeneveOptions(value string) ([]GeneveOption, error) {
	if value == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	options := make([]GeneveOption, 0, len(parts))
	for i, part := range parts {
		option, err := ParseGeneveOption(strings.TrimSpace(part))
		if err != nil {
			return nil, fmt.Errorf("GENEVE option %d: %w", i+1, err)
		}
		options = append(options, option)
	}
	return options, nil
}

// String returns the canonical compact wire representation.
func (o GeneveOption) String() string {
	return fmt.Sprintf("%04x:%02x:%s", o.Class, o.Type, hex.EncodeToString(o.Data))
}

func (o GeneveOption) MarshalJSON() ([]byte, error) {
	if len(o.Data)%4 != 0 {
		return nil, fmt.Errorf("GENEVE option data length %d is not a multiple of 4 bytes", len(o.Data))
	}
	return json.Marshal(o.String())
}

func (o *GeneveOption) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("GENEVE option must be a string: %w", err)
	}
	parsed, err := ParseGeneveOption(value)
	if err != nil {
		return err
	}
	*o = parsed
	return nil
}

func parseHexUint(value string, bits int, field string) (uint64, error) {
	if strings.HasPrefix(value, "+") || strings.HasPrefix(value, "-") {
		return 0, fmt.Errorf("%s %q must be an unsigned hexadecimal value", field, value)
	}
	parsed, err := strconv.ParseUint(value, 16, bits)
	if err != nil {
		return 0, fmt.Errorf("%s %q is not a %d-bit hexadecimal value", field, value, bits)
	}
	return parsed, nil
}

// marshalGeneveOptions validates and serializes opaque options for one slot.
// The returned totalLen includes the generated TLV locator when configured;
// the map value itself contains only opaque caller options.
func marshalGeneveOptions(locator GeneveLocator, tlv *GeneveTLVLocator, options []GeneveOption) (GeneveOptsValue, uint8, error) {
	var value GeneveOptsValue
	offset := 0
	for i, option := range options {
		if len(option.Data)%4 != 0 {
			return GeneveOptsValue{}, 0, fmt.Errorf("GENEVE option %d data length %d is not a multiple of 4 bytes", i+1, len(option.Data))
		}
		if locator == GeneveLocatorTLV && tlv != nil &&
			option.Class == tlv.Class && option.Type&0x7f == tlv.Type&0x7f {
			return GeneveOptsValue{}, 0, fmt.Errorf("GENEVE option %d %s collides with TLV locator %s", i+1, option.String(), tlv.String())
		}
		wireLen := 4 + len(option.Data)
		if offset+wireLen > int(MaxGeneveOptsLen) {
			return GeneveOptsValue{}, 0, fmt.Errorf("opaque GENEVE options length %d exceeds maximum %d bytes", offset+wireLen, MaxGeneveOptsLen)
		}
		value.Data[offset] = byte(option.Class >> 8)
		value.Data[offset+1] = byte(option.Class)
		value.Data[offset+2] = option.Type
		value.Data[offset+3] = byte(len(option.Data) / 4)
		copy(value.Data[offset+4:offset+wireLen], option.Data)
		offset += wireLen
		if option.Type&0x80 != 0 {
			value.Critical = 1
		}
	}

	totalLen := offset
	if locator == GeneveLocatorTLV {
		totalLen += geneveTLVLocatorWireLen
	}
	if totalLen > int(MaxGeneveOptsLen) {
		return GeneveOptsValue{}, 0, fmt.Errorf("GENEVE wire options length %d exceeds maximum %d bytes", totalLen, MaxGeneveOptsLen)
	}
	value.Len = uint8(offset)
	return value, uint8(totalLen), nil
}

// validateTransitGeneveVNI enforces the locator-specific VNI width.
func validateTransitGeneveVNI(locator GeneveLocator, vni uint32) error {
	max := uint32(0xffffff)
	if locator == GeneveLocatorVNI {
		max = bpf.GeneveVNIValueMask
	}
	if vni > max {
		return fmt.Errorf("transit GENEVE VNI %#x exceeds %s locator maximum %#x", vni, locator, max)
	}
	return nil
}

func geneveWirePort(locator GeneveLocator, portBase uint32, slotID uint32) uint16 {
	if locator == GeneveLocatorPort {
		return uint16(portBase + slotID)
	}
	return GeneveStandardPort
}

// GeneveWirePort returns the actual UDP destination port for a slot.
func GeneveWirePort(locator GeneveLocator, portBase uint32, slotID uint32) uint16 {
	return geneveWirePort(locator, portBase, slotID)
}

func geneveWireVNI(locator GeneveLocator, slotID uint32, vni uint32) uint32 {
	if locator == GeneveLocatorVNI {
		return slotID<<bpf.GeneveVNILocatorBits | vni
	}
	return vni
}

func geneveLocatorFromConfig(cfg *SwitchConfig) GeneveLocator {
	return GeneveLocator(cfg.GeneveLocator)
}

// GeneveLocatorFromSwitchConfig decodes the in-kernel locator value.
func GeneveLocatorFromSwitchConfig(cfg *SwitchConfig) GeneveLocator {
	return geneveLocatorFromConfig(cfg)
}

func geneveTLVLocatorFromConfig(cfg *SwitchConfig) GeneveTLVLocator {
	return GeneveTLVLocator{Class: cfg.GeneveTlvClass, Type: cfg.GeneveTlvType}
}

// GeneveTLVLocatorFromSwitchConfig returns the exact configured class/type.
func GeneveTLVLocatorFromSwitchConfig(cfg *SwitchConfig) GeneveTLVLocator {
	return geneveTLVLocatorFromConfig(cfg)
}

func geneveTotalOptionsLen(locator GeneveLocator, opaqueLen uint8) uint8 {
	if locator == GeneveLocatorTLV {
		return opaqueLen + geneveTLVLocatorWireLen
	}
	return opaqueLen
}

// GeneveTotalOptionsLen adds the generated locator to the opaque option hint.
func GeneveTotalOptionsLen(locator GeneveLocator, opaqueLen uint8) uint8 {
	return geneveTotalOptionsLen(locator, opaqueLen)
}
