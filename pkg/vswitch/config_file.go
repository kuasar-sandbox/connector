package vswitch

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
)

// configValue retains JSON member order, duplicate members and number spelling.
// A map[string]any would change all three before FileConfig sees the input.
// Arrays are atomic values: layers replace them rather than merge their items.
type configValue struct {
	object  bool
	members []configMember
	raw     json.RawMessage
}

type configMember struct {
	name  string
	value *configValue
}

// LoadConfigFile loads PATH[:PATH...] in order. Each file is parsed as JSON
// first, with one YAML fallback only for JSON syntax errors, irrespective of its
// name. Layers are combined before FileConfig decoding and ToConfig defaults.
// Directories are not discovered and colons cannot occur in individual paths.
func LoadConfigFile(path string) (*Config, error) {
	paths := strings.Split(path, ":")
	for _, name := range paths {
		if name == "" {
			return nil, fmt.Errorf("config paths %q: empty path segment", path)
		}
	}
	var merged *configValue
	for i, name := range paths {
		data, err := os.ReadFile(name)
		if err != nil {
			return nil, fmt.Errorf("read config %q: %w", name, err)
		}
		value, err := parseConfigFile(data)
		if err != nil {
			return nil, fmt.Errorf("parse config %q: %w", name, err)
		}
		if !value.object {
			return nil, fmt.Errorf("parse config %q: root must be an object", name)
		}
		if i == 0 {
			merged = value // The first file's null members keep their native meaning.
		} else {
			merged = mergeConfigObjects(merged, value, true)
		}
	}
	var data bytes.Buffer
	merged.writeJSON(&data)
	var fc FileConfig
	if err := json.Unmarshal(data.Bytes(), &fc); err != nil {
		return nil, fmt.Errorf("decode config %q: %w", path, err)
	}
	cfg, err := fc.ToConfig()
	if err != nil {
		return nil, fmt.Errorf("convert config %q: %w", path, err)
	}
	return cfg, nil
}

func parseConfigFile(data []byte) (*configValue, error) {
	// RawMessage checks the entire JSON document, including trailing input,
	// without running FileConfig or a custom field decoder. Those errors must
	// never trigger YAML fallback.
	var raw json.RawMessage
	jsonErr := json.Unmarshal(data, &raw)
	if jsonErr == nil {
		return parseConfigJSON(raw)
	}
	value, yamlErr := parseConfigYAML(data)
	if yamlErr != nil {
		return nil, fmt.Errorf("JSON: %v; YAML: %w", jsonErr, yamlErr)
	}
	return value, nil
}

func parseConfigJSON(data []byte) (*configValue, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '{' {
		return &configValue{raw: data}, nil
	}
	d := json.NewDecoder(bytes.NewReader(data))
	if _, err := d.Token(); err != nil {
		return nil, err
	}
	value := &configValue{object: true}
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return nil, err
		}
		var raw json.RawMessage
		if err := d.Decode(&raw); err != nil {
			return nil, err
		}
		child, err := parseConfigJSON(raw)
		if err != nil {
			return nil, err
		}
		value.members = append(value.members, configMember{key.(string), child})
	}
	_, err := d.Token()
	return value, err
}

func (v *configValue) writeJSON(out *bytes.Buffer) {
	if !v.object {
		out.Write(v.raw)
		return
	}
	out.WriteByte('{')
	for i, member := range v.members {
		if i != 0 {
			out.WriteByte(',')
		}
		key, _ := json.Marshal(member.name)
		out.Write(key)
		out.WriteByte(':')
		member.value.writeJSON(out)
	}
	out.WriteByte('}')
}

func (v *configValue) isNull() bool {
	return !v.object && bytes.Equal(v.raw, []byte("null"))
}

var configJSONNames = func() []string {
	t := reflect.TypeOf(FileConfig{})
	names := make([]string, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		name := strings.Split(t.Field(i).Tag.Get("json"), ",")[0]
		if name != "" && name != "-" {
			names = append(names, name)
		}
	}
	return names
}()

func configMemberID(name string, root bool) string {
	if root {
		for _, known := range configJSONNames {
			if strings.EqualFold(name, known) {
				return known
			}
		}
	}
	return name
}

// Replace the inherited occurrences of each field as a group. Keeping the new
// group's original order lets encoding/json retain its duplicate-member rules:
// for an int, {"mtu":9000,"mtu":null} still means 9000, while a group consisting
// only of null deletes the inherited field. Field aliases such as MTU and mtu
// have the same identity only where FileConfig's JSON decoder recognizes them.
func mergeConfigObjects(base, layer *configValue, root bool) *configValue {
	result := &configValue{object: true, members: append([]configMember(nil), base.members...)}
	seen := make(map[string]bool)
	for _, first := range layer.members {
		id := configMemberID(first.name, root)
		if seen[id] {
			continue
		}
		seen[id] = true
		var group []configMember
		allNull, allObjects := true, true
		for _, member := range layer.members {
			if configMemberID(member.name, root) == id {
				group = append(group, member)
				allNull = allNull && member.value.isNull()
				allObjects = allObjects && member.value.object
			}
		}
		var inherited *configValue
		kept := make([]configMember, 0, len(result.members))
		for _, member := range result.members {
			if configMemberID(member.name, root) == id {
				inherited = member.value
			} else {
				kept = append(kept, member)
			}
		}
		result.members = kept
		if allNull {
			continue
		}
		if allObjects {
			if inherited == nil || !inherited.object {
				inherited = &configValue{object: true}
			}
			for _, member := range group {
				inherited = mergeConfigObjects(inherited, member.value, false)
			}
			result.members = append(result.members, configMember{first.name, inherited})
		} else {
			result.members = append(result.members, group...)
		}
	}
	return result
}

func parseConfigYAML(data []byte) (*configValue, error) {
	d := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := d.Decode(&document); err != nil {
		return nil, err
	}
	var extra yaml.Node
	if err := d.Decode(&extra); err != io.EOF {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("multiple YAML documents are not supported")
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("root must be a mapping")
	}
	// Validate the complete document before overlays can hide duplicate keys.
	// The native decoder also rejects recursive/excessive alias expansion. The
	// temporary result is not used: its numeric conversion would lose spelling.
	var checked any
	if err := document.Decode(&checked); err != nil {
		return nil, err
	}
	return configFromYAML(document.Content[0])
}

func configFromYAML(n *yaml.Node) (*configValue, error) {
	if n.Kind == yaml.AliasNode {
		return configFromYAML(n.Alias)
	}
	switch n.Kind {
	case yaml.MappingNode:
		value := &configValue{object: true}
		explicit := make(map[string]bool)
		for i := 0; i < len(n.Content); i += 2 {
			key := n.Content[i]
			if key.Tag == "!!merge" {
				continue
			}
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
				return nil, fmt.Errorf("line %d: mapping keys must be strings", key.Line)
			}
			explicit[key.Value] = true
		}
		// YAML merge sequences give the first source precedence. Explicit keys
		// always override merged keys, regardless of where << appears.
		for i := 0; i < len(n.Content); i += 2 {
			if n.Content[i].Tag != "!!merge" {
				continue
			}
			sources := n.Content[i+1]
			if sources.Kind == yaml.AliasNode {
				sources = sources.Alias
			}
			items := []*yaml.Node{sources}
			if sources.Kind == yaml.SequenceNode {
				items = sources.Content
			}
			for _, item := range items {
				merged, err := configFromYAML(item)
				if err != nil {
					return nil, err
				}
				if !merged.object {
					return nil, fmt.Errorf("line %d: YAML merge value must be a mapping", item.Line)
				}
				for _, member := range merged.members {
					if !explicit[member.name] {
						explicit[member.name] = true
						value.members = append(value.members, member)
					}
				}
			}
		}
		for i := 0; i < len(n.Content); i += 2 {
			if n.Content[i].Tag == "!!merge" {
				continue
			}
			child, err := configFromYAML(n.Content[i+1])
			if err != nil {
				return nil, err
			}
			value.members = append(value.members, configMember{n.Content[i].Value, child})
		}
		return value, nil
	case yaml.SequenceNode:
		var out bytes.Buffer
		out.WriteByte('[')
		for i, child := range n.Content {
			if i != 0 {
				out.WriteByte(',')
			}
			value, err := configFromYAML(child)
			if err != nil {
				return nil, err
			}
			value.writeJSON(&out)
		}
		out.WriteByte(']')
		return &configValue{raw: out.Bytes()}, nil
	case yaml.ScalarNode:
		var raw []byte
		switch n.Tag {
		case "!!null":
			raw = []byte("null")
		case "!!bool":
			raw = []byte(strings.ToLower(n.Value))
		case "!!int":
			integer, ok := new(big.Int).SetString(strings.ReplaceAll(n.Value, "_", ""), 0)
			if !ok {
				return nil, fmt.Errorf("line %d: invalid integer %q", n.Line, n.Value)
			}
			raw = []byte(integer.String())
		case "!!float":
			number, err := configYAMLFloat(n.Value)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", n.Line, err)
			}
			raw = []byte(number)
		case "!!binary":
			var decoded string
			if err := n.Decode(&decoded); err != nil {
				return nil, err
			}
			raw, _ = json.Marshal(decoded)
		default:
			// Strings, timestamps and application tags keep their source text.
			raw, _ = json.Marshal(n.Value)
		}
		return &configValue{raw: raw}, nil
	default:
		return nil, fmt.Errorf("line %d: unsupported YAML node", n.Line)
	}
}

// Normalize YAML's decimal spelling without converting through float64. Keep
// floats distinguishable from integers so 9000.0 cannot silently become an int.
func configYAMLFloat(value string) (string, error) {
	number := strings.ReplaceAll(value, "_", "")
	number = strings.TrimPrefix(number, "+")
	sign := ""
	if strings.HasPrefix(number, "-") {
		sign, number = "-", number[1:]
	}
	exponent := ""
	if i := strings.IndexAny(number, "eE"); i >= 0 {
		number, exponent = number[:i], number[i:]
	}
	whole, fraction, dot := strings.Cut(number, ".")
	whole = strings.TrimLeft(whole, "0")
	if whole == "" {
		whole = "0"
	}
	number = sign + whole
	if dot {
		if fraction == "" {
			fraction = "0"
		}
		number += "." + fraction
	} else if exponent == "" {
		number += ".0"
	}
	number += exponent
	if !json.Valid([]byte(number)) {
		return "", fmt.Errorf("YAML number %q is not a finite JSON number", value)
	}
	return number, nil
}
