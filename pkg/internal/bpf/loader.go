// Package bpf provides eBPF program loading and management.
package bpf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

const (
	// BPF filesystem path
	BPFPath = "/sys/fs/bpf"
)

// Programs holds the loaded eBPF programs.
type Programs struct {
	IngressNX      *ebpf.Program
	IngressMX      *ebpf.Program
	IngressTransit *ebpf.Program
}

// Maps holds the loaded eBPF maps.
type Maps struct {
	Slots         *ebpf.Map
	Config        *ebpf.Map
	Stats         *ebpf.Map
	IfindexToSlot *ebpf.Map
	Metadata      *ebpf.Map // Userspace-only metadata (new)
	MgmtSvcFwd    *ebpf.Map // mgmt service NAT, egress: {VIP,vport,proto}->{target_ip,target_port}
	MgmtSvcRev    *ebpf.Map // mgmt service NAT, ingress: {target_ip,tport,proto}->{VIP,vport}
}

// Objects holds all loaded eBPF objects.
type Objects struct {
	Programs *Programs
	Maps     *Maps
}

func init() {
	// Remove resource limits for kernels < 5.11
	if err := rlimit.RemoveMemlock(); err != nil {
		//ignore error, as it may fail on older kernels without rlimit support
	}
}

// Close releases all eBPF resources.
func (o *Objects) Close() error {
	var errs []error
	if o.Programs != nil {
		if o.Programs.IngressNX != nil {
			errs = append(errs, o.Programs.IngressNX.Close())
		}
		if o.Programs.IngressMX != nil {
			errs = append(errs, o.Programs.IngressMX.Close())
		}
		if o.Programs.IngressTransit != nil {
			errs = append(errs, o.Programs.IngressTransit.Close())
		}
	}
	if o.Maps != nil {
		errs = append(errs, o.Maps.Close())
	}
	return errors.Join(errs...)
}

// LoadObjects loads the eBPF programs and maps from the embedded bytecode.
func LoadObjects() (*Objects, error) {
	spec, err := loadVswitch()
	if err != nil {
		return nil, fmt.Errorf("failed to load BPF spec: %w", err)
	}

	var objs vswitchObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("failed to load BPF objects: %w", err)
	}

	return &Objects{
		Programs: &Programs{
			IngressNX:      objs.TcIngressNx,
			IngressMX:      objs.TcIngressMx,
			IngressTransit: objs.TcIngressTransit,
		},
		Maps: &Maps{
			Slots:         objs.Slots,
			Config:        objs.Config,
			Stats:         objs.Stats,
			IfindexToSlot: objs.IfindexToSlot,
			Metadata:      objs.Metadata,
			MgmtSvcFwd:    objs.MgmtSvcFwd,
			MgmtSvcRev:    objs.MgmtSvcRev,
		},
	}, nil
}

// ensureBPFFS ensures the BPF filesystem is mounted at /sys/fs/bpf.
func ensureBPFFS() error {
	// Check if already mounted by looking for the expected filesystem type
	var stat unix.Statfs_t
	if err := unix.Statfs(BPFPath, &stat); err == nil {
		// BPF_FS_MAGIC = 0xcafe4a11
		if stat.Type == 0xcafe4a11 {
			return nil
		}
	}

	// Create mount point if needed
	if err := os.MkdirAll(BPFPath, 0755); err != nil {
		return fmt.Errorf("failed to create %s: %w", BPFPath, err)
	}

	// Mount bpffs
	if err := unix.Mount("bpffs", BPFPath, "bpf", 0, ""); err != nil {
		return fmt.Errorf("failed to mount bpffs at %s: %w", BPFPath, err)
	}

	return nil
}

// PinMaps pins the eBPF maps to the BPF filesystem.
// The pin directory must already exist (created by StartReserved via os.Mkdir).
func (o *Objects) PinMaps(switchName string) error {
	pinPath := filepath.Join(BPFPath, switchName)

	// Pin each map
	if err := o.Maps.Slots.Pin(filepath.Join(pinPath, "slots")); err != nil {
		return fmt.Errorf("failed to pin slots map: %w", err)
	}
	if err := o.Maps.Config.Pin(filepath.Join(pinPath, "config")); err != nil {
		return fmt.Errorf("failed to pin config map: %w", err)
	}
	if err := o.Maps.Stats.Pin(filepath.Join(pinPath, "stats")); err != nil {
		return fmt.Errorf("failed to pin stats map: %w", err)
	}
	if err := o.Maps.IfindexToSlot.Pin(filepath.Join(pinPath, "ifindex_to_slot")); err != nil {
		return fmt.Errorf("failed to pin ifindex_to_slot map: %w", err)
	}
	if err := o.Maps.Metadata.Pin(filepath.Join(pinPath, "metadata")); err != nil {
		return fmt.Errorf("failed to pin metadata map: %w", err)
	}
	if err := o.Maps.MgmtSvcFwd.Pin(filepath.Join(pinPath, "mgmt_svc_fwd")); err != nil {
		return fmt.Errorf("failed to pin mgmt_svc_fwd map: %w", err)
	}
	if err := o.Maps.MgmtSvcRev.Pin(filepath.Join(pinPath, "mgmt_svc_rev")); err != nil {
		return fmt.Errorf("failed to pin mgmt_svc_rev map: %w", err)
	}

	return nil
}

// ClosePrograms releases all program resources.
func (p *Programs) Close() error {
	var errs []error
	if p.IngressNX != nil {
		errs = append(errs, p.IngressNX.Close())
	}
	if p.IngressMX != nil {
		errs = append(errs, p.IngressMX.Close())
	}
	if p.IngressTransit != nil {
		errs = append(errs, p.IngressTransit.Close())
	}
	return errors.Join(errs...)
}

// EnsureBPFFS ensures the BPF filesystem is mounted. Exported for use by flock.
func EnsureBPFFS() error {
	return ensureBPFFS()
}

// UnpinMaps removes pinned maps from the BPF filesystem.
func UnpinMaps(switchName string) error {
	pinPath := filepath.Join(BPFPath, switchName)
	return os.RemoveAll(pinPath)
}

// LoadPinnedMaps loads maps from the BPF filesystem.
func LoadPinnedMaps(switchName string) (*Maps, error) {
	pinPath := filepath.Join(BPFPath, switchName)

	slots, err := ebpf.LoadPinnedMap(filepath.Join(pinPath, "slots"), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to load slots map: %w", err)
	}

	config, err := ebpf.LoadPinnedMap(filepath.Join(pinPath, "config"), nil)
	if err != nil {
		slots.Close()
		return nil, fmt.Errorf("failed to load config map: %w", err)
	}

	stats, err := ebpf.LoadPinnedMap(filepath.Join(pinPath, "stats"), nil)
	if err != nil {
		slots.Close()
		config.Close()
		return nil, fmt.Errorf("failed to load stats map: %w", err)
	}

	ifindexToSlot, err := ebpf.LoadPinnedMap(filepath.Join(pinPath, "ifindex_to_slot"), nil)
	if err != nil {
		slots.Close()
		config.Close()
		stats.Close()
		return nil, fmt.Errorf("failed to load ifindex_to_slot map: %w", err)
	}

	metadata, err := ebpf.LoadPinnedMap(filepath.Join(pinPath, "metadata"), nil)
	if err != nil {
		slots.Close()
		config.Close()
		stats.Close()
		ifindexToSlot.Close()
		return nil, fmt.Errorf("failed to load metadata map: %w", err)
	}

	mgmtSvcFwd, err := ebpf.LoadPinnedMap(filepath.Join(pinPath, "mgmt_svc_fwd"), nil)
	if err != nil {
		slots.Close()
		config.Close()
		stats.Close()
		ifindexToSlot.Close()
		metadata.Close()
		return nil, fmt.Errorf("failed to load mgmt_svc_fwd map: %w", err)
	}

	mgmtSvcRev, err := ebpf.LoadPinnedMap(filepath.Join(pinPath, "mgmt_svc_rev"), nil)
	if err != nil {
		slots.Close()
		config.Close()
		stats.Close()
		ifindexToSlot.Close()
		metadata.Close()
		mgmtSvcFwd.Close()
		return nil, fmt.Errorf("failed to load mgmt_svc_rev map: %w", err)
	}

	return &Maps{
		Slots:         slots,
		Config:        config,
		Stats:         stats,
		IfindexToSlot: ifindexToSlot,
		Metadata:      metadata,
		MgmtSvcFwd:    mgmtSvcFwd,
		MgmtSvcRev:    mgmtSvcRev,
	}, nil
}

// CloseMaps releases all map resources.
func (m *Maps) Close() error {
	var errs []error
	if m.Slots != nil {
		errs = append(errs, m.Slots.Close())
	}
	if m.Config != nil {
		errs = append(errs, m.Config.Close())
	}
	if m.Stats != nil {
		errs = append(errs, m.Stats.Close())
	}
	if m.IfindexToSlot != nil {
		errs = append(errs, m.IfindexToSlot.Close())
	}
	if m.Metadata != nil {
		errs = append(errs, m.Metadata.Close())
	}
	if m.MgmtSvcFwd != nil {
		errs = append(errs, m.MgmtSvcFwd.Close())
	}
	if m.MgmtSvcRev != nil {
		errs = append(errs, m.MgmtSvcRev.Close())
	}
	return errors.Join(errs...)
}

// PinPathExists checks if the BPF pin directory exists for a switch.
func PinPathExists(switchName string) (bool, error) {
	pinPath := filepath.Join(BPFPath, switchName)
	info, err := os.Stat(pinPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("stat %s: %w", pinPath, err)
	}
	if !info.IsDir() {
		return false, fmt.Errorf("%s is not a directory", pinPath)
	}
	return true, nil
}
