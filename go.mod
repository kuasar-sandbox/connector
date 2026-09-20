module github.com/kuasar-sandbox/connector

go 1.26.1

require (
	github.com/cilium/ebpf v0.20.0
	github.com/insomniacslk/dhcp v0.0.0-20250109001534-8abf58130905
	github.com/spf13/cobra v1.10.0
	github.com/vishvananda/netlink v1.3.1
	github.com/vishvananda/netns v0.0.5
	golang.org/x/sys v0.47.0
)

require (
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/mdlayher/packet v1.1.2 // indirect
	github.com/mdlayher/socket v0.4.1 // indirect
	github.com/pierrec/lz4/v4 v4.1.14 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	github.com/stretchr/testify v1.11.1 // indirect
	github.com/u-root/uio v0.0.0-20230220225925-ffce2a382923 // indirect
	// Keep this transitive version floor; go mod tidy drops it without direct imports.
	golang.org/x/crypto v0.56.0 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
)
