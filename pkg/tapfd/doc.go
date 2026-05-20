// Package tapfd implements the end-to-end protocol for transferring tap-device
// file descriptors between processes, as used by vswitch-ctl to hand a
// per-port tap fd to a VMM (or any userspace orchestrator).
//
// The package covers the full lifecycle:
//
//   - Wire format: PortMetadata + Marshal/ParsePayload encode/decode the
//     control-line payload that travels alongside each SCM_RIGHTS message.
//   - Open: OpenTap binds a new fd to an already-existing persistent tap
//     device via TUNSETIFF (vswitch-ctl's send side).
//   - Send: SendFd, ConnectUnix, UnixConnFromFd transmit the fd plus
//     metadata over a connected unix socket via SCM_RIGHTS (send side).
//   - Receive: RecvFd, RecvFds extract the fd and parse the metadata in
//     a single recvmsg call (VMM-orchestrator side).
//
// The wire format is a single line of space-separated key=value pairs
// followed by a NUL byte:
//
//	port=1 mac=02:00:00:00:80:01 mtu=1500 ip=169.254.1.1 fd=1\0
//
// Unknown keys are tolerated so receivers built against this version remain
// forward-compatible with future vswitch-ctl releases.
//
// # Example: minimal VMM orchestrator (receive side)
//
//	ln, err := net.Listen("unix", "/run/vm1.sock")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer ln.Close()
//	c, err := ln.Accept()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer c.Close()
//
//	uc := c.(*net.UnixConn)
//	tapFile, meta, err := tapfd.RecvFd(uc)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer tapFile.Close()
//
//	// Configure your VMM's virtio-net using meta.MAC / meta.MTU / meta.InnerIP,
//	// then hand tapFile.Fd() to the VMM's tap-backend (cloud-hypervisor's
//	// --net fd= argument, firecracker's tap-fd plumbing, etc.).
//	fmt.Printf("port=%d mac=%s mtu=%d ip=%s\n",
//	    meta.Port, meta.MAC, meta.MTU, meta.InnerIP)
//
// # Example: socketpair / inherited-fd handshake
//
// When the orchestrator and vswitch-ctl share a parent, the parent can
// socketpair(2) and pass one end to each child via fd inheritance. The
// orchestrator side then reads from the inherited socket exactly as above;
// vswitch-ctl is invoked with TAPFD_SOCKET=fd=N in its environment.
package tapfd
