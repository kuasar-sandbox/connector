// tapfd_receiver listens on a unix socket and prints the tap fd + metadata
// (and the optional netns fd) it receives from vswitch-ctl. Pair it with:
//
//	TAPFD_SOCKET=/tmp/recv.sock vswitch-ctl open-port <sw> --port=N
//
// To also receive the tap's netns fd, add TAPFD_WANT_NETNS=1 to that command.
//
// Build: go build ./examples/tapfd_receiver
// Run:   ./tapfd_receiver /tmp/recv.sock
package main

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/kuasar-sandbox/sandbox-vswitch/pkg/tapfd"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <socket-path>\n", os.Args[0])
		os.Exit(2)
	}
	path := os.Args[1]
	_ = os.Remove(path)

	ln, err := net.Listen("unix", path)
	if err != nil {
		log.Fatalf("listen %s: %v", path, err)
	}
	defer func() {
		ln.Close()
		os.Remove(path)
	}()
	fmt.Fprintf(os.Stderr, "listening on %s (waiting for vswitch-ctl)\n", path)

	c, err := ln.Accept()
	if err != nil {
		log.Fatalf("accept: %v", err)
	}
	defer c.Close()

	uc := c.(*net.UnixConn)
	// RecvFdsWithNetns also surfaces the optional netns fd the provider sends
	// when driven with TAPFD_WANT_NETNS=1; netnsFile is nil otherwise.
	tapFiles, netnsFile, meta, err := tapfd.RecvFdsWithNetns(uc)
	if err != nil {
		log.Fatalf("RecvFdsWithNetns: %v", err)
	}
	defer func() {
		for _, f := range tapFiles {
			f.Close()
		}
		if netnsFile != nil {
			netnsFile.Close()
		}
	}()

	tapFD := int64(-1)
	if len(tapFiles) > 0 {
		tapFD = int64(tapFiles[0].Fd())
	}
	netnsFD := int64(-1)
	if netnsFile != nil {
		netnsFD = int64(netnsFile.Fd())
	}
	fmt.Printf("port=%d mac=%s mtu=%d ip=%s fd_count=%d tap_fd=%d netns_fd=%d\n",
		meta.Port, meta.MAC, meta.MTU, meta.InnerIP, meta.FDCount, tapFD, netnsFD)
}
