//go:build integration

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/kuasar-sandbox/connector/pkg/netns"
	"github.com/kuasar-sandbox/connector/pkg/tapfd"
	"github.com/kuasar-sandbox/connector/pkg/vswitch"
	"golang.org/x/sys/unix"
)

// A real persistent TAP and SCM_RIGHTS descriptor survive final configuration.
// All network devices live in a uniquely named test namespace; no host route is changed.
func TestTapFDDeferredRealDescriptorSurvivesPortUp(t *testing.T) {
	if os.Geteuid() != 0 {
		if os.Getenv("REQUIRE_CONNECTOR_STATS") == "1" {
			t.Fatal("root required")
		}
		t.Skip("root/TAP/BPF required")
	}

	// Public Start/Provision create the real BPF/TC/TAP resources in an isolated
	// network namespace. Never add routes or addresses to the host namespace.
	name := fmt.Sprintf("i%06x", os.Getpid())
	if out, err := exec.Command("ip", "netns", "add", name).CombinedOutput(); err != nil {
		t.Fatalf("create netns: %v %s", err, out)
	}
	defer exec.Command("ip", "netns", "del", name).Run()
	cfg := &vswitch.Config{Name: name, SwitchNetNS: name, NumPorts: 1, DefaultMode: vswitch.PortKindTap,
		MACAddr: net.HardwareAddr{2, 0, 0, 0, 0, 1}, FloatingIPBase: net.ParseIP("198.18.0.1"), GenerationBits: 4, MTU: 1500}
	if _, err := vswitch.Start(cfg); err != nil {
		t.Fatal(err)
	}
	defer vswitch.Stop(name, vswitch.StopOptions{Force: true})
	ns, err := netns.GetByName(name)
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	sw, err := vswitch.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer sw.Close()
	exchange := func(line string) string {
		server, client := unixSocketPair(t)
		defer client.Close()
		done := make(chan struct{})
		go func() { defer close(done); handleTapFDConn(server, name, sw, ns) }()
		if _, err := client.Write([]byte(line + "\n")); err != nil {
			t.Fatal(err)
		}
		response := readAllString(t, client)
		<-done
		return response
	}
	response := exchange("TAPFD/1 PREPARE VSWITCH=" + name + " INNER_IP=10.0.0.1 GENERATION=3 ADMIN_DOWN=1")
	if !strings.Contains(response, "OK port=1") || !strings.Contains(response, "admin_down=1") {
		t.Fatal(response)
	}
	server, client := unixSocketPair(t)
	defer client.Close()
	done := make(chan struct{})
	go func() { defer close(done); handleTapFDConn(server, name, sw, ns) }()
	if _, err := client.Write([]byte("TAPFD/1 OPEN VSWITCH=" + name + " PORT=1\n")); err != nil {
		t.Fatal(err)
	}
	fds, nsfd, meta, err := tapfd.RecvFdsWithNetns(client)
	<-done
	if err != nil {
		t.Fatal(err)
	}
	for _, fd := range fds {
		defer fd.Close()
	}
	if nsfd != nil {
		defer nsfd.Close()
	}
	if len(fds) != 1 || meta.InnerIP != "10.0.0.1" || sw.MmapSlots().GetSlot(0).Flags != 0 {
		t.Fatal("down FD handoff", meta)
	}

	headerSize, err := unix.IoctlGetInt(int(fds[0].Fd()), unix.TUNGETVNETHDRSZ)
	if err != nil {
		t.Fatal(err)
	}
	guestMAC, err := net.ParseMAC(meta.MAC)
	if err != nil {
		t.Fatal(err)
	}
	arpFrame := func(source string) []byte {
		packet := make([]byte, headerSize+60)
		frame := packet[headerSize:]
		for i := 0; i < 6; i++ {
			frame[i] = 0xff
		}
		copy(frame[6:12], guestMAC)
		binary.BigEndian.PutUint16(frame[12:14], 0x0806)
		binary.BigEndian.PutUint16(frame[14:16], 1)
		binary.BigEndian.PutUint16(frame[16:18], 0x0800)
		frame[18] = 6
		frame[19] = 4
		binary.BigEndian.PutUint16(frame[20:22], 1)
		copy(frame[22:28], guestMAC)
		copy(frame[28:32], net.ParseIP(source).To4())
		copy(frame[38:42], net.ParseIP("169.254.169.254").To4())
		return packet
	}
	expectARP := func(source string, want bool) {
		t.Helper()
		if _, err := fds[0].Write(arpFrame(source)); err != nil {
			t.Fatal(err)
		}
		until := time.Now().Add(150 * time.Millisecond)
		if want {
			until = time.Now().Add(time.Second)
		}
		for time.Now().Before(until) {
			poll := []unix.PollFd{{Fd: int32(fds[0].Fd()), Events: unix.POLLIN}}
			n, err := unix.Poll(poll, int(time.Until(until).Milliseconds())+1)
			if err == unix.EINTR {
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			if n == 0 {
				break
			}
			buffer := make([]byte, 2048)
			n, err = fds[0].Read(buffer)
			if err != nil {
				t.Fatal(err)
			}
			if n < headerSize+42 {
				continue
			}
			frame := buffer[headerSize:n]
			if binary.BigEndian.Uint16(frame[12:14]) == 0x0806 && binary.BigEndian.Uint16(frame[20:22]) == 2 && net.IP(frame[38:42]).Equal(net.ParseIP(source)) {
				if !want {
					t.Fatal("down TAP leaked an ARP proxy reply")
				}
				return
			}
		}
		if want {
			t.Fatal("original TAP descriptor did not receive ARP reply after port-up")
		}
	}
	expectARP("10.0.0.1", false)
	descriptor := fds[0].Fd()
	before := *sw.MmapSlots().GetSlot(0)
	response = exchange("TAPFD/1 SET_PORT_UP VSWITCH=" + name + " PORT=1 INNER_IP=10.0.0.2")
	if !strings.Contains(response, "OK port=1 admin_down=0") {
		t.Fatal(response)
	}
	if _, err := fds[0].Stat(); err != nil {
		t.Fatal("delivered descriptor was invalidated", err)
	}
	after := sw.MmapSlots().GetSlot(0)
	if fds[0].Fd() != descriptor || after.Ifindex != before.Ifindex || after.Generation != 3 || after.Flags != vswitch.PortFUp || vswitch.Uint32ToIP(after.InnerIp).String() != "10.0.0.2" {
		t.Fatal("resource identity changed", after)
	}
	expectARP("10.0.0.2", true)
	// Already delivered metadata is a snapshot, not a guest configuration update.
	if meta.InnerIP != "10.0.0.1" {
		t.Fatal("old metadata unexpectedly changed")
	}
	response = exchange("TAPFD/1 RELEASE VSWITCH=" + name + " PORT=1")
	if !strings.Contains(response, "OK port=1 released=1") {
		t.Fatal(response)
	}
	t.Log("PREPARE down -> real TAP FD handoff -> SET_PORT_UP A-to-B -> RELEASE passed with the original descriptor")
}
