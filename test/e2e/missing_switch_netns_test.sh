#!/usr/bin/env bash
# Real regression: missing switch netns must not turn stale indices into host deletes.
set -euo pipefail
if [ "${1:-}" != --isolated ]; then
    : "${BIN:?BIN must point to the assembled platform binaries}"
    binary="$(realpath "$BIN/connector-ctl")"
    [ -x "$binary" ]
    exec unshare --mount --propagation private --net --pid --fork --mount-proc \
        bash "$0" --isolated "$binary"
fi
binary=${2:?connector binary}
mount -t bpf bpf /sys/fs/bpf
mkdir -p /run/netns
mount -t tmpfs -o mode=755 tmpfs /run/netns
ip link set lo up
# Private mounts and namespaces disappear with this test, including on failure.
ip netns add gone-switch
"$binary" vswitch start gone --netns=gone-switch --ports=2 --mode=tap \
    --mac-addr=02:00:00:00:00:01 --floating-ip-base=100.100.96.0
index=$("$binary" vswitch show slots gone | python3 -c \
    'import json,sys; v=json.load(sys.stdin)[0]["ifindex"]; assert v>1; print(v)')
ip netns del gone-switch
ip netns add unrelated-proxy
ip link add e2eph0 index "$index" type veth peer name e2epn0
ip link set e2epn0 netns unrelated-proxy
ip -n unrelated-proxy addr add 172.31.254.2/30 dev e2epn0
ip -n unrelated-proxy link set lo up
ip -n unrelated-proxy link set e2epn0 up
"$binary" vswitch stop gone --force
# Checking only exit status would pass on the broken implementation.
ip -j link show e2eph0 | python3 -c \
    'import json,sys; assert json.load(sys.stdin)[0]["ifindex"] == int(sys.argv[1])' "$index"
ip -n unrelated-proxy -j addr show dev e2epn0 | python3 -c \
    'import json,sys; assert any(a.get("local")=="172.31.254.2" for d in json.load(sys.stdin) for a in d["addr_info"])'
ip netns exec unrelated-proxy python3 -c \
    'import socket; s=socket.socket(); s.bind(("172.31.254.2",0)); s.listen(); s.close()'
[ ! -e /sys/fs/bpf/gone ]
echo 'PASS: stale switch cleanup retained caller veth, peer and MMDS bind address; pins removed'
