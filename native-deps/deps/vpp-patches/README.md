# VPP patches

The upstream source version and archive digest are fixed in `../vpp-source.json`.
`make -C native-deps vpp-fetch` verifies the archive, extracts it and imports it
into a local Git repository tagged `vpp-patches-base`, following the same
workflow as the Cloud Hypervisor and Guest kernel dependencies.

The ordered `git format-patch` series preserves the existing Egress changes:

1. Honor AF_PACKET virtio framing when device transmit offloads are disabled.
2. Expose NAT44-ED policy admission, connection ownership and lifecycle hooks.
3. Keep the owned gateway's memory and control endpoints private.
4. Support routed-peer admission and ICMP source selection for Egress interfaces.
5. Retire FIB reassembly state only after pending graph and handoff traffic drains.

The first-party plugins remain in `egress/vpp/plugins` in the Connector source
tree. Only modifications to upstream VPP belong in this patch directory.

## Updating a patch

```sh
make -C native-deps vpp-patches-apply
# Modify native-deps/build/src/vpp and commit the changes in that Git tree.
make -C native-deps vpp-patches-format
make -C native-deps vpp-build
```

Formatting exports all commits after `vpp-patches-base`. It preserves this
README and replaces only the numbered `.patch` files. Standard builds require
the source tree to match the exported patches, including their contents;
uncommitted or unexported work is rejected before publishing build outputs.
`clean` keeps the source tree and download cache so local patch work survives.

To change the upstream version, update the source lock and use a fresh
`VPP_BUILD_SRC`/`VPP_BUILD_OUT`, then rebase the patch series. The archive's
version is preserved in upstream's `src/scripts/.version`; the synthetic import
commit does not replace the upstream commit recorded in the runtime manifest.
