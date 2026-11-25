/* SPDX-License-Identifier: Apache-2.0 */
/* Connector's bounded policy adapter for the pinned native NAT44-ED runtime. */
#ifndef included_nat44_ed_policy_h
#define included_nat44_ed_policy_h
#include <vnet/ip/ip.h>
#define NAT44_ED_POLICY_NONE (~(u64)0)
typedef struct
{
  ip4_address_t backend_addr;
  u16 backend_port;   /* network byte order */
  u32 tx_fib_index;   /* Actual egress routing FIB. */
  u32 return_key_fib; /* Actual outside RX FIB used by the native hash. */
  const ip4_address_t *addresses;
  u32 address_count;
  u64 cookie;
  u64 path_signature;
} nat44_ed_policy_decision_t;
typedef struct
{
  int (*managed) (u32 fib_index);
  int (*prepare) (u32 fib_index, u32 thread_index, u8 proto, ip4_address_t local, u16 local_port,
                  ip4_address_t remote, u16 remote_port, nat44_ed_policy_decision_t *decision);
  int (*reserve) (u64 cookie, u32 thread_index);
  void (*commit) (u64 cookie);
  void (*release) (u64 cookie, u8 committed);
  /* >0: unique selected path MTU, 0: unhandled, -1: no unique usable path. */
  int (*path_mtu) (u64 cookie, u64 expected_path, u32 inside_fib, u32 route_fib,
                   ip4_address_t translated_dst, ip4_address_t forward_dst, u8 out2in);
} nat44_ed_policy_hooks_t;
typedef struct
{
  u64 cookie, path_signature;
  u32 thread_index, native_index, inside_fib, outside_fib, route_fib;
  ip4_address_t local, original_remote, backend, snat;
  u16 local_port, original_remote_port, backend_port, snat_port;
  u8 proto;
} nat44_ed_policy_flow_t;
typedef int (*nat44_ed_policy_visit_t) (const nat44_ed_policy_flow_t *, void *);
extern nat44_ed_policy_hooks_t nat44_ed_policy_hooks;
int nat44_ed_policy_register (const nat44_ed_policy_hooks_t *);
/* Caller holds the VPP worker barrier. Return nonzero from visit to delete. */
u32 nat44_ed_policy_walk (nat44_ed_policy_visit_t visit, void *opaque);
#endif
