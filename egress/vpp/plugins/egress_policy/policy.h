/* SPDX-License-Identifier: Apache-2.0 */
#ifndef included_connector_egress_policy_h
#define included_connector_egress_policy_h

#include <vlib/vlib.h>

int egress_policy_vtep_conflict (u32 address);
int egress_policy_has_area (u32 area);
int egress_policy_context_bind (u32 fib, u32 table, u32 area, u32 peer, u32 local, u32 slot);
u32 egress_policy_context_live (u32 fib);
u32 egress_policy_access_count (void);
int egress_policy_context_retire (u32 fib);
void egress_policy_context_revoke (u32 fib);
u32 egress_policy_context_flush (u32 fib);
u32 egress_policy_flush_revoked (void);
clib_error_t *egress_policy_batch_validate (void);
u32 egress_policy_batch_publish (void);

#endif
