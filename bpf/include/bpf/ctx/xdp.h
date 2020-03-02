/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2020 Authors of Cilium */

#ifndef __BPF_CTX_XDP_H_
#define __BPF_CTX_XDP_H_

#include <linux/if_ether.h>

#define __ctx_buff			xdp_md
#define __ctx_is			__ctx_xdp

#include "common.h"
#include "../helpers_xdp.h"

#define CTX_ACT_OK			XDP_PASS
#define CTX_ACT_DROP			XDP_DROP
#define CTX_ACT_TX			XDP_TX	/* hairpin only */

#define META_PIVOT			field_sizeof(struct __sk_buff, cb)

static __always_inline __maybe_unused __overloadable int
xdp_load_bytes(struct xdp_md *ctx, __u32 off, void *to, const __u32 len)
{
	void *data_end = ctx_data_end(ctx);
	void *data = ctx_data(ctx) + off;

	if (ctx_no_room(data + len, data_end))
		return -EFAULT;

	__builtin_memcpy(to, data, len);
	return 0;
}

static __always_inline __maybe_unused __overloadable int
xdp_store_bytes(struct xdp_md *ctx, __u32 off, const void *from,
		const __u32 len, __u32 flags)
{
	void *data_end = ctx_data_end(ctx);
	void *data = ctx_data(ctx) + off;

	if (ctx_no_room(data + len, data_end))
		return -EFAULT;

	__builtin_memcpy(data, from, len);
	return 0;
}

#define ctx_load_bytes			xdp_load_bytes
#define ctx_store_bytes			xdp_store_bytes

/* Fyi, remapping to stubs helps to assert that the code is not in
 * use since it otherwise triggers a verifier error.
 */
#define ctx_adjust_room			xdp_adjust_room__stub	/* TODO */

#define ctx_change_type			xdp_change_type__stub
#define ctx_change_proto		xdp_change_proto__stub
#define ctx_change_tail			xdp_change_tail__stub

#define ctx_pull_data(ctx, ...)		do { /* Already linear. */ } while (0)

#define ctx_get_tunnel_key		xdp_get_tunnel_key__stub
#define ctx_set_tunnel_key		xdp_set_tunnel_key__stub

#define ctx_event_output		xdp_event_output

#define ctx_adjust_meta			xdp_adjust_meta

#define get_hash_recalc(ctx)		({ 0; })

/* Checksum pieces from Linux kernel. */
static inline __sum16 csum_fold(__wsum csum)
{
	__u32 sum = (__u32)csum;
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return (__sum16)~sum;
}

static inline __wsum csum_unfold(__sum16 n)
{
	return (__wsum)n;
}

static inline __wsum csum_add(__wsum csum, __wsum addend)
{
	__u32 res = (__u32)csum;
	res += (__u32)addend;
	return (__wsum)(res + (res < (__u32)addend));
}

static __always_inline __maybe_unused void
__csum_replace_by_diff(__sum16 *sum, __wsum diff)
{
	*sum = csum_fold(csum_add(diff, ~csum_unfold(*sum)));
}

static __always_inline __maybe_unused __overloadable int
l3_csum_replace(struct xdp_md *ctx, __u32 off, const __u32 from, __u32 to,
		__u32 flags)
{
	void *data_end = ctx_data_end(ctx);
	__sum16 *data = (void *)(ctx_data(ctx) + off);

	if (ctx_no_room(data + 1, data_end))
		return -EFAULT;
	if (unlikely(from != 0 || flags != 0))
		return -EINVAL;

	__csum_replace_by_diff(data, to);
	return 0;
}

#define CSUM_MANGLED_0		((__sum16)0xffff)

static __always_inline __maybe_unused __overloadable int
l4_csum_replace(struct xdp_md *ctx, __u32 off, __u32 from, __u32 to,
		__u32 flags)
{
	bool is_mmzero = flags & BPF_F_MARK_MANGLED_0;
	void *data_end = ctx_data_end(ctx);
	__sum16 *data = (void *)(ctx_data(ctx) + off);

	if (ctx_no_room(data + 1, data_end))
		return -EFAULT;
	if (unlikely(flags & ~(BPF_F_MARK_MANGLED_0 | BPF_F_PSEUDO_HDR)))
		return -EINVAL;
	if (unlikely(from != 0))
		return -EINVAL;

	if (is_mmzero && !*data)
		return 0;
	__csum_replace_by_diff(data, to);
	if (is_mmzero && !*data)
		*data = CSUM_MANGLED_0;
	return 0;
}

#define redirect			redirect__stub

static __always_inline __maybe_unused __overloadable int
ctx_redirect(struct xdp_md *ctx, int ifindex, const __u32 flags)
{
	if (unlikely(flags))
		return -ENOTSUPP;
	if (ifindex != ctx->ingress_ifindex)
		return -ENOTSUPP;
	return XDP_TX;
}

static __always_inline __maybe_unused __overloadable __u32
ctx_full_len(struct xdp_md *ctx)
{
	/* No non-linear section in XDP. */
	return ctx_data_end(ctx) - ctx_data(ctx);
}

static __always_inline __maybe_unused __overloadable void
ctx_store_meta(struct xdp_md *ctx, const __u32 off, __u32 datum)
{
	__u32 *data_meta = ctx_data_meta(ctx);
	void *data = ctx_data(ctx);

	if (!ctx_no_room(data_meta + off + 1, data))
		data_meta[off] = datum;
	else {
		build_bug_on((off + 1) * sizeof(__u32) > META_PIVOT);
	}
}

static __always_inline __maybe_unused __overloadable __u32
ctx_load_meta(struct xdp_md *ctx, const __u32 off)
{
	__u32 *data_meta = ctx_data_meta(ctx);
	void *data = ctx_data(ctx);

	if (!ctx_no_room(data_meta + off + 1, data))
		return data_meta[off];
	else {
		build_bug_on((off + 1) * sizeof(__u32) > META_PIVOT);
		return 0;
	}
}

static __always_inline __maybe_unused __overloadable __u32
ctx_get_protocol(struct xdp_md *ctx)
{
	void *data_end = ctx_data_end(ctx);
	struct ethhdr *eth = ctx_data(ctx);

	if (ctx_no_room(eth + 1, data_end))
		return 0;

	return eth->h_proto;
}

static __always_inline __maybe_unused __overloadable __u32
ctx_get_ifindex(struct xdp_md *ctx)
{
	return ctx->ingress_ifindex;
}

#endif /* __BPF_CTX_XDP_H_ */
