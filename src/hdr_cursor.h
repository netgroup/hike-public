
#ifndef _HDR_CURSOR_H
#define _HDR_CURSOR_H

#include "compiler.h"

/* header cursor to keep track of current parsing position within the packet */
struct hdr_cursor {
	int dataoff;
	int mhoff;
	int nhoff;
	int thoff;
};

/* the maximum offset at which a generic protocol is considered to be valid
 * from the beginning (head) of the hdr_cursor.
 *
 * XXX: SUPPORTED UP TO 16K OFFSET
 */
#define PROTO_OFF_MAX 0x3fff

static __always_inline void cur_reset_mac_header(struct hdr_cursor *cur)
{
	cur->mhoff = cur->dataoff;
}

static __always_inline void cur_reset_network_header(struct hdr_cursor *cur)
{
	cur->nhoff = cur->dataoff;
}

static __always_inline void cur_reset_transport_header(struct hdr_cursor *cur)
{
	cur->thoff = cur->dataoff;
}

static __always_inline unsigned char *xdp_md_head(struct xdp_md *ctx)
{
	return (unsigned char *)((long)ctx->data);
}

static __always_inline unsigned char *xdp_md_tail(struct xdp_md *ctx)
{
	return (unsigned char *)((long)ctx->data_end);
}

static __always_inline unsigned char *
cur_data(struct xdp_md *ctx, struct hdr_cursor *cur)
{
	return xdp_md_head(ctx) + cur->dataoff;
}

static __always_inline unsigned char *
cur_mac_header(struct xdp_md *ctx, struct hdr_cursor *cur)
{
	return xdp_md_head(ctx) + cur->mhoff;
}

static __always_inline unsigned char *
cur_network_header(struct xdp_md *ctx, struct hdr_cursor *cur)
{
	return xdp_md_head(ctx) + cur->nhoff;
}

static __always_inline unsigned char *
cur_transport_header(struct xdp_md *ctx, struct hdr_cursor *cur)
{
	return xdp_md_head(ctx) + cur->thoff;
}

static __always_inline void
cur_init(struct hdr_cursor *cur)
{
	cur->dataoff = 0;
	cur_reset_mac_header(cur);
	cur_reset_network_header(cur);
	cur_reset_transport_header(cur);
}

static __always_inline int
__check_proto_offsets(struct hdr_cursor *cur)
{
	if (cur->dataoff < 0 || cur->dataoff > PROTO_OFF_MAX)
		return -EINVAL;

	if (cur->mhoff < 0 || cur->mhoff > PROTO_OFF_MAX)
		return -EINVAL;

	if (cur->nhoff < 0 || cur->nhoff > PROTO_OFF_MAX)
		return -EINVAL;

	if (cur->thoff < 0 || cur->thoff > PROTO_OFF_MAX)
		return -EINVAL;

	return 0;
}

static __always_inline int
cur_adjust_proto_offsets(struct hdr_cursor *cur, int off)
{
	cur->dataoff += off;
	cur->mhoff += off;
	cur->nhoff += off;
	cur->thoff += off;

	return __check_proto_offsets(cur);
}

#define		__may_pull(__ptr, __len, __data_end)			\
			(((unsigned char *)(__ptr)) + (__len) <= (__data_end))

#define 	__may_pull_hdr(__hdr, __data_end)			\
			((__hdr) + 1 <= (__data_end))

#define 	__pull(__cur, __len)					\
			((__cur)->dataoff += (__len))

static __always_inline int
cur_may_pull(struct xdp_md *ctx, struct hdr_cursor *cur, unsigned int len)
{
	unsigned char *data, *tail;

	cur->dataoff &= PROTO_OFF_MAX;
	len &= PROTO_OFF_MAX;

	data = cur_data(ctx, cur);
	tail = xdp_md_tail(ctx);

	return __may_pull(data, len, tail);
}

static __always_inline unsigned char *
cur_pull(struct xdp_md *ctx, struct hdr_cursor *cur, unsigned int len)
{
	if (!cur_may_pull(ctx, cur, len))
		return NULL;

	__pull(cur, len);
	return cur_data(ctx, cur);
}

static __always_inline unsigned char *
cur_header_pointer(struct xdp_md *ctx, struct hdr_cursor *cur,
		   unsigned int off, unsigned int len)
{
	unsigned char *head = xdp_md_head(ctx);
	unsigned char *tail = xdp_md_tail(ctx);
	unsigned int __off = off + len;

	if (__off > PROTO_OFF_MAX)
		return NULL;

	len &= PROTO_OFF_MAX;
	off &= PROTO_OFF_MAX;
	/* to make the verifier happy... */
	barrier_data(len);
	barrier_data(off);

	/* overflow for the packet */
	if (!__may_pull(head + off, len, tail))
		return NULL;

	return head + off;
}

#endif
