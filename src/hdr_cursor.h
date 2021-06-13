
#ifndef _HDR_CURSOR_H
#define _HDR_CURSOR_H

#define __HDR_CURSOR_BARRIER	0

#ifndef barrier
#define barrier()	__asm__ __volatile__("": : :"memory")
#endif

#if __HDR_CURSOR_BARRIER == 1
#define cur_barrier()	barrier()
#else
#define cur_barrier()
#endif

/* header cursor to keep track of current parsing position within the packet */
struct hdr_cursor {
	int dataoff;
	int mhoff;
	int nhoff;
	int thoff;
};

/* the maximum offset at which a generic protocol is considered to be valid
 * from the beginning (head) of the hdr_cursor.
 */
#define PROTO_OFF_MAX 0xffff

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

static __always_inline unsigned char *
cur_data(struct xdp_md *ctx, struct hdr_cursor *cur)
{
	return xdp_md_head(ctx) + cur->dataoff;
}

static __always_inline int cur_set_data(struct hdr_cursor *cur, int off)
{
	if (off < 0 || off > PROTO_OFF_MAX)
		return -EINVAL;

	cur->dataoff = off & PROTO_OFF_MAX;

	return 0;
}

static __always_inline unsigned char *xdp_md_tail(struct xdp_md *ctx)
{
	return (unsigned char *)((long)ctx->data_end);
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
cur_init(struct xdp_md * ctx, struct hdr_cursor *cur)
{
	cur->dataoff = 0;
	cur_reset_mac_header(cur);
	cur_reset_network_header(cur);
	cur_reset_transport_header(cur);
}

static __always_inline int
__check_proto_offsets(struct hdr_cursor *cur)
{
	int rc = -EINVAL;

	if (cur->dataoff < 0 || cur->dataoff > PROTO_OFF_MAX)
		goto out;

	if (cur->mhoff < 0 || cur->mhoff > PROTO_OFF_MAX)
		goto out;

	if (cur->nhoff < 0 || cur->nhoff > PROTO_OFF_MAX)
		goto out;

	if (cur->thoff < 0 || cur->thoff > PROTO_OFF_MAX)
		goto out;

	rc = 0;

out:
	barrier();

	return rc;
}

static __always_inline int
cur_adjust_proto_offsets(struct hdr_cursor *cur, int off)
{
	cur->dataoff += off;
	cur->mhoff += off;
	cur->nhoff += off;
	cur->thoff += off;

	barrier();

	return __check_proto_offsets(cur);
}

#define		__may_pull(__ptr, __len, __data_end)			\
			(((unsigned char *)(__ptr)) + (__len) <= (__data_end))

#define 	__may_pull_hdr(__hdr, __data_end)			\
			((__hdr) + 1 <= (__data_end))

#define 	__pull(__cur, __len)					\
			((__cur)->dataoff += (__len))

static __always_inline int
cur_may_pull(struct xdp_md *ctx, struct hdr_cursor *cur, int len)
{
	unsigned char *data, *tail;
	int rc = 0;

	if (cur->dataoff < 0 || cur->dataoff > PROTO_OFF_MAX)
		goto out;

	cur->dataoff &= PROTO_OFF_MAX;

	data = cur_data(ctx, cur);
	tail = xdp_md_tail(ctx);

	rc = __may_pull(data, len, tail);

out:
	return rc;
}

static __always_inline unsigned char *
cur_pull(struct xdp_md *ctx, struct hdr_cursor *cur, int len)
{
	unsigned char *ptr = NULL;

	if (!cur_may_pull(ctx, cur, len))
		goto out;

	__pull(cur, len);
	ptr = cur_data(ctx, cur);

out:
	barrier();

	return ptr;
}

static __always_inline unsigned char *
cur_header_pointer(struct xdp_md *ctx, struct hdr_cursor *cur, int off, int len)
{
	unsigned char *head = xdp_md_head(ctx);
	unsigned char *tail = xdp_md_tail(ctx);
	unsigned char *ptr = NULL;
	int __off = off + len;

	if (__off < 0 || __off > PROTO_OFF_MAX)
		goto out;

	/* to make the verifier happy... */
	len &= PROTO_OFF_MAX;
	off &= PROTO_OFF_MAX;

	/* overflow for the packet */
	if (!__may_pull(head + off, len, tail))
		goto out;

	ptr = head + off;

out:
	barrier();

	return ptr;
}

static __always_inline unsigned char *
cur_push(struct xdp_md *ctx, struct hdr_cursor *cur, int len)
{
	unsigned char *ptr = NULL;
	int off;

	if (len < 0)
		goto out;

	off = cur->dataoff - len;
	if (off < 0)
		goto out;

	cur->dataoff = off & PROTO_OFF_MAX;
	if (!cur_may_pull(ctx, cur, len))
		goto out;

	ptr = cur_data(ctx, cur);

out:
	barrier();

	return ptr;
}

#endif
