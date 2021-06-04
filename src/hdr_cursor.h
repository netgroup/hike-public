
#ifndef _HDR_CURSOR_H
#define _HDR_CURSOR_H

/* header cursor to keep track of current parsing position within the packet */
struct hdr_cursor {
	struct xdp_md *ctx;

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

static __always_inline void *cur_head(struct hdr_cursor *cur)
{
	return (void *)((long)cur->ctx->data);
}

static __always_inline void *cur_data(struct hdr_cursor *cur)
{
	return cur_head(cur) + cur->dataoff;
}

static __always_inline int cur_set_data(struct hdr_cursor *cur, int off)
{
	if (off < 0 || off > PROTO_OFF_MAX)
		return -EINVAL;

	cur->dataoff = off & PROTO_OFF_MAX;

	return 0;
}

static __always_inline void *cur_tail(struct hdr_cursor *cur)
{
	return (void *)((long)cur->ctx->data_end);
}

static __always_inline void *cur_mac_header(struct hdr_cursor *cur)
{
	return cur_head(cur) + cur->mhoff;
}

static __always_inline void *cur_network_header(struct hdr_cursor *cur)
{
	return cur_head(cur) + cur->nhoff;
}

static __always_inline void *cur_transport_header(struct hdr_cursor *cur)
{
	return cur_head(cur) + cur->thoff;
}

static __always_inline int
__cur_update(struct hdr_cursor *cur, struct xdp_md * ctx)
{
	cur->ctx = ctx;

	return 0;
}

#define cur_touch	__cur_update

static __always_inline void
cur_init(struct hdr_cursor *cur, struct xdp_md * ctx)
{
	__cur_update(cur, ctx);
	cur->dataoff = 0;
	cur_reset_mac_header(cur);
	cur_reset_network_header(cur);
	cur_reset_transport_header(cur);
}

static __always_inline int
__check_proto_offsets(struct hdr_cursor *cur)
{
	if (cur->dataoff < 0 || cur->dataoff > PROTO_OFF_MAX)
		goto error;

	if (cur->mhoff < 0 || cur->mhoff > PROTO_OFF_MAX)
		goto error;

	if (cur->nhoff < 0 || cur->nhoff > PROTO_OFF_MAX)
		goto error;

	if (cur->thoff < 0 || cur->thoff > PROTO_OFF_MAX)
		goto error;

	return 0;

error:
	return -EINVAL;

}

static __always_inline int
cur_update_pointers(struct hdr_cursor *cur, struct xdp_md * ctx)
{
	int rc;

	rc =__cur_update(cur, ctx);
	if (rc < 0)
		return rc;

	return __check_proto_offsets(cur);
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

static __always_inline int
cur_update_pointers_after_head_expand(struct hdr_cursor *cur,
				      struct xdp_md * ctx, int head_off)
{
	int rc;

	rc = __cur_update(cur, ctx);
	if (rc < 0)
		return rc;

	return cur_adjust_proto_offsets(cur, head_off);
}

#define		__may_pull(__ptr, __len, __data_end)			\
			(((void *)(__ptr)) + (__len) <= (__data_end))

#define 	__may_pull_hdr(__hdr, __data_end)			\
			((__hdr) + 1 <= (__data_end))

#define 	__pull(__cur, __len)					\
			((__cur)->dataoff += (__len))

static __always_inline int cur_may_pull(struct hdr_cursor *cur, int len)
{
	void *tail;
	void *data;

	if (cur->dataoff < 0 || cur->dataoff > PROTO_OFF_MAX)
		return 0;

	cur->dataoff &= PROTO_OFF_MAX;
	data = cur_data(cur);
	tail = cur_tail(cur);

	return __may_pull(data, len, tail);
}

static __always_inline void *cur_pull(struct hdr_cursor *cur, int len)
{
	if (!cur_may_pull(cur, len))
		return NULL;

	__pull(cur, len);

	return cur_data(cur);
}

static __always_inline void *
cur_header_pointer(struct hdr_cursor *cur, int off, int len)
{
	void *head = cur_head(cur);
	void *tail = cur_tail(cur);
	int __off = off + len;

	if (__off < 0 || __off > PROTO_OFF_MAX)
		goto error;

	/* to make the verifier happy... */
	len &= PROTO_OFF_MAX;
	off &= PROTO_OFF_MAX;

	/* overflow for the packet */
	if (!__may_pull(head + off, len, tail))
		goto error;

	return head + off;

error:
	return NULL;
}

static __always_inline void *cur_push(struct hdr_cursor *cur, int len)
{
	int off;

	if (len < 0)
		goto error;

	off = (cur->dataoff - len);
	if (off < 0)
		goto error;

	cur->dataoff = off & PROTO_OFF_MAX;
	if (!cur_may_pull(cur, len))
		goto error;

	return cur_data(cur);

error:
	return NULL;
}

#endif
