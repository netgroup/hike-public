
#define UDP_DPORT 862

/* XXX: consider to disable debug information during performance testing */
#define HIKE_PRINT_LEVEL HIKE_PRINT_LEVEL_DEBUG
#define HIKE_DEBUG 1

#include "ip6_udport_classifier.h"

IP6_UDPORT_CLS()
{
	int rc;

	rc = process_packet(ctx, UDP_DPORT);
	if (unlikely(rc)) {
		hike_pr_err("packet is discarded due an error");
		return XDP_ABORTED;
	}

	return XDP_PASS;
}
char LICENSE[] SEC("license") = "Dual BSD/GPL";
