#ifndef __PARSING_HELPERS_H
#define __PARSING_HELPERS_H

#include <linux/in.h>
#include <stddef.h>
#include <stdbool.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <netinet/tcp.h>

#include "options.h"

/*
struct opthdr
{
	__u8 kind;
	__u8 len;
	__u8 data;
};
*/

struct hdr_cursor
{
	void *pos;
};
/*
struct options_pack
{
	__u16 mss;
	__u8 ws;
	__u8 sack_permit;
	__u32 sack[4];
	__u32 timeout;
	__u32 echo_timeout;
};
*/

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct options_pack);
	__uint(max_entries, 4096);
} option_map SEC(".maps");

static __always_inline int parse_ethhdr(struct hdr_cursor *h_cur,
										void *data_end,
										struct ethhdr **ethhdr)
{
	struct ethhdr *eth = h_cur->pos;
	int hdrsize = sizeof(*eth);

	if (h_cur->pos + hdrsize > data_end)
		return -1;

	h_cur->pos += hdrsize;
	*ethhdr = eth;

	return bpf_htons(eth->h_proto);
}
static __always_inline int parse_iphdr(struct hdr_cursor *h_cur,
									   void *data_end,
									   struct iphdr **iphdr)
{
	int hdrsize;
	struct iphdr *iph = h_cur->pos;

	if ((void *)iph + 1 > data_end)
		return -1;

	hdrsize = iph->ihl * 4;
	if (hdrsize < sizeof(*iph))
		return -1;

	if (h_cur->pos + hdrsize > data_end)
		return -1;

	h_cur->pos += hdrsize;
	*iphdr = iph;

	return iph->protocol;
}

static __always_inline int parse_ip6hdr(struct hdr_cursor *h_cur,
										void *data_end,
										struct ipv6hdr **ip6hdr)
{
	struct ipv6hdr *ip6h = h_cur->pos;

	if ((void *)ip6h + 1 > data_end)
		return -1;

	h_cur->pos = (void *)ip6h + 1;
	*ip6hdr = ip6h;

	return ip6h->nexthdr;
}

#if 1
static __always_inline __u8 validate_tcphdr(struct hdr_cursor *h_cur,
											void *data_end,
											struct tcphdr **tcphdr)
{
	__u8 hdrlen;
	struct tcphdr *th = h_cur->pos;

	if ((void *)th + 1 > data_end)
		return -1;

	hdrlen = th->doff * 4;

	if (hdrlen < sizeof(struct tcphdr))
		return -1;

	if (h_cur->pos + hdrlen > data_end)
		return -1;

	return hdrlen;
}
#endif

#if 1
static __always_inline bool is_tcp_syn(struct hdr_cursor *h_cur)
{
	struct tcphdr *th = (struct tcphdr *)h_cur->pos;
	return (th->syn == 1 && th->ack == 0);
}
#endif

static __always_inline int parse_options(struct hdr_cursor *h_cur,
										 __u8 hdrlen,
										 struct options_pack *op)
{
	struct opthdr *oh = h_cur->pos;

	__u8 *optstart = (__u8 *)oh;
	__u8 optlen = hdrlen - sizeof(struct tcphdr);
	__u8 *optend = optstart + optlen;

#pragma unroll
	for (__u8 *optpos = optstart; optpos < optend;)
	{
		switch (oh->kind)
		{
		case TCPOPT_EOL:
			return 0;

		case TCPOPT_NOP:
			optpos++;
			break;

		case TCPOPT_MAXSEG:
			if (oh->len != TCPOLEN_MAXSEG)
				return -1;
			op->mss = *(__u16 *)oh->data;
			optpos += TCPOLEN_MAXSEG;
			break;

		case TCPOPT_WINDOW:
			if (oh->len != TCPOLEN_WINDOW)
				return -1;
			op->ws = *(oh->data);
			optpos += TCPOLEN_WINDOW;
			break;

		case TCPOPT_SACK_PERMITTED:
			if (oh->len != TCPOLEN_SACK_PERMITTED)
				return -1;
			/*
			 * Key only option pass as boolean value
			 */
			op->mss = 1;
			optpos += TCPOLEN_SACK_PERMITTED;
			break;

		case TCPOPT_SACK:
			/*
			 * Length is variable, so check if it is a multiple of record size
			 */
			if ((oh->len - 2) % 4)
				return -1;
			int sackcnt = (oh->len - 2) / 4;

#pragma unroll
			for (__u8 sc = 0; sc < sackcnt; sc++)
			{
				op->sack[sc].begin = *(__u32 *)optpos;
				optpos += sizeof(struct sack);
			}
			break;

		case TCPOPT_TIMESTAMP:
			if (oh->len != TCPOLEN_TIMESTAMP)
				return -1;

			op->timeout.curr = *(__u32 *)oh->data;
			op->timeout.echo = *(__u32 *)(oh->data + sizeof(__u32));
			optpos += TCPOLEN_TIMESTAMP;
			break;

		default:
			return -1;
		}
	}
	/* We should not get here*/
	return -1;
}

#endif /* __PARSING_HELPERS_H */
