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

struct opthdr
{
	__u8 kind;
	__u8 len;
	__u8 data;
};

struct hdr_cursor
{
	void *pos;
};

struct options_pack
{
	__u16 mss;
	__u8 ws;
	__u8 sack_permit;
	__u32 sack[4];
	__u32 timeout;
	__u32 echo_timeout;
};

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

static __always_inline bool is_tcp_syn(struct hdr_cursor *h_cur)
{
	struct tcphdr *th = (struct tcphdr *)h_cur->pos;
	return (th->syn == 1 && th->ack == 0);
}

static __always_inline void parse_options(struct hdr_cursor *h_cur,
										  __u8 hdrlen,
										  struct options_pack *op)
{
	struct opthdr *oh = h_cur->pos;

	while (hdrlen > 0)
	{
		h_cur->pos++;
		bpf_trace_printk("opt: %d", oh->kind);

		switch (oh->kind)
		{
		case TCPOPT_EOL:
			return;

		case TCPOPT_NOP:
			hdrlen--;
			continue;

		case TCPOPT_MAXSEG:
			if (oh->len != TCPOLEN_MAXSEG)
				goto parse_error;
			op->mss = oh->data;
			continue;

		case TCPOPT_WINDOW:
			if (oh->len != TCPOLEN_WINDOW)
				goto parse_error;
			op->ws = oh->data;
			continue;

		case TCPOPT_SACK_PERMITTED:
			if (oh->len != TCPOLEN_SACK_PERMITTED)
				goto parse_error;
			// key only option pass as boolean value
			op->mss = 1;
			continue;

		case TCPOPT_SACK:
			/* length variable, so check maximum possible value */
			if (oh->len > 34)
				goto parse_error;
			// TODO: process all pointers
			op->sack[0] = oh->data;

			continue;

		case TCPOPT_TIMESTAMP:
			if (oh->len != TCPOLEN_TIMESTAMP)
				goto parse_error;

			op->timeout = oh->data;
			op->echo_timeout = (oh + sizeof(__u32))->data;
			continue;

		default:
			goto parse_error;

			bpf_trace_printk("len: %d", oh->len);

			for (int i = 0; i < oh->len; i++)
			{
				bpf_trace_printk("%#02x ", oh->data);
			}

			h_cur->pos += oh->len;
			hdrlen -= oh->len;
		}
	}
parse_error:
	bpf_printk("Wrong option %#02x len %#02x", oh->kind, oh->len);
}

#endif /* __PARSING_HELPERS_H */
