#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "parsing_helpers.h"

SEC("xdp")
int xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth;
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;
	struct tcphdr *tcphdr;
	struct options_pack op;

	__u32 action = XDP_PASS;

	struct hdr_cursor h_cur;
	int eth_type;
	int ip_type;
	int tcp_hdr_len;
	int syn_flag;
	h_cur.pos = data;

	eth_type = parse_ethhdr(&h_cur, data_end, &eth);
	switch (eth_type)
	{
	case ETH_P_IP:
		ip_type = parse_iphdr(&h_cur, data_end, &iphdr);
		break
;
	case ETH_P_IPV6:
		ip_type = parse_ip6hdr(&h_cur, data_end, &ipv6hdr);
		break;
	default:
		goto out;
	}

	if (ip_type != IPPROTO_TCP)
		goto out;

	tcp_hdr_len = validate_tcphdr(&h_cur, data_end, &tcphdr);



	//if ((tcp_hdr_len < 5) || (tcp_hdr_len > 15))
	//	return -1;


	if (!is_tcp_syn(&h_cur))
		goto out;

	parse_options(&h_cur, tcp_hdr_len, &op);
	
	//bpf_map_update_elem(&option_map, &(iphdr->saddr), &op, BPF_ANY);

out:
	return 0; // placeholder
}

char _license[] SEC("license") = "GPL";
