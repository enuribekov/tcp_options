#ifndef __OPTIONS_H
#define __OPTIONS_H

struct opthdr
{
    __u8 kind;
    __u8 len;
    __u8 *data;
};

struct sack
{
    __u32 begin;
    __u32 end;
};

struct timeout
{
    __u32 curr;
    __u32 echo;
};

struct options_pack
{
    __u16 mss;
    __u8 ws;
    __u8 sack_permit;
    struct sack sack[4];
    struct timeout timeout;
} options_pack;




/*
 *      TCP option
 */

#define TCPOPT_NOP              1       /* Padding */
#define TCPOPT_EOL              0       /* End of options */
#define TCPOPT_MSS              2       /* Segment size negotiating */
#define TCPOPT_WINDOW           3       /* Window scaling */
#define TCPOPT_SACK_PERM        4       /* SACK Permitted */
#define TCPOPT_SACK             5       /* SACK Block */
#define TCPOPT_TIMESTAMP        8       /* Better RTT estimations/PAWS */
#define TCPOPT_MD5SIG           19      /* MD5 Signature (RFC2385) */
#define TCPOPT_AO               29      /* Authentication Option (RFC5925) */
#define TCPOPT_MPTCP            30      /* Multipath TCP (RFC6824) */
#define TCPOPT_FASTOPEN         34      /* Fast open (RFC7413) */
#define TCPOPT_EXP              254     /* Experimental */
/*
 *     TCP option lengths
 */

#define TCPOLEN_MSS            4
#define TCPOLEN_WINDOW         3
#define TCPOLEN_SACK_PERM      2
#define TCPOLEN_TIMESTAMP      10
#define TCPOLEN_MD5SIG         18
#define TCPOLEN_FASTOPEN_BASE  2
#define TCPOLEN_EXP_FASTOPEN_BASE  4
#define TCPOLEN_EXP_SMC_BASE   6

#endif // __OPTIONS_H