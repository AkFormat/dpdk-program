/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/time.h>
#include <unistd.h>

#include <rte_arp.h>
#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>


#define   __USE_XOPEN2K 1

#define   D_MAX_PACKET_SIZE   2048
#define   D_RING_SIZE         64
#define   D_BURST_SIZE        4096

#define   D_DEFAULT_FD_NUM	  3
#define   D_MAX_FD_COUNT	  16384

#define   D_NUM_MBUFS               (4096-1)
#define   D_UDP_BUFFER_SIZE	 1024

#define   D_TCP_OPTION_LENGTH	20
#define   D_TCP_INITIAL_WINDOW  ntohs(56335)
#define   D_TCP_MAX_SEQ		    0xffffffff
#define   D_TCP_BUFFER_SIZE  1440

#define   D_MAX_WORK_NODE 4

unsigned char g_aucDefaultArpMac[RTE_ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

unsigned char clientMAC[RTE_ETHER_ADDR_LEN] = {0x6C,0xFE,0x54,0x40,0x52,0xA8};

static struct rte_ether_addr work_node_MAC[D_MAX_WORK_NODE] = 
{
    {0x00,0x0C,0x29,0xD5,0x46,0xCF},
    {0x00,0x0C,0x29,0xD5,0x46,0xCF},
    {0x00,0x0C,0x29,0xD5,0x46,0xCF},
    {0x00,0x0C,0x29,0xD5,0x46,0xCF}
};

#define LL_ADD(item, list) do			 \
{										 \
	item->prev = NULL;					 \
	item->next = list;					 \
	if (list != NULL) list->prev = item; \
	list = item;						 \
} while(0)

#define LL_REMOVE(item, list) do 							\
{															\
	if (item->prev != NULL) item->prev->next = item->next;	\
	if (item->next != NULL) item->next->prev = item->prev;	\
	if (list == item) list = item->next;					\
	item->prev = item->next = NULL;							\
} while(0)

unsigned char g_ucFdTable[D_MAX_FD_COUNT] = {0};
unsigned char finish_v4_fd[D_MAX_FD_COUNT] = {0};
unsigned char finish_v6_fd[D_MAX_FD_COUNT] = {0};

char *work_node[] = {"echo0","echo1","echo2","echo3"};

char *local_ipv6 = "fe80::4ab0:2dff:fe8f:e1c7";

char *work_node_ipv6[D_MAX_WORK_NODE] =
{
    "2001:0db8:85a3:0000:0000:8a2e:0370:7331",
    "2001:0db8:85a3:0000:0000:8a2e:0370:7331",
    "2001:0db8:85a3:0000:0000:8a2e:0370:7331",
    "2001:0db8:85a3:0000:0000:8a2e:0370:7331"
};

typedef enum _ENUM_TCP_STATUS 
{
	TCP_STATUS_CLOSED = 0,
	TCP_STATUS_LISTEN,
	TCP_STATUS_SYN_RCVD,
	TCP_STATUS_SYN_SENT,
	TCP_STATUS_ESTABLISHED,

	TCP_STATUS_FIN_WAIT_1,
	TCP_STATUS_FIN_WAIT_2,
	TCP_STATUS_CLOSING,
	TCP_STATUS_TIME_WAIT,

	TCP_STATUS_CLOSE_WAIT,
	TCP_STATUS_LAST_ACK

}TCP_STATUS;

struct syn_tcp_option{
    uint8_t kind_mss;
    uint8_t mss_length;
    rte_be16_t mss_option_value;
    uint8_t kind_sack;
    uint8_t sack_length;
    uint8_t kind_tsecr;
    uint8_t tsecr_length;
    rte_be32_t ts_option_value;
    rte_be32_t tsecr_option_value;
    uint8_t kind_nop;
    uint8_t kind_wscale;
    uint8_t wscale_length;
    uint8_t wscale_option_value;
}__rte_packed; //共20字节

struct tcp_stream 
{ 
	int fd; 

	uint32_t dip;
	uint8_t localmac[RTE_ETHER_ADDR_LEN];
	uint16_t dport;
	
	uint8_t protocol;
	
	uint16_t sport;
	uint32_t sip;

	uint32_t snd_nxt; // seqnum
	uint32_t rcv_nxt; // acknum
    uint32_t recv_ac;

	TCP_STATUS status;

	struct rte_ring *sndbuf;
	// struct rte_ring *rcvbuf;

	struct tcp_stream *prev;
	struct tcp_stream *next;

	pthread_cond_t cond;
	pthread_mutex_t mutex;

    struct syn_tcp_option syn_op;
};

struct tcp_v6_stream 
{ 
	int fd; 
    int work_node_id;

	uint8_t d_ipv6[16];
	uint8_t localmac[RTE_ETHER_ADDR_LEN];
	uint16_t dport;
	
	uint8_t protocol;
	
	uint16_t sport;
	uint8_t s_ipv6[16];

    uint32_t v4_dip;
    uint32_t v4_sip;

	uint32_t snd_nxt; // seqnum
	uint32_t rcv_nxt; // acknum
    uint32_t recv_ac;

	TCP_STATUS status;

	struct rte_ring *sndbuf;
	// struct rte_ring *rcvbuf;

	struct tcp_v6_stream *prev;
	struct tcp_v6_stream *next;

	pthread_cond_t cond;
	pthread_mutex_t mutex;

    char *request_payload;
    uint16_t req_payloadlen;
};

struct tcp_table 
{
	int count;
	//struct tcp_stream *listener_set;	//
#if ENABLE_SINGLE_EPOLL 
	struct eventpoll *ep; // single epoll
#endif
	struct tcp_stream *tcb_set;
    struct tcp_v6_stream *tcb_v6_set;
	pthread_mutex_t mutex_v4;
	pthread_mutex_t mutex_v6;
};
struct tcp_table *g_pstTcpTbl = NULL;
struct tcp_table *tcpInstance(void) 
{
	if (g_pstTcpTbl == NULL) 
    {
		g_pstTcpTbl = rte_malloc("tcp_table", sizeof(struct tcp_table), 0);
		memset(g_pstTcpTbl, 0, sizeof(struct tcp_table));
        pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
	    rte_memcpy(&g_pstTcpTbl->mutex_v4, &blank_mutex, sizeof(pthread_mutex_t));
        rte_memcpy(&g_pstTcpTbl->mutex_v6, &blank_mutex, sizeof(pthread_mutex_t));
	}
	return g_pstTcpTbl;
}

struct tcp_fragment 
{ 
	uint16_t sport;  
	uint16_t dport;  
	uint32_t seqnum;  
	uint32_t acknum;  
	uint8_t  hdrlen_off;  
	uint8_t  tcp_flags; 
	uint16_t windows;   
	uint16_t cksum;     
	uint16_t tcp_urp;  

	int optlen;
	uint32_t option[D_TCP_OPTION_LENGTH];

	unsigned char *data;
	uint32_t length;
};

struct localhost 
{
	int fd;

	//unsigned int status; //
	uint32_t localip; // ip --> mac
	unsigned char localmac[RTE_ETHER_ADDR_LEN];
	uint16_t localport;

	unsigned char protocol;

	struct rte_ring *sndbuf;
	struct rte_ring *rcvbuf;

	struct localhost *prev; 
	struct localhost *next;

	pthread_cond_t cond;
	pthread_mutex_t mutex;
};
struct localhost *g_pstHost = NULL;

static volatile bool force_quit;

struct St_InOut_Ring 
{
	struct rte_ring *pstInRing;
	struct rte_ring *pstOutRing;
};
struct St_InOut_Ring *g_pstRingIns = NULL;

struct proxy_Ring
{
    struct rte_ring *proInRing;
	struct rte_ring *proOutRing;
    struct rte_ring *proTranStoCRing;
    struct rte_ring *proTranCtoSRing;
};
struct proxy_Ring *fs_proxyRingIns = NULL;

struct arp_entry 
{
	uint32_t ip;
	unsigned char hwaddr[RTE_ETHER_ADDR_LEN];

	unsigned char type;

	struct arp_entry *next;
	struct arp_entry *prev;
};

// arp表结构
struct arp_table 
{
	struct arp_entry *entries;
	int count;

	pthread_spinlock_t spinlock;
};
struct arp_table *g_pstArpTbl = NULL;

#define RTE_LOGTYPE_L2FWD RTE_LOGTYPE_USER1

#define MAX_PKT_BURST 2048
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */
#define MEMPOOL_CACHE_SIZE 256

/*
 * Configurable number of RX/TX ring descriptors
 */
#define MAX_RX_QUEUE_PER_LCORE 16
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

/* ethernet addresses of ports */
static struct rte_ether_addr l2fwd_ports_eth_addr[RTE_MAX_ETHPORTS];

//struct rte_ether_addr g_stCpuMac;

/* mask of enabled ports */
static uint32_t l2fwd_enabled_port_mask = 0;

static struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_ETHPORTS];

static uint32_t l2fwd_dst_ports[RTE_MAX_ETHPORTS];

static struct rte_eth_conf port_conf = {
    .rxmode = {.mtu = 1518 },
    .txmode = {
        .mq_mode = RTE_ETH_MQ_TX_NONE,
    },
};

struct rte_mempool * l2fwd_pktmbuf_pool = NULL;


struct my_header {
    uint16_t id;
    uint16_t flag;
};

struct lcore_queue_conf {
	unsigned n_rx_port;
	unsigned rx_port_list[MAX_RX_QUEUE_PER_LCORE];
} __rte_cache_aligned;
struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];

struct l2fwd_port_statistics {
	uint64_t tx;
	uint64_t rx;
	uint64_t dropped;
} __rte_cache_aligned;
struct l2fwd_port_statistics port_statistics[RTE_MAX_ETHPORTS];

static uint64_t timer_period = 5; /* default period is 10 seconds for send packets */

static struct St_InOut_Ring *ringInstance(void) 
{
	if (g_pstRingIns == NULL) 
    {
		g_pstRingIns = rte_malloc("in/out ring", sizeof(struct St_InOut_Ring), 0);
		memset(g_pstRingIns, 0, sizeof(struct St_InOut_Ring));
	}

	return g_pstRingIns;
}

static struct proxy_Ring *proxy_RingInstance(void)
{
    if(fs_proxyRingIns == NULL)
    {
        fs_proxyRingIns = rte_malloc("proxy ring", sizeof(struct proxy_Ring), 0);
        memset(fs_proxyRingIns, 0, sizeof(struct proxy_Ring));
    }
    return fs_proxyRingIns;
}

static struct tcp_v6_stream * tcp_v6_stream_create(char sip[], char dip[], uint16_t sport, uint16_t dport, char *payload, uint16_t payloadlen) 
{ 
    char acBuf[32] = {0};
    unsigned int uiSeed;
    struct tcp_v6_stream *pstStream = rte_malloc("tcp_v6_stream", sizeof(struct tcp_v6_stream), 0);
	if (pstStream == NULL) 
        return NULL;
    struct in6_addr ipv6_address;
    inet_pton(AF_INET6, sip, &ipv6_address);
    rte_memcpy(pstStream->s_ipv6, ipv6_address.s6_addr, 16);
    inet_pton(AF_INET6, dip, &ipv6_address);
    rte_memcpy(pstStream->d_ipv6, ipv6_address.s6_addr, 16);
    //printf("sip: %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X\n",sip[0],sip[1],sip[2],sip[3],sip[4],sip[5],sip[6],sip[7],sip[8],sip[9],sip[10],sip[11],sip[12],sip[13],sip[14],sip[15]);
    //printf("srcipv6: %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X\n", pstStream->s_ipv6[0],pstStream->s_ipv6[1],pstStream->s_ipv6[2],pstStream->s_ipv6[3],pstStream->s_ipv6[4],pstStream->s_ipv6[5],pstStream->s_ipv6[6],pstStream->s_ipv6[7],pstStream->s_ipv6[8],pstStream->s_ipv6[9],pstStream->s_ipv6[10],pstStream->s_ipv6[11],pstStream->s_ipv6[12],pstStream->s_ipv6[13],pstStream->s_ipv6[14],pstStream->s_ipv6[15]);

    pstStream->sport = sport;
    pstStream->dport = dport;
    pstStream->protocol = IPPROTO_TCP;
    pstStream->fd = -1;
    pstStream->status = TCP_STATUS_CLOSED;
    pstStream->recv_ac = 0;
    
    sprintf(acBuf, "sendbuf%d", ntohs(sport));
	pstStream->sndbuf = rte_ring_create(acBuf, D_RING_SIZE, rte_socket_id(), RING_F_SC_DEQ);
	// sprintf(acBuf, "recvbuf%d", sport);
	// pstStream->rcvbuf = rte_ring_create(acBuf, D_RING_SIZE, rte_socket_id(), 0);

    // seq num
	uiSeed = time(NULL);
	pstStream->snd_nxt = rand_r(&uiSeed) % D_TCP_MAX_SEQ;
	rte_memcpy(pstStream->localmac, &l2fwd_ports_eth_addr[5], RTE_ETHER_ADDR_LEN);

	pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
	rte_memcpy(&pstStream->cond, &blank_cond, sizeof(pthread_cond_t));

	pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
	rte_memcpy(&pstStream->mutex, &blank_mutex, sizeof(pthread_mutex_t));

    pstStream->request_payload = rte_malloc("request_payload", payloadlen + 1, 0);
    if(pstStream->request_payload == NULL)
    {
        printf("no pstStream->request_payload allocated! \n");
        return NULL;
    }
    memset(pstStream->request_payload, 0, payloadlen + 1);
    memcpy(pstStream->request_payload, payload, payloadlen);

    pstStream->req_payloadlen = payloadlen;

    return pstStream;
}

static struct tcp_stream * tcp_stream_create(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport) 
{ 
    char acBuf[32] = {0};
    unsigned int uiSeed;
    struct tcp_stream *pstStream = rte_malloc("tcp_stream", sizeof(struct tcp_stream), 0);
	if (pstStream == NULL) 
        return NULL;
        
    pstStream->sip = sip;
    pstStream->dip = dip;
    pstStream->sport = sport;
    pstStream->dport = dport;
    pstStream->protocol = IPPROTO_TCP;
    pstStream->fd = -1;
    pstStream->status = TCP_STATUS_LISTEN;
    pstStream->recv_ac = 0;

    sprintf(acBuf, "sndbuf%x%d", sip, ntohs(sport));
	pstStream->sndbuf = rte_ring_create(acBuf, D_RING_SIZE, rte_socket_id(), RING_F_SC_DEQ);
	// sprintf(acBuf, "rcvbuf%x%d", sip, sport);
	// pstStream->rcvbuf = rte_ring_create(acBuf, D_RING_SIZE, rte_socket_id(), 0);

    // seq num
	uiSeed = time(NULL);
	pstStream->snd_nxt = rand_r(&uiSeed) % D_TCP_MAX_SEQ;
	rte_memcpy(pstStream->localmac, &l2fwd_ports_eth_addr[2], RTE_ETHER_ADDR_LEN);

	pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
	rte_memcpy(&pstStream->cond, &blank_cond, sizeof(pthread_cond_t));

	pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
	rte_memcpy(&pstStream->mutex, &blank_mutex, sizeof(pthread_mutex_t));

    return pstStream;
}


/* display usage */
static void
l2fwd_usage(const char *prgname)
{
    printf("%s [EAL options] -- -p PORTMASK\n"
           "  -p PORTMASK: hexadecimal bitmask of ports to configure\n",
           prgname);
}

static int
l2fwd_parse_portmask(const char *portmask)
{
    char *end = NULL;
    unsigned long pm;

    /* parse hexadecimal string */
    pm = strtoul(portmask, &end, 16);
    if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
        return -1;

    if (pm == 0)
        return -1;

    return pm;
}

static const char short_options[] =
    "p:"  /* portmask */
    ;


/* Parse the argument given in the command line of the application */
static int
l2fwd_parse_args(int argc, char **argv)
{
    int opt, ret;
    char **argvopt;
    char *prgname = argv[0];

    argvopt = argv;

    while ((opt = getopt(argc, argvopt, short_options)) != EOF) {

        switch (opt) {
        /* portmask */
        case 'p':
            l2fwd_enabled_port_mask = l2fwd_parse_portmask(optarg);
            if (l2fwd_enabled_port_mask == 0) {
                printf("invalid portmask\n");
                l2fwd_usage(prgname);
                return -1;
            }
            break;

        /* long options */
        case 0:
            break;

        default:
            l2fwd_usage(prgname);
            return -1;
        }
    }

    if (optind >= 0)
        argv[optind-1] = prgname;

    ret = optind-1;
    optind = 1; /* reset getopt lib */
    return ret;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
    uint16_t portid;
    uint8_t count, all_ports_up, print_flag = 0;
    struct rte_eth_link link;
    int ret;

    printf("\nChecking link status");
    fflush(stdout);
    for (count = 0; count <= MAX_CHECK_TIME; count++) {
        if (force_quit)
            return;
        all_ports_up = 1;
        RTE_ETH_FOREACH_DEV(portid) {
            if (force_quit)
                return;
            if ((port_mask & (1 << portid)) == 0)
                continue;
            memset(&link, 0, sizeof(link));
            ret = rte_eth_link_get_nowait(portid, &link);
            if (ret < 0) {
                all_ports_up = 0;
                if (print_flag == 1)
                    printf("Port %u link get failed: %s\n",
                        portid, rte_strerror(-ret));
                continue;
            }
            /* print link status if flag set */
            if (print_flag == 1) {
                if (link.link_status)
                    printf(
                    "Port%d Link Up. Speed %u Mbps - %s\n",
                        portid, link.link_speed,
                (link.link_duplex == RTE_ETH_LINK_FULL_DUPLEX) ?
                    ("full-duplex") : ("half-duplex\n"));
                else
                    printf("Port %d Link Down\n", portid);
                continue;
            }
            /* clear all_ports_up flag if any link down */
            if (link.link_status == RTE_ETH_LINK_DOWN) {
                all_ports_up = 0;
                break;
            }
        }
        /* after finally printing all link status, get out */
        if (print_flag == 1)
            break;

        if (all_ports_up == 0) {
            printf(".");
            fflush(stdout);
            rte_delay_ms(CHECK_INTERVAL);
        }

        /* set the print_flag if all ports up or timeout */
        if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
            print_flag = 1;
            printf("done\n");
        }
    }
}

static void
signal_handler(int signum)
{
    if (signum == SIGINT) {
        printf("\n\nSignal %d received, preparing to exit...\n",
                signum);
        force_quit = true;
    }
}

int get_fd_frombitmap(void) 
{
	int fd = D_DEFAULT_FD_NUM;
	for (; fd < D_MAX_FD_COUNT; fd ++) 
    {
		if ((g_ucFdTable[fd/8] & (0x1 << (fd % 8))) == 0) 
        {
			g_ucFdTable[fd/8] |= (0x1 << (fd % 8));
			return fd;
		}
	}

	return -1;
}

int set_fd_frombitmap(int fd) 
{
	if (fd >= D_MAX_FD_COUNT) 
        return -1;

	g_ucFdTable[fd/8] &= ~(0x1 << (fd % 8));

	return 0;
}

void GetNext(char* sub, int* next, int lensub)/*sub代表子串；next是外部开辟的动态内存数组；lensub是子串长度*/
{
	next[0] = -1;
	next[1] = 0;
	int i = 2;//当前i下标
	int k = 0;//前一项的k

	while(i < lensub)
	{
		if (k == -1 || sub[i - 1] == sub[k])//k回退到-1或前一项sub[i-1]==sub[k]
		{
			next[i] = k + 1;
			i++;
			k++;
		}
		else
		{
			k = next[k];//if条件不满足时则需将k回退到-1下标
		}
	}
}

int KMP(char* str, char* sub, int pos)/*str:代表主串；sub:代表子串；pos:代表从主串的pos位置开始找*/
{
	assert(str&&sub);//断言
	if (str == NULL || sub == NULL)//字符串为空直接返回-1
		return -1;
	int lenstr = strlen(str);//求主串长度
	int lensub = strlen(sub);//求子串长度
	if (pos < 0 || pos >= lenstr)//pos位置不合法直接返回-1
		return -1;

	int *next = (int*)malloc(sizeof(int)*lensub);//开辟动态内存给next数组存放数据
	assert(next);

	GetNext(sub, next,lensub);//求出next数组

	int i = pos;//遍历主串
	int j = 0;//遍历子串

	while (i < lenstr&&j < lensub)
	{
		if (j == -1 || str[i] == sub[j])
		{
			i++;
			j++;
		}
		else
		{
			j = next[j];
		}
	}
	free(next);
	next = NULL;
	if (j >= lensub)
	{
		return i - j;
	}
	return -1;
}

static int ng_encode_v6_tcp_apppkt(uint8_t *msg, uint8_t sip[], uint8_t dip[],
	uint8_t *srcmac, uint8_t *dstmac, struct tcp_fragment *fragment, unsigned int total_len, int work_Node_id) 
{
	struct rte_ether_hdr *pstEth;
	struct rte_ipv6_hdr *pstIp;
	struct rte_tcp_hdr *pstTcp;

	// 1 ethhdr
	pstEth = (struct rte_ether_hdr *)msg;
	rte_memcpy(pstEth->src_addr.addr_bytes, srcmac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(pstEth->dst_addr.addr_bytes, dstmac, RTE_ETHER_ADDR_LEN);
	pstEth->ether_type = htons(RTE_ETHER_TYPE_IPV6);
	
	// 2 iphdr 
	pstIp = (struct rte_ipv6_hdr *)(pstEth + 1);
    rte_memcpy(pstIp->src_addr, sip, 16);
    rte_memcpy(pstIp->dst_addr, dip, 16);
    pstIp->hop_limits = 64;
    pstIp->payload_len = htons(total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv6_hdr));
    pstIp->proto = IPPROTO_TCP;
    pstIp->vtc_flow = htonl(0x60000000 + (unsigned int)work_Node_id);

	// 3 tcphdr 
	pstTcp = (struct rte_tcp_hdr *)(pstIp + 1);
	pstTcp->src_port = fragment->sport;
	pstTcp->dst_port = fragment->dport;
	pstTcp->sent_seq = htonl(fragment->seqnum);
	pstTcp->recv_ack = htonl(fragment->acknum);
	pstTcp->data_off = fragment->hdrlen_off;
	pstTcp->rx_win = fragment->windows;
	pstTcp->tcp_urp = fragment->tcp_urp;
	pstTcp->tcp_flags = fragment->tcp_flags;
	if (fragment->data != NULL) 
	{
		uint8_t *payload = (uint8_t*)(pstTcp + 1) + fragment->optlen * sizeof(uint32_t);
		rte_memcpy(payload, fragment->data, fragment->length);
	}
	pstTcp->cksum = 0;
	pstTcp->cksum = rte_ipv6_udptcp_cksum(pstIp, pstTcp);

	return 0;
}

static struct rte_mbuf * ng_v6_tcp_pkt(struct rte_mempool *mbuf_pool, uint8_t sip[], uint8_t dip[],
	uint8_t *srcmac, uint8_t *dstmac, struct tcp_fragment *fragment, int work_Node_id) 
{
	unsigned int uiTotalLen;
	struct rte_mbuf *pstMbuf;
    unsigned char *pucPktData;

	uiTotalLen = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr) + sizeof(struct rte_tcp_hdr) + 
							fragment->optlen * sizeof(uint32_t) + fragment->length;  
	
	pstMbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!pstMbuf) 
		rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
	
	pstMbuf->pkt_len = uiTotalLen;
    pstMbuf->data_len = uiTotalLen;
    pucPktData = rte_pktmbuf_mtod(pstMbuf, unsigned char*);

	ng_encode_v6_tcp_apppkt(pucPktData, sip, dip, srcmac, dstmac, fragment, uiTotalLen, work_Node_id);

	return pstMbuf;
}

int tcp_v6_out(struct rte_mempool *pstMbufPool) 
{
	struct tcp_table *pstTable = tcpInstance();
	struct tcp_v6_stream *pstStream = NULL;
	for(pstStream = pstTable->tcb_v6_set; pstStream != NULL; pstStream = pstStream->next)
	{
        if(pthread_mutex_trylock(&pstStream->mutex) != 0) return 0;
		if(pstStream->sndbuf == NULL)
        {
            pthread_mutex_unlock(&pstStream->mutex);
            continue;
        }
			

		struct tcp_fragment *pstFragment = NULL;		
		int iSendCnt = rte_ring_mc_dequeue(pstStream->sndbuf, (void**)&pstFragment);
		if (iSendCnt < 0) 
        {
            pthread_mutex_unlock(&pstStream->mutex);
            continue;
        }

		// struct in6_addr addr;
        // rte_memcpy(addr.s6_addr, pstStream->d_ipv6, 16);
        // char ipv6_str[INET6_ADDRSTRLEN];

		uint8_t *dstmac = work_node_MAC[pstStream->work_node_id].addr_bytes; // 这里的源ip指的是对端ip
		if (dstmac == NULL)  // 先广播发个arp包确定对端mac地址 
		{
			printf("NO WORK_NODE MAC!!\n");
            continue;
		} 
		else 
		{
            if(pstStream->s_ipv6 == 0)
            {
                rte_free(pstFragment);
                pthread_mutex_unlock(&pstStream->mutex);
                continue;
            }
			struct rte_mbuf *pstTcpBuf = ng_v6_tcp_pkt(pstMbufPool, pstStream->s_ipv6, pstStream->d_ipv6, 
												pstStream->localmac, dstmac, pstFragment, pstStream->work_node_id);

			rte_ring_sp_enqueue_burst(fs_proxyRingIns->proOutRing, (void **)&pstTcpBuf, 1, NULL);
            //printf("tcp_v6_out_p1 ---> dst: %s:  %d \n", inet_ntop(AF_INET6, &addr, ipv6_str, INET6_ADDRSTRLEN), ntohs(pstFragment->dport));

			if (pstFragment->data != NULL)
				rte_free(pstFragment->data);
			
			rte_free(pstFragment);
		}
        pthread_mutex_unlock(&pstStream->mutex);
	}

    return 0;
}

int nsocket(__attribute__((unused)) int domain, int type, __attribute__((unused))  int protocol)
{
    int iFd;
    struct localhost *pstHost;
    pthread_cond_t pctCond = PTHREAD_COND_INITIALIZER;
    pthread_mutex_t pmtMutex = PTHREAD_MUTEX_INITIALIZER;

    iFd = get_fd_frombitmap();
    if(type == SOCK_DGRAM) // udp
    {
        pstHost = rte_malloc("localhost", sizeof(struct localhost), 0);
        if(pstHost == NULL)
        {
            printf("[%s][%d]: rte_malloc fail!\n", __FUNCTION__, __LINE__);
            return -1;
        }

        memset(pstHost, 0x00, sizeof(struct localhost));
        pstHost->fd = iFd;
        pstHost->protocol = IPPROTO_UDP;
        pstHost->rcvbuf = rte_ring_create("recv buffer", D_RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (pstHost->rcvbuf == NULL) 
        {
            printf("[%s][%d]: rte_ring_create fail!\n", __FUNCTION__, __LINE__);
			rte_free(pstHost);
			return -1;
		}
        pstHost->sndbuf = rte_ring_create("send buffer", D_RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (pstHost->sndbuf == NULL) 
        {
            printf("[%s][%d]: rte_ring_create fail!\n", __FUNCTION__, __LINE__);
            rte_ring_free(pstHost->rcvbuf);
			rte_free(pstHost);
			return -1;
		}

		rte_memcpy(&pstHost->cond, &pctCond, sizeof(pthread_cond_t));

		rte_memcpy(&pstHost->mutex, &pmtMutex, sizeof(pthread_mutex_t));

		LL_ADD(pstHost, g_pstHost);
    }
    else if(type == SOCK_STREAM) // tcp
    {
        struct tcp_stream *pstStream = rte_malloc("tcp_stream", sizeof(struct tcp_stream), 0);
		if (pstStream == NULL) 
			return -1;
		
		memset(pstStream, 0, sizeof(struct tcp_stream));
        pstStream->fd = iFd;
        pstStream->protocol = IPPROTO_TCP;
		pstStream->next = pstStream->prev = NULL;

        // pstStream->rcvbuf = rte_ring_create("tcp recv buffer", D_RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
		// if (pstStream->rcvbuf == NULL) 
        // {
		// 	rte_free(pstStream);
		// 	return -1;
		// }
		pstStream->sndbuf = rte_ring_create("tcp send buffer", D_RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (pstStream->sndbuf == NULL) 
        {
			//rte_ring_free(pstStream->rcvbuf);
			rte_free(pstStream);
			return -1;
		}

        pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
		rte_memcpy(&pstStream->cond, &blank_cond, sizeof(pthread_cond_t));

		pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
		rte_memcpy(&pstStream->mutex, &blank_mutex, sizeof(pthread_mutex_t));

        g_pstTcpTbl = tcpInstance();
		LL_ADD(pstStream, g_pstTcpTbl->tcb_set);           // todo :hash
    }

    return iFd;
}

void* get_hostinfo_fromfd(int iSockFd) 
{
	struct localhost *pstHost = NULL;
	struct tcp_stream *pstStream = NULL;
    struct tcp_v6_stream *pstv6Stream = NULL;

	for (pstHost = g_pstHost; pstHost != NULL; pstHost = g_pstHost->next) 
    {
		if (iSockFd == pstHost->fd) 
			return pstHost;
	}

	for (pstStream = g_pstTcpTbl->tcb_set; pstStream != NULL; pstStream = pstStream->next) {
		if (iSockFd == pstStream->fd) {
			return pstStream;
		}
	}

    for (pstv6Stream = g_pstTcpTbl->tcb_v6_set; pstv6Stream != NULL; pstv6Stream = pstv6Stream->next) {
		if (iSockFd == pstv6Stream->fd) {
			return pstv6Stream;
		}
	}
	
	return NULL;
}

int nbind(int sockfd, const struct sockaddr *addr, __attribute__((unused))  socklen_t addrlen)
{
    void *info = NULL;

    info = get_hostinfo_fromfd(sockfd);
    if(info == NULL) 
        return -1;

    struct localhost *pstHostInfo = (struct localhost *)info;
    if(pstHostInfo->protocol == IPPROTO_UDP)
    {
        const struct sockaddr_in *pstAddr = (const struct sockaddr_in *)addr;
		pstHostInfo->localport = pstAddr->sin_port;
		rte_memcpy(&pstHostInfo->localip, &pstAddr->sin_addr.s_addr, sizeof(uint32_t));
		rte_memcpy(pstHostInfo->localmac, &l2fwd_ports_eth_addr[2], RTE_ETHER_ADDR_LEN);
    }
    else if(pstHostInfo->protocol == IPPROTO_TCP)
    {
        struct tcp_stream* pstStream = (struct tcp_stream*)pstHostInfo;

        const struct sockaddr_in *pstAddr = (const struct sockaddr_in *)addr;
		pstStream->dport = pstAddr->sin_port;
		rte_memcpy(&pstStream->dip, &pstAddr->sin_addr.s_addr, sizeof(uint32_t));
		rte_memcpy(pstStream->localmac, &l2fwd_ports_eth_addr[2], RTE_ETHER_ADDR_LEN);

		pstStream->status = TCP_STATUS_CLOSED;
    }

    return 0;
}

int nlisten(int sockfd, __attribute__((unused)) int backlog)
{
    void *pstHostInfo = get_hostinfo_fromfd(sockfd);
	if (pstHostInfo == NULL) 
        return -1;

	struct tcp_stream *pstStream = (struct tcp_stream *)pstHostInfo;
	if (pstStream->protocol == IPPROTO_TCP) 
    {
		pstStream->status = TCP_STATUS_LISTEN;
	}

    return 0;
}

static struct tcp_stream *get_accept_tcb(uint16_t dport) 
{
	struct tcp_stream *apt;
	for (apt = g_pstTcpTbl->tcb_set; apt != NULL; apt = apt->next) 
    {
		if (dport == apt->dport && apt->fd == -1) 
        {
			return apt;
		}
	}

	return NULL;
}

int fconnect(int sockfd, int work_Node_id, struct rte_tcp_hdr * pstTcphdr, struct syn_tcp_option *synopt)
{
    void *pstHostInfo = get_hostinfo_fromfd(sockfd);
    struct tcp_v6_stream *pstStream = (struct tcp_v6_stream *)pstHostInfo;
    struct tcp_fragment *pstFragment = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
	if (pstFragment == NULL) 
        return -1;
	memset(pstFragment, 0, sizeof(struct tcp_fragment));

    pstFragment->sport = pstTcphdr->src_port;
	pstFragment->dport = pstTcphdr->dst_port;

    pstFragment->seqnum = pstStream->snd_nxt;
	pstFragment->acknum = 0;
	pstStream->rcv_nxt = pstFragment->acknum;
	
	pstFragment->tcp_flags = RTE_TCP_SYN_FLAG;
	pstFragment->windows = D_TCP_INITIAL_WINDOW;
	pstFragment->hdrlen_off = 0xA0;
	
	pstFragment->data = rte_malloc("unsigned char *", sizeof(struct syn_tcp_option), 0);
    if (pstFragment->data == NULL) 
    {
		rte_free(pstFragment);
		return -1;
	}
    memset(pstFragment->data, 0, sizeof(struct syn_tcp_option));
    rte_memcpy(pstFragment->data, synopt, sizeof(struct syn_tcp_option));
	pstFragment->length = sizeof(struct syn_tcp_option);
    //printf("ready enqueue\n");
	rte_ring_sp_enqueue(pstStream->sndbuf, pstFragment);
    pstStream->status = TCP_STATUS_SYN_SENT;
    //printf("connect done\n");
    return 0;
}


int naccept(int sockfd, struct sockaddr *addr, __attribute__((unused)) socklen_t *addrlen)
{
    void *pstHostInfo = get_hostinfo_fromfd(sockfd);
	if (pstHostInfo == NULL) 
        return -1;

	struct tcp_stream *pstStream = (struct tcp_stream *)pstHostInfo;
    if (pstStream->protocol == IPPROTO_TCP) 
    {
        struct tcp_stream *pstAccept = NULL;

        pthread_mutex_lock(&pstStream->mutex);
        while((pstAccept = get_accept_tcb(pstStream->dport)) == NULL)
        {
            pthread_cond_wait(&pstStream->cond, &pstStream->mutex);
        }
        pthread_mutex_unlock(&pstStream->mutex);

        pstAccept->fd = get_fd_frombitmap();

        struct sockaddr_in *saddr = (struct sockaddr_in *)addr;
		saddr->sin_port = pstAccept->sport;
		rte_memcpy(&saddr->sin_addr.s_addr, &pstAccept->sip, sizeof(uint32_t));

		return pstAccept->fd;
    }

    return -1;
}

// ssize_t nrecv(int sockfd, void *buf, size_t len, __attribute__((unused)) int flags)
// {
//     ssize_t length = 0;
//     void *pstHostInfo = get_hostinfo_fromfd(sockfd);
// 	if (pstHostInfo == NULL) 
//         return -1;

// 	struct tcp_stream *pstStream = (struct tcp_stream *)pstHostInfo;
//     if(pstStream->protocol == IPPROTO_TCP)
//     {
//         struct tcp_fragment *pstFragment = NULL;
//         int iRcvNum = 0;

//         // 等待接收队列中的数据到来
//         pthread_mutex_lock(&pstStream->mutex);
// 		while ((iRcvNum = rte_ring_mc_dequeue(pstStream->rcvbuf, (void **)&pstFragment)) < 0) 
//         {
// 			pthread_cond_wait(&pstStream->cond, &pstStream->mutex);
// 		}
// 		pthread_mutex_unlock(&pstStream->mutex);

//         if (pstFragment->length > len) 
//         {
//             rte_memcpy(buf, pstFragment->data, len);

// 			uint32_t i = 0;
// 			for(i = 0; i < pstFragment->length - len; i ++) 
//             {
// 				pstFragment->data[i] = pstFragment->data[len + i];
// 			}
// 			pstFragment->length = pstFragment->length - len;
// 			length = pstFragment->length;

// 			rte_ring_mp_enqueue(pstStream->rcvbuf, pstFragment);
//         }
//         else if(pstFragment->length == 0)
//         {
//             rte_free(pstFragment);
// 			return 0;
//         }
//         else
//         {
//             rte_memcpy(buf, pstFragment->data, pstFragment->length);
// 			length = pstFragment->length;

// 			rte_free(pstFragment->data);
// 			pstFragment->data = NULL;

// 			rte_free(pstFragment);
//         }
//     }

//     return length;
// }

ssize_t nsend(int sockfd, const void *buf, size_t len,__attribute__((unused)) int flags)
{
    unsigned int uiLength = 0;
    void *pstHostInfo = get_hostinfo_fromfd(sockfd);
	if (pstHostInfo == NULL) 
        return -1;

	struct tcp_stream *pstStream = (struct tcp_stream *)pstHostInfo;
    if(pstStream->protocol == IPPROTO_TCP)
    {
        struct tcp_fragment *pstFragment = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
		if (pstFragment == NULL) 
        {
			return -2;
		}

		memset(pstFragment, 0, sizeof(struct tcp_fragment));
        pstFragment->dport = pstStream->sport;
		pstFragment->sport = pstStream->dport;
		pstFragment->acknum = pstStream->rcv_nxt;
		pstFragment->seqnum = pstStream->snd_nxt;
		pstFragment->tcp_flags = RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG;
		pstFragment->windows = D_TCP_INITIAL_WINDOW;
		pstFragment->hdrlen_off = 0x50;

        pstFragment->data = rte_malloc("unsigned char *", len + 1, 0);
		if (pstFragment->data == NULL) 
        {
			rte_free(pstFragment);
			return -1;
		}
		memset(pstFragment->data, 0, len+1);

		rte_memcpy(pstFragment->data, buf, len);
		pstFragment->length = len;
		uiLength = pstFragment->length;

		puts("ready to send!");
		rte_ring_mp_enqueue(pstStream->sndbuf, pstFragment);
    }

    return uiLength;
}

int nclose(int fd)
{
    void *info = NULL;

    info = (struct localhost *)get_hostinfo_fromfd(fd);
    if(info == NULL) 
        return -1;

    struct localhost *pstHostInfo = (struct localhost *)info;
    if(pstHostInfo->protocol == IPPROTO_UDP)
    {
        LL_REMOVE(pstHostInfo, g_pstHost);

        if (pstHostInfo->rcvbuf)
			rte_ring_free(pstHostInfo->rcvbuf);
		if (pstHostInfo->sndbuf) 
			rte_ring_free(pstHostInfo->sndbuf);

		rte_free(pstHostInfo);

		set_fd_frombitmap(fd);
    }
    else if(pstHostInfo->protocol == IPPROTO_TCP)
    {
        struct tcp_stream *pstStream = (struct tcp_stream*)info;
        if (pstStream->status != TCP_STATUS_LISTEN)
        {
            struct tcp_fragment *pstFragment = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
			if (pstFragment == NULL) 
                return -1;

            memset(pstFragment, 0x00, sizeof(struct tcp_fragment));
            pstFragment->data = NULL;
			pstFragment->length = 0;
			pstFragment->sport = pstStream->dport;
			pstFragment->dport = pstStream->sport;

			pstFragment->seqnum = pstStream->snd_nxt;
			pstFragment->acknum = pstStream->rcv_nxt;

			pstFragment->tcp_flags = RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG;  // 发送FIN
			pstFragment->windows = D_TCP_INITIAL_WINDOW;
			pstFragment->hdrlen_off = 0x50;

            rte_ring_mp_enqueue(pstStream->sndbuf, pstFragment);
			pstStream->status = TCP_STATUS_LAST_ACK;

            set_fd_frombitmap(fd); 
        }
        else
        {
            LL_REMOVE(pstStream, g_pstTcpTbl->tcb_set);	
			rte_free(pstStream);
        }
    }

    return 0;
}

int tcp_client_entry(__attribute__((unused))  void *arg)
{
    int iRxNum;
    int iTotalNum;
    int iOffset;
    int iTxNum;
    struct rte_mbuf *pstRecvMbuf[1024] = {NULL};
    struct rte_mbuf *pstSendMbuf[512] = {NULL};
    while (!force_quit) 
    {
        // rx
        iRxNum = rte_eth_rx_burst(5, 0, pstRecvMbuf, D_BURST_SIZE);
        if(iRxNum > 0)
            rte_ring_sp_enqueue_burst(fs_proxyRingIns->proInRing, (void**)pstRecvMbuf, iRxNum, NULL);
        
        // tx
        iTotalNum = rte_ring_sc_dequeue_burst(fs_proxyRingIns->proOutRing, (void**)pstSendMbuf, D_BURST_SIZE, NULL);
		if(iTotalNum > 0)
		{
			iOffset = 0;
			while(iOffset < iTotalNum)
			{
				iTxNum = rte_eth_tx_burst(5, 0, &pstSendMbuf[iOffset], iTotalNum - iOffset);
				if(iTxNum > 0)
					iOffset += iTxNum;
			}
		}
    }
}

int get_work_node_id(char * payload)
{
    for(int j = 0; j < D_MAX_WORK_NODE; ++j)
    {
        if(KMP(payload, work_node[j], 0) >= 0)
        {
            return j;
        }
    }
}

struct tcp_stream * tcp_stream_search(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport) 
{
	struct tcp_table *pstTable = tcpInstance();
	struct tcp_stream *iter = NULL;

	for (iter = pstTable->tcb_set; iter != NULL; iter = iter->next) // established
    {  
		if (iter->sip == sip && iter->dip == dip && 
			    iter->sport == sport && iter->dport == dport) 
        {
			return iter;
		}

	}

	for (iter = pstTable->tcb_set; iter != NULL; iter = iter->next) 
    {
		if (iter->dip == dip && iter->dport == dport && iter->status == TCP_STATUS_LISTEN)  // listen
        { 
			return iter;
		}
	}

	return NULL;
}

struct tcp_v6_stream * tcp_v6_stream_search(char sip[], char dip[], uint16_t sport, uint16_t dport) 
{
	struct tcp_table *pstTable = tcpInstance();
	struct tcp_v6_stream *iter = NULL;

    struct in6_addr sipv6_address;
    inet_pton(AF_INET6, sip, &sipv6_address);
    struct in6_addr dipv6_address;
    inet_pton(AF_INET6, dip, &dipv6_address);
	for (iter = pstTable->tcb_v6_set; iter != NULL; iter = iter->next)
    {  
		if ((memcmp(iter->s_ipv6, sipv6_address.s6_addr, 16) == 0) && (memcmp(iter->d_ipv6, dipv6_address.s6_addr, 16) == 0) && 
			    iter->sport == sport && iter->dport == dport) 
        {
			return iter;
		}

	}

	return NULL;
}

struct tcp_v6_stream * tcp_v6_stream_search_2(char sip[], char dip[], uint16_t sport, uint16_t dport) 
{
	struct tcp_table *pstTable = tcpInstance();
	struct tcp_v6_stream *iter = NULL;

	for (iter = pstTable->tcb_v6_set; iter != NULL; iter = iter->next)
    {  
        struct in6_addr addr;
        rte_memcpy(addr.s6_addr, dip, 16);
        char ipv6_str[INET6_ADDRSTRLEN];
        //printf("recv src : %s\n", inet_ntop(AF_INET6, &addr, ipv6_str, INET6_ADDRSTRLEN));
		if ((memcmp(iter->s_ipv6, sip, 16) == 0) && (memcmp(iter->d_ipv6, dip, 16) == 0) && 
			    iter->sport == sport && iter->dport == dport) 
        {
			return iter;
		}

	}
    struct in6_addr addr;
    rte_memcpy(addr.s6_addr, dip, 16);
    char ipv6_str[INET6_ADDRSTRLEN];
    printf("recv src : %s, toport : %d\n", inet_ntop(AF_INET6, &addr, ipv6_str, INET6_ADDRSTRLEN), ntohs(sport));
	return NULL;
}

static int send_http_request(struct tcp_v6_stream *pstStream)
{
    struct tcp_fragment *pstFragment = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
	if (pstFragment == NULL) 
        return -1;
	memset(pstFragment, 0, sizeof(struct tcp_fragment));

    pstFragment->sport = pstStream->sport;
	pstFragment->dport = pstStream->dport;
    pstFragment->seqnum = pstStream->snd_nxt;
    pstFragment->acknum = pstStream->rcv_nxt;
    pstFragment->tcp_flags = RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG;
	pstFragment->windows = D_TCP_INITIAL_WINDOW;
	pstFragment->hdrlen_off = 0x50;
    pstFragment->data = rte_malloc("unsigned char *", pstStream->req_payloadlen + 1, 0);
    if (pstFragment->data == NULL) 
    {
		rte_free(pstFragment);
		return -1;
	}
    memset(pstFragment->data, 0, pstStream->req_payloadlen + 1);
    rte_memcpy(pstFragment->data, pstStream->request_payload, pstStream->req_payloadlen);
	pstFragment->length = pstStream->req_payloadlen;
    rte_ring_sp_enqueue(pstStream->sndbuf, pstFragment);
    printf("send request!\n");
    //rte_eal_remote_launch(flow_thread, pstStream, CALL_MAIN);
    return 0;
}

// static int ng_tcp_enqueue_recvbuffer(struct tcp_stream *pstStream, struct rte_tcp_hdr *pstTcphdr, int iTcplen) 
// {
// 	struct tcp_fragment *pstFragment = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
// 	if (pstFragment == NULL) 
// 		return -1;

// 	memset(pstFragment, 0, sizeof(struct tcp_fragment));
// 	pstFragment->dport = ntohs(pstTcphdr->dst_port);
// 	pstFragment->sport = ntohs(pstTcphdr->src_port);

// 	// data_off：前4位表示包头到数据域起始位置之间的大小
// 	// 每一位表示4Byte，最大表示为 15*4Byte 大小
// 	uint8_t hdrlen = pstTcphdr->data_off >> 4;   
// 	int payloadlen = iTcplen - (hdrlen * 4); // 数据域长度
// 	// if (pstTcphdr->tcp_flags & RTE_TCP_FIN_FLAG) 
// 	// 	printf("iTcplen = %d\n", iTcplen);
// 	// printf("payloadlen = %d,", payloadlen);
//     // printf("recv_pkt: TCP--payload: %s\n", (char *)(pstTcphdr + 1));
// 	if(payloadlen > 0)
// 	{
// 		uint8_t *payload = (uint8_t*)pstTcphdr + hdrlen * 4;

// 		pstFragment->data = rte_malloc("unsigned char *", payloadlen+1, 0);
// 		if (pstFragment->data == NULL) 
// 		{
// 			rte_free(pstFragment);
// 			return -1;
// 		}

// 		memset(pstFragment->data, 0, payloadlen + 1);
// 		rte_memcpy(pstFragment->data, payload, payloadlen);
// 		pstFragment->length = payloadlen;
// 	}
// 	else if(payloadlen == 0)
// 	{
// 		pstFragment->length = 0;
// 		pstFragment->data = NULL;
// 	}

// 	rte_ring_mp_enqueue(pstStream->rcvbuf, pstFragment);

// 	pthread_mutex_lock(&pstStream->mutex);
// 	pthread_cond_signal(&pstStream->cond);
// 	pthread_mutex_unlock(&pstStream->mutex);

// 	return 0;
// }

static int ng_tcp_v6_send_ackpkt(struct tcp_v6_stream *pstStream, struct rte_tcp_hdr *pstTcphdr) 
{
	struct tcp_fragment *pstAckFrag = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
	if (pstAckFrag == NULL) 
		return -1;
	
	memset(pstAckFrag, 0, sizeof(struct tcp_fragment));
	pstAckFrag->dport = pstTcphdr->src_port;
	pstAckFrag->sport = pstTcphdr->dst_port;

	// remote
	
	//printf("tcp_send_ackpkt: %u, %u\n", pstStream->rcv_nxt, ntohs(pstTcphdr->sent_seq));
	
    
	pstAckFrag->acknum = pstStream->rcv_nxt;
	pstAckFrag->seqnum = pstStream->snd_nxt;
	pstAckFrag->tcp_flags = RTE_TCP_ACK_FLAG;
	pstAckFrag->windows = D_TCP_INITIAL_WINDOW;
	pstAckFrag->hdrlen_off = 0x50;
	pstAckFrag->data = NULL;
	pstAckFrag->length = 0;
	
	rte_ring_mp_enqueue(pstStream->sndbuf, pstAckFrag);

	return 0;
}

static int ng_tcp_v6_send_finpkt_1(struct tcp_v6_stream *pstStream, struct rte_tcp_hdr *pstTcphdr) 
{
	struct tcp_fragment *pstAckFrag = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
	if (pstAckFrag == NULL) 
		return -1;
	
	memset(pstAckFrag, 0, sizeof(struct tcp_fragment));
	pstAckFrag->dport = pstTcphdr->dst_port;
	pstAckFrag->sport = pstTcphdr->src_port;

	// remote
	
	//printf("tcp_send_ackpkt: %u, %u\n", pstStream->rcv_nxt, ntohs(pstTcphdr->sent_seq));
	
    
	pstAckFrag->acknum = pstStream->rcv_nxt;
	pstAckFrag->seqnum = pstStream->snd_nxt;
	pstAckFrag->tcp_flags = (RTE_TCP_ACK_FLAG | RTE_TCP_FIN_FLAG);
	pstAckFrag->windows = D_TCP_INITIAL_WINDOW;
	pstAckFrag->hdrlen_off = 0x50;
	pstAckFrag->data = NULL;
	pstAckFrag->length = 0;
	
	rte_ring_mp_enqueue(pstStream->sndbuf, pstAckFrag);

	return 0;
}

static int ng_tcp_send_ackpkt(struct tcp_stream *pstStream, struct rte_tcp_hdr *pstTcphdr) 
{
	struct tcp_fragment *pstAckFrag = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
	if (pstAckFrag == NULL) 
		return -1;
	
	memset(pstAckFrag, 0, sizeof(struct tcp_fragment));
	pstAckFrag->dport = pstTcphdr->src_port;
	pstAckFrag->sport = pstTcphdr->dst_port;

	// remote
	
	//printf("tcp_send_ackpkt: %u, %u\n", pstStream->rcv_nxt, ntohs(pstTcphdr->sent_seq));
	
    
	pstAckFrag->acknum = pstStream->rcv_nxt;
	pstAckFrag->seqnum = pstStream->snd_nxt;
	pstAckFrag->tcp_flags = RTE_TCP_ACK_FLAG;
	pstAckFrag->windows = D_TCP_INITIAL_WINDOW;
	pstAckFrag->hdrlen_off = 0x50;
	pstAckFrag->data = NULL;
	pstAckFrag->length = 0;
	
	rte_ring_mp_enqueue(pstStream->sndbuf, pstAckFrag);

	return 0;
}

static int ng_tcp_send_finpkt(struct tcp_stream *pstStream, struct rte_tcp_hdr *pstTcphdr) 
{
	struct tcp_fragment *pstAckFrag = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
	if (pstAckFrag == NULL) 
		return -1;
	
	memset(pstAckFrag, 0, sizeof(struct tcp_fragment));
	pstAckFrag->dport = pstTcphdr->src_port;
	pstAckFrag->sport = pstTcphdr->dst_port;

	// remote
	
	//printf("tcp_send_ackpkt: %u, %u\n", pstStream->rcv_nxt, ntohs(pstTcphdr->sent_seq));
	
    
	pstAckFrag->acknum = pstStream->rcv_nxt;
	pstAckFrag->seqnum = pstStream->snd_nxt;
	pstAckFrag->tcp_flags = (RTE_TCP_ACK_FLAG | RTE_TCP_FIN_FLAG);
	pstAckFrag->windows = D_TCP_INITIAL_WINDOW;
	pstAckFrag->hdrlen_off = 0x50;
	pstAckFrag->data = NULL;
	pstAckFrag->length = 0;
	
	rte_ring_mp_enqueue(pstStream->sndbuf, pstAckFrag);

	return 0;
}

static int ng_tcp_v6_send_finpkt_2(struct tcp_v6_stream *pstStream, struct rte_tcp_hdr *pstTcphdr) 
{
	struct tcp_fragment *pstAckFrag = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
	if (pstAckFrag == NULL) 
		return -1;
	
	memset(pstAckFrag, 0, sizeof(struct tcp_fragment));
	pstAckFrag->dport = pstTcphdr->src_port;
	pstAckFrag->sport = pstTcphdr->dst_port;

	// remote
	
	//printf("tcp_send_ackpkt: %u, %u\n", pstStream->rcv_nxt, ntohs(pstTcphdr->sent_seq));
	
    
	pstAckFrag->acknum = pstStream->rcv_nxt;
	pstAckFrag->seqnum = pstStream->snd_nxt;
	pstAckFrag->tcp_flags = RTE_TCP_ACK_FLAG | RTE_TCP_FIN_FLAG;
	pstAckFrag->windows = D_TCP_INITIAL_WINDOW;
	pstAckFrag->hdrlen_off = 0x50;
	pstAckFrag->data = NULL;
	pstAckFrag->length = 0;
	
	rte_ring_mp_enqueue(pstStream->sndbuf, pstAckFrag);

    pstStream->status = TCP_STATUS_FIN_WAIT_2;
	return 0;
}

static int ng_tcp_v6_send_finpkt_3(struct tcp_v6_stream *pstStream, struct rte_tcp_hdr *pstTcphdr) 
{
	struct tcp_fragment *pstAckFrag = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
	if (pstAckFrag == NULL) 
		return -1;
	
	memset(pstAckFrag, 0, sizeof(struct tcp_fragment));
	pstAckFrag->dport = pstTcphdr->src_port;
	pstAckFrag->sport = pstTcphdr->dst_port;

	// remote
	
	//printf("tcp_send_ackpkt: %u, %u\n", pstStream->rcv_nxt, ntohs(pstTcphdr->sent_seq));
	
    
	pstAckFrag->acknum = pstStream->rcv_nxt;
	pstAckFrag->seqnum = pstStream->snd_nxt;
	pstAckFrag->tcp_flags = RTE_TCP_ACK_FLAG | RTE_TCP_FIN_FLAG;
	pstAckFrag->windows = D_TCP_INITIAL_WINDOW;
	pstAckFrag->hdrlen_off = 0x50;
	pstAckFrag->data = NULL;
	pstAckFrag->length = 0;
	
	rte_ring_mp_enqueue(pstStream->sndbuf, pstAckFrag);

    pstStream->status = TCP_STATUS_LAST_ACK;
	return 0;
}

static int ng_tcp_send_finreppkt(struct tcp_stream *pstStream, struct rte_tcp_hdr *pstTcphdr, int payloadlen) 
{
    if(pstStream == NULL)
    {
        return 0;
    }
    else
    {
        pthread_mutex_lock(&pstStream->mutex);
    }
	struct tcp_fragment *pstAckFrag = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
	if (pstAckFrag == NULL) 
		return -1;
	
	memset(pstAckFrag, 0, sizeof(struct tcp_fragment));
	pstAckFrag->dport = pstTcphdr->dst_port;
	pstAckFrag->sport = pstTcphdr->src_port;

	// remote
	
	//printf("tcp_send_ackpkt: %u, %u\n", pstStream->rcv_nxt, ntohs(pstTcphdr->sent_seq));
	
    printf("p0 ----- ng_tcp_send_finreppkt\n");
	pstAckFrag->acknum = pstStream->rcv_nxt;
	pstAckFrag->seqnum = pstStream->snd_nxt;
    if(payloadlen > 0)
    {
        pstAckFrag->tcp_flags = RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG | RTE_TCP_FIN_FLAG;
    }
    else{
        pstAckFrag->tcp_flags = RTE_TCP_ACK_FLAG | RTE_TCP_FIN_FLAG;
    }
	
	pstAckFrag->windows = D_TCP_INITIAL_WINDOW;
	pstAckFrag->hdrlen_off = 0x50;

    if(payloadlen > 0)
    {
        uint8_t hdrlen = pstTcphdr->data_off >> 4;
        uint8_t *payload = (uint8_t*)pstTcphdr + hdrlen * 4;
	    pstAckFrag->data = rte_malloc("unsigned char *", payloadlen+1, 0);
	    if (pstAckFrag->data == NULL) 
	    {
		    rte_free(pstAckFrag);
		    return -1;
	    }
        memset(pstAckFrag->data, 0, payloadlen + 1);
	    rte_memcpy(pstAckFrag->data, payload, payloadlen);
	    pstAckFrag->length = payloadlen;
    }
    else
    {
        pstAckFrag->data = NULL;
        pstAckFrag->length = 0;
    }

    pstStream->status = TCP_STATUS_CLOSE_WAIT;
	
	rte_ring_mp_enqueue(pstStream->sndbuf, pstAckFrag);

    pthread_mutex_unlock(&pstStream->mutex);


	return 0;
}

static int ng_tcp_send_reppkt(struct tcp_stream *pstStream, struct rte_tcp_hdr *pstTcphdr, int payloadlen) 
{
	struct tcp_fragment *pstAckFrag = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
	if (pstAckFrag == NULL) 
		return -1;
	
	memset(pstAckFrag, 0, sizeof(struct tcp_fragment));
	pstAckFrag->dport = pstTcphdr->dst_port;
	pstAckFrag->sport = pstTcphdr->src_port;

	// remote
	
	//printf("tcp_send_ackpkt: %u, %u\n", pstStream->rcv_nxt, ntohs(pstTcphdr->sent_seq));
    if(pthread_mutex_trylock(&pstStream->mutex) != 0) return -2;
	
    printf("p0 ----- ng_tcp_send_reppkt to port : %d\n", ntohs(pstStream->sport));
	pstAckFrag->acknum = pstStream->rcv_nxt;
	pstAckFrag->seqnum = pstStream->snd_nxt;
    if(payloadlen > 0)
    {
        pstAckFrag->tcp_flags = RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG;
    }
    else{
        pstAckFrag->tcp_flags = RTE_TCP_ACK_FLAG;
    }
	
	pstAckFrag->windows = D_TCP_INITIAL_WINDOW;
	pstAckFrag->hdrlen_off = 0x50;

	uint8_t hdrlen = pstTcphdr->data_off >> 4;
    uint8_t *payload = (uint8_t*)pstTcphdr + hdrlen * 4;
	pstAckFrag->data = rte_malloc("unsigned char *", payloadlen+1, 0);
	if (pstAckFrag->data == NULL) 
	{
		rte_free(pstAckFrag);
		return -1;
	}
    memset(pstAckFrag->data, 0, payloadlen + 1);
	rte_memcpy(pstAckFrag->data, payload, payloadlen);
	pstAckFrag->length = payloadlen;
	if(pstStream->sndbuf == NULL)
    {
        return 0;
    }
	rte_ring_mp_enqueue(pstStream->sndbuf, pstAckFrag);
    pthread_mutex_unlock(&pstStream->mutex);

	return 0;
}

int tcp_server_process(__attribute__((unused))  void *arg)
{
    int tRxNum;
    int i;
    struct rte_ether_hdr *pstEthHdr;
    struct rte_ipv4_hdr *pstIpHdr;
    struct rte_ipv6_hdr *pstIpv6Hdr;
    struct rte_tcp_hdr *pstTcpHdr;

    while(!force_quit)
    {
        struct rte_mbuf *pstMbuf[1024];
        tRxNum = rte_ring_sc_dequeue_burst(fs_proxyRingIns->proTranCtoSRing, (void**)pstMbuf, D_BURST_SIZE, NULL);
        if(tRxNum <= 0)
			continue;
        
        for(i = 0; i < tRxNum; ++i)
        {
            //printf("recv from CtoSRing\n");
            pstEthHdr = rte_pktmbuf_mtod_offset(pstMbuf[i], struct rte_ether_hdr *, 0);
            if (pstEthHdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6))
            {
                pstIpv6Hdr = rte_pktmbuf_mtod_offset(pstMbuf[i], struct rte_ipv6_hdr *, sizeof(struct rte_ether_hdr));
                if(pstIpv6Hdr->proto != IPPROTO_TCP)
                {
                    printf("no!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
                }
                pstTcpHdr = (struct rte_tcp_hdr *)(pstIpv6Hdr + 1);
                int tcplen = ntohs(pstIpv6Hdr->payload_len);
                uint8_t tcphdrlen = pstTcpHdr->data_off >> 4;
                uint16_t payloadlen = tcplen - tcphdrlen * 4;
                if(payloadlen > 0)
                {
                    char *payload = (char *)(pstTcpHdr + 1);
                    printf("recv HTTP response\n");
                    struct tcp_v6_stream *pstStream = tcp_v6_stream_search_2(pstIpv6Hdr->dst_addr, pstIpv6Hdr->src_addr, pstTcpHdr->dst_port, pstTcpHdr->src_port);
                    if(pstStream == NULL)
                    {
                        printf("client v6 stream no found!\n");
                        continue;
                    }
                    struct tcp_stream *v4Stream = tcp_stream_search(pstStream->v4_dip, pstStream->v4_sip, pstTcpHdr->dst_port, pstTcpHdr->src_port);
                    if(v4Stream == NULL)
                    {
                        printf("server v4 stream no found!\n");
                        continue;
                    }
                    if(pstTcpHdr->tcp_flags & RTE_TCP_PSH_FLAG)  // 要转发回的应答数据包，TCP数据域不为0
	                {
                        if(pstTcpHdr->tcp_flags & RTE_TCP_FIN_FLAG) //关闭连接
                        {
                            //pstStream->status = TCP_STATUS_FIN_WAIT_1;
                            if((pstStream->recv_ac + 1) != ntohl(pstTcpHdr->sent_seq))
                            {
                                printf("exp seq: %u,but recv: %u\n", pstStream->recv_ac + 1, ntohl(pstTcpHdr->sent_seq));
                                ng_tcp_v6_send_ackpkt(pstStream, pstTcpHdr);
                            }
                            else{
                                pstStream->recv_ac = ntohl(pstTcpHdr->sent_seq) + payloadlen - 1;
                                pstStream->rcv_nxt = pstStream->rcv_nxt + payloadlen;
		                        pstStream->snd_nxt = ntohl(pstTcpHdr->recv_ack);
                                //pstStream->rcv_nxt = pstStream->rcv_nxt + payloadlen;
		                        //pstStream->snd_nxt = ntohl(pstTcpHdr->recv_ack);
                                ng_tcp_v6_send_ackpkt(pstStream, pstTcpHdr);
                                //ng_tcp_v6_send_finpkt_3(pstStream, pstTcpHdr);
                                while(ng_tcp_send_reppkt(v4Stream, pstTcpHdr, payloadlen) == -2)
                                {
                                    v4Stream = tcp_stream_search(pstStream->v4_dip, pstStream->v4_sip, pstTcpHdr->dst_port, pstTcpHdr->src_port);
                                    if(v4Stream == NULL)
                                    {
                                        printf("v4 stream free already\n");
                                        break;
                                    }
                                    else continue;
                                }
                            }
                        }
                        else
                        {
                            if((pstStream->recv_ac + 1) != ntohl(pstTcpHdr->sent_seq))
                            {
                                printf("exp seq: %u,but recv: %u\n", pstStream->recv_ac + 1, ntohl(pstTcpHdr->sent_seq));
                                ng_tcp_v6_send_ackpkt(pstStream, pstTcpHdr);
                            }
                            else{
                                pstStream->recv_ac = ntohl(pstTcpHdr->sent_seq) + payloadlen - 1;
                                pstStream->rcv_nxt = pstStream->rcv_nxt + payloadlen;
		                        pstStream->snd_nxt = ntohl(pstTcpHdr->recv_ack);
                                ng_tcp_v6_send_ackpkt(pstStream, pstTcpHdr);
                                while(ng_tcp_send_reppkt(v4Stream, pstTcpHdr, payloadlen) == -2)
                                {
                                    v4Stream = tcp_stream_search(pstStream->v4_dip, pstStream->v4_sip, pstTcpHdr->dst_port, pstTcpHdr->src_port);
                                    if(v4Stream == NULL)
                                    {
                                        printf("v4 stream free already\n");
                                        break;
                                    }
                                    else continue;
                                }
                            }
                        } 
	                }
                }
                else
                {
                    struct tcp_v6_stream *pstStream = tcp_v6_stream_search_2(pstIpv6Hdr->dst_addr, pstIpv6Hdr->src_addr, pstTcpHdr->dst_port, pstTcpHdr->src_port);
                    if(pstStream == NULL)
                    {
                        printf("client v6 stream no found!\n");
                        continue;
                    }
                    struct tcp_stream *v4Stream = tcp_stream_search(pstStream->v4_dip, pstStream->v4_sip, pstTcpHdr->dst_port, pstTcpHdr->src_port);
                    if(v4Stream == NULL)
                    {
                        printf("server v4 stream no found!\n");
                    }
                    if(pstTcpHdr->tcp_flags & RTE_TCP_FIN_FLAG) //关闭连接
                    {
                        if((pstStream->recv_ac + 1) != ntohl(pstTcpHdr->sent_seq))
                        {
                            printf("exp seq: %u,but recv: %u", pstStream->recv_ac + 1, ntohl(pstTcpHdr->sent_seq));
                            ng_tcp_v6_send_ackpkt(pstStream, pstTcpHdr);
                        }
                        else
                        {
                            //pstStream->status = TCP_STATUS_FIN_WAIT_1;
                            pstStream->rcv_nxt = pstStream->rcv_nxt + 1;
		                    pstStream->snd_nxt = ntohl(pstTcpHdr->recv_ack);
                            ng_tcp_v6_send_ackpkt(pstStream, pstTcpHdr);
                            ng_tcp_v6_send_finpkt_3(pstStream, pstTcpHdr);
                            //ng_tcp_send_finreppkt(v4Stream, pstTcpHdr, 0);
                        }
                    }
                    else
                    {
                        // pstStream->rcv_nxt = pstStream->rcv_nxt + payloadlen;
		                pstStream->snd_nxt = ntohl(pstTcpHdr->recv_ack);
                        // ng_tcp_v6_send_ackpkt(pstStream, pstTcpHdr);
                        // ng_tcp_send_reppkt(v4Stream, pstTcpHdr, payloadlen);
                    }
                }
            }
        }
    }
}

int tcp_client_process(__attribute__((unused))  void *arg) 
{
    int tRxNum;
    int i;
    struct rte_ether_hdr *pstEthHdr;
    struct rte_ipv4_hdr *pstIpHdr;
    struct rte_ipv6_hdr *pstIpv6Hdr;
    struct rte_tcp_hdr *pstTcpHdr;
    while(!force_quit)
    {
		struct rte_mbuf *pstMbuf[1024];
        tRxNum = rte_ring_sc_dequeue_burst(fs_proxyRingIns->proTranStoCRing, (void**)pstMbuf, D_BURST_SIZE, NULL);
        if(tRxNum <= 0)
			continue;
        
        for(i = 0; i < tRxNum; ++i)
        {
            //printf("recv from StoCRing\n");
            pstEthHdr = rte_pktmbuf_mtod_offset(pstMbuf[i], struct rte_ether_hdr *, 0);
            if (pstEthHdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))   //IPv4: 0800 
            {
                pstIpHdr = rte_pktmbuf_mtod_offset(pstMbuf[i], struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
                pstTcpHdr = (struct rte_tcp_hdr *)(pstIpHdr + 1);
                int tcplen = ntohs(pstIpHdr->total_length) - sizeof(struct rte_ipv4_hdr);
                uint8_t tcphdrlen = pstTcpHdr->data_off >> 4;
                uint16_t payloadlen = tcplen - tcphdrlen * 4;
                if(payloadlen > 0)
                {
                    char *payload = (char *)(pstTcpHdr + 1);
                    if((KMP(payload, "GET", 0) || KMP(payload, "POST", 0)) >= 0)//转发开启新连接，IP使用IPV6。
                    {
                        int work_node_id = get_work_node_id(payload);
                    
                        if(work_node_id >= D_MAX_WORK_NODE)
                        {
                            printf("NO THIS WORK NODE!!\n");
                            work_node_id = 0;
                            continue;
                        }
                        //printf("worknode = %d\n", work_node_id);
                        //printf("recv HTTP request\n");

                        struct tcp_v6_stream *pstStream = tcp_v6_stream_search(local_ipv6, work_node_ipv6[work_node_id], pstTcpHdr->src_port, pstTcpHdr->dst_port);
                        struct tcp_stream *v4Stream = tcp_stream_search(pstIpHdr->src_addr, pstIpHdr->dst_addr, pstTcpHdr->src_port, pstTcpHdr->dst_port);
                        // printf("get_kind_mss = %d\n",v4Stream->syn_op.kind_mss);
                        // printf("get_kind_sack = %d\n",v4Stream->syn_op.kind_sack);
                        // printf("get_kind_tsecr = %d\n",v4Stream->syn_op.kind_tsecr);
                        // printf("get_kind_nop = %d\n",v4Stream->syn_op.kind_nop);
                        // printf("get_kind_wscale = %d\n",v4Stream->syn_op.kind_wscale);
                        if(pstStream != NULL)
                        {
                            //printf("stream already exist, srcport: %d, status = %d\n", ntohs(pstStream->sport),pstStream->status);
                            if(pstStream->status == TCP_STATUS_ESTABLISHED)
                            {
                                continue;
                                printf("http request retransimition, toport: %d\n", ntohs(pstStream->sport));
                                send_http_request(pstStream);
                            }
                            else if(pstStream->status == TCP_STATUS_CLOSE_WAIT)
                            {
                                continue;
                            }
                            else if(pstStream->status == TCP_STATUS_CLOSED || pstStream->status == TCP_STATUS_SYN_SENT)
                            {
                                continue;
                                fconnect(pstStream->fd, work_node_id, pstTcpHdr, &v4Stream->syn_op);
                            }
                            else
                            {
                                continue;
                            }
                        }
                        
                        else
                        {
                            printf("create new stream\n");
                            int connectfd;
	                        int iRet = -1;
	                        struct sockaddr_in6 servaddr;
                            connectfd = get_fd_frombitmap();
                            pstStream = tcp_v6_stream_create(local_ipv6, work_node_ipv6[work_node_id], pstTcpHdr->src_port, pstTcpHdr->dst_port, payload, payloadlen);
                            pstStream->v4_dip = v4Stream->sip;
                            pstStream->v4_sip = v4Stream->dip;
		                    if (pstStream == NULL) 
			                    return -1;
                            pstStream->fd = connectfd;
                            pstStream->work_node_id = work_node_id;
                            pthread_mutex_lock(&g_pstTcpTbl->mutex_v6);
                            LL_ADD(pstStream, g_pstTcpTbl->tcb_v6_set);
                            pthread_mutex_unlock(&g_pstTcpTbl->mutex_v6);
                            if(pstStream->status == TCP_STATUS_CLOSED)
                            {
                                printf("begin connect\n");
                                fconnect(connectfd, work_node_id, pstTcpHdr, &v4Stream->syn_op);
                            }
                        }
                    }
                }
                else
                {
                    if(pstTcpHdr->tcp_flags & RTE_TCP_FIN_FLAG)
                    {
                        struct tcp_v6_stream *pstStream = tcp_v6_stream_search(local_ipv6, work_node_ipv6[0], pstTcpHdr->src_port, pstTcpHdr->dst_port);
                        struct tcp_stream *v4Stream = tcp_stream_search(pstIpHdr->src_addr, pstIpHdr->dst_addr, pstTcpHdr->src_port, pstTcpHdr->dst_port);
                        v4Stream->rcv_nxt = v4Stream->rcv_nxt + 1;
    		            v4Stream->snd_nxt = ntohl(pstTcpHdr->recv_ack);
    		            ng_tcp_send_ackpkt(v4Stream, pstTcpHdr);
                        ng_tcp_send_finpkt(v4Stream, pstTcpHdr);
                        v4Stream -> status = TCP_STATUS_LAST_ACK;
                        set_fd_frombitmap(v4Stream->fd); 
                        ng_tcp_v6_send_finpkt_1(pstStream, pstTcpHdr);
                        pstStream->status = TCP_STATUS_CLOSE_WAIT;
                    }
                }
			}   
        }
    }
    return 0;
}



static struct arp_table *arp_table_instance(void) 
{
	if (g_pstArpTbl == NULL) 
    {
		g_pstArpTbl = rte_malloc("arp table", sizeof(struct  arp_table), 0);
		if (g_pstArpTbl == NULL) 
			rte_exit(EXIT_FAILURE, "rte_malloc arp table failed\n");
		
		memset(g_pstArpTbl, 0, sizeof(struct arp_table));

		pthread_spin_init(&g_pstArpTbl->spinlock, PTHREAD_PROCESS_SHARED);
	}

	return g_pstArpTbl;
}

unsigned char* ng_get_dst_macaddr(uint32_t dip) 
{
	struct arp_entry *pstIter;
	struct arp_table *pstTbl = arp_table_instance();

	int count = pstTbl->count;
	
	for (pstIter = pstTbl->entries; count-- != 0 && pstIter != NULL; pstIter = pstIter->next) 
    {
		if (dip == pstIter->ip) 
			return pstIter->hwaddr;
	}

	return NULL;
}

int ng_arp_entry_insert(uint32_t ip, unsigned char *mac)
{
    struct arp_table *pstTbl = arp_table_instance();
    struct arp_entry *pstEntry = NULL;
    unsigned char *pstHwaddr = NULL;

    pstHwaddr = ng_get_dst_macaddr(ip);
    if(pstHwaddr == NULL)
    {
        pstEntry = rte_malloc("arp_entry", sizeof(struct arp_entry), 0);
		if (pstEntry) 
        {
			memset(pstEntry, 0, sizeof(struct arp_entry));

			pstEntry->ip = ip;
			rte_memcpy(pstEntry->hwaddr, mac, RTE_ETHER_ADDR_LEN);
			pstEntry->type = 0;

			pthread_spin_lock(&pstTbl->spinlock);
			LL_ADD(pstEntry, pstTbl->entries);
			pstTbl->count ++;
			pthread_spin_unlock(&pstTbl->spinlock);
		}
        return 1;
    }

    return 0;
}

static int tcp_handle_listen(struct tcp_stream *pstStream, struct rte_tcp_hdr *pstTcphdr, 
                                struct rte_ipv4_hdr *pstIphdr, struct syn_tcp_option *synopt) 
{
    if (pstTcphdr->tcp_flags & RTE_TCP_SYN_FLAG)  
    {
        struct in_addr addr;
        uint16_t tcp_opt_len = ((pstTcphdr -> data_off) >> 4) * 4 - sizeof(struct rte_tcp_hdr);
        //printf("SYN tcpoptlen = %d\n", tcp_opt_len);
        addr.s_addr = pstIphdr -> src_addr;
        //printf("TCP---src: %s:%u,", inet_ntoa(addr), rte_cpu_to_be_16(pstTcphdr -> src_port));
        addr.s_addr = pstIphdr -> dst_addr;
        //printf("dst: %s:%u, tcpdataoff:%u\n", inet_ntoa(addr), rte_cpu_to_be_16(pstTcphdr -> dst_port), ((pstTcphdr -> data_off) >> 4) * 4);
        if (pstStream->status == TCP_STATUS_LISTEN)
        {
            struct tcp_stream *pstSyn = tcp_stream_create(pstIphdr->src_addr, pstIphdr->dst_addr, 
                                                            pstTcphdr->src_port, pstTcphdr->dst_port);
			pthread_mutex_lock(&g_pstTcpTbl->mutex_v4);
            LL_ADD(pstSyn, g_pstTcpTbl->tcb_set);
            pthread_mutex_unlock(&g_pstTcpTbl->mutex_v4);
            pstSyn->syn_op = *synopt;
            // printf("kind_mss = %d\n",pstSyn->syn_op.kind_mss);
            // printf("kind_sack = %d\n",pstSyn->syn_op.kind_sack);
            // printf("kind_tsecr = %d\n",pstSyn->syn_op.kind_tsecr);
            // printf("kind_nop = %d\n",pstSyn->syn_op.kind_nop);
            // printf("kind_wscale = %d\n",pstSyn->syn_op.kind_wscale);
            pstSyn->syn_op.mss_option_value = ntohs(1440);

            struct tcp_fragment *pstFragment = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
			if (pstFragment == NULL) 
                return -1;
			memset(pstFragment, 0, sizeof(struct tcp_fragment));

            pstFragment->sport = pstTcphdr->dst_port;
			pstFragment->dport = pstTcphdr->src_port;

            struct in_addr addr;
			addr.s_addr = pstSyn->sip;
			printf("tcp ---> src: %s:%d \n", inet_ntoa(addr), ntohs(pstTcphdr->src_port));

			//addr.s_addr = pstSyn->dip;
			//printf("  ---> dst: %s:%d \n", inet_ntoa(addr), ntohs(pstTcphdr->dst_port));

            pstFragment->seqnum = pstSyn->snd_nxt;
			pstFragment->acknum = ntohl(pstTcphdr->sent_seq) + 1;
			pstSyn->rcv_nxt = pstFragment->acknum;
			
			pstFragment->tcp_flags = (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG);
			pstFragment->windows = D_TCP_INITIAL_WINDOW;
			pstFragment->hdrlen_off = 0x50;
			
			pstFragment->data = NULL;
			pstFragment->length = 0;

			rte_ring_mp_enqueue(pstSyn->sndbuf, pstFragment);
			
			pstSyn->status = TCP_STATUS_SYN_RCVD;
        }
    }

    return 0;
}

static int fconnect_third_handle(struct tcp_v6_stream *pstStream, struct rte_tcp_hdr *pstTcpHdr)
{
    struct tcp_fragment *pstFragment = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
	if (pstFragment == NULL) 
        return -1;
	memset(pstFragment, 0, sizeof(struct tcp_fragment));

    pstFragment->sport = pstStream->sport;
	pstFragment->dport = pstStream->dport;

    pstFragment->seqnum = pstStream->snd_nxt;
    //pstStream->snd_nxt = (rte_be32_t)1;

	pstFragment->acknum = ntohl(pstTcpHdr->sent_seq) + 1;
	pstStream->rcv_nxt = pstFragment->acknum;
	
	pstFragment->tcp_flags = RTE_TCP_ACK_FLAG;
	pstFragment->windows = D_TCP_INITIAL_WINDOW;
	pstFragment->hdrlen_off = 0x50;
	
	pstFragment->data = NULL;
	pstFragment->length = 0;
    //printf("ready enqueue\n");
	rte_ring_sp_enqueue(pstStream->sndbuf, pstFragment);
    pstStream->status = TCP_STATUS_ESTABLISHED;
    printf("connect done,sport: %d\n",ntohs(pstStream->sport));
    return 0;
}

static int tcp_handle_syn_rcvd(struct tcp_stream *pstStream, struct rte_tcp_hdr *pstTcphdr)
{
	if (pstTcphdr->tcp_flags & RTE_TCP_ACK_FLAG) 
	{
		if (pstStream->status == TCP_STATUS_SYN_RCVD) 
		{
			uint32_t acknum = ntohl(pstTcphdr->recv_ack);
			// if (acknum == pstStream->snd_nxt + 1) 
			// {
			// 	printf("ack response success!\n");
			// }
			// else
			// {
			// 	printf("ack response error! \n");
			// }

			pstStream->status = TCP_STATUS_ESTABLISHED;

			// accept
			struct tcp_stream *pstListener = tcp_stream_search(0, htonl((in_addr_t)0xC0A80A64), 0, pstStream->dport);
			if (pstListener == NULL) 
			{
				rte_exit(EXIT_FAILURE, "tcp_stream_search failed\n");
			}

			// pthread_mutex_lock(&pstListener->mutex);
			// pthread_cond_signal(&pstListener->cond);   // 唤醒accept中的等待
			// pthread_mutex_unlock(&pstListener->mutex);

#if ENABLE_SINGLE_EPOLL

			struct ng_tcp_table *table = tcpInstance();
			epoll_event_callback(table->ep, listener->fd, EPOLLIN);
#endif
		}
	}

	return 0;
}

// static int flow_thread(void *arg)
// {
//     struct tcp_v6_stream *pstStream = (struct tcp_v6_stream *)arg;
//     int length = 0;
//     char buff[D_TCP_BUFFER_SIZE] = {0};
//     while(!force_quit)
//     {
//         struct tcp_fragment *pstFragment = NULL;
//         int iRcvNum = 0;

//         // 等待接收队列中的数据到来
//         pthread_mutex_lock(&pstStream->mutex);
// 		while ((iRcvNum = rte_ring_mc_dequeue(pstStream->rcvbuf, (void **)&pstFragment)) < 0) 
//         {
// 			pthread_cond_wait(&pstStream->cond, &pstStream->mutex);
// 		}
// 		pthread_mutex_unlock(&pstStream->mutex);

//         if (pstFragment->length > D_TCP_BUFFER_SIZE) 
//         {
//             rte_memcpy(buff, pstFragment->data, D_TCP_BUFFER_SIZE);

// 			uint32_t i = 0;
// 			for(i = 0; i < pstFragment->length - D_TCP_BUFFER_SIZE; i ++) 
//             {
// 				pstFragment->data[i] = pstFragment->data[D_TCP_BUFFER_SIZE + i];
// 			}
// 			pstFragment->length = pstFragment->length - D_TCP_BUFFER_SIZE;
// 			length = pstFragment->length;

// 			rte_ring_mp_enqueue(pstStream->rcvbuf, pstFragment);
//         }
//         else if(pstFragment->length == 0)
//         {
//             rte_free(pstFragment);
// 			return 0;
//         }
//         else
//         {
//             rte_memcpy(buff, pstFragment->data, pstFragment->length);
// 			length = pstFragment->length;

// 			rte_free(pstFragment->data);
// 			pstFragment->data = NULL;

// 			rte_free(pstFragment);
//         }
//         if (length > 0) 
// 		{
// 			printf("P1---recv: %s\n", buff);
// 		} 
//     }
// }


// static int tcp_handle_established(struct tcp_stream *pstStream, struct rte_tcp_hdr *pstTcphdr, int iTcplen) 
// {
// 	if (pstTcphdr->tcp_flags & RTE_TCP_SYN_FLAG)  // 异常：收到对端的SYN重传包
// 	{
// 		printf("RTE_TCP_SYN_FLAG\n");
// 	} 
// 	if(pstTcphdr->tcp_flags & RTE_TCP_PSH_FLAG)  // 收到对端的数据包，TCP数据域不为0
// 	{
// 		ng_tcp_enqueue_recvbuffer(pstStream, pstTcphdr, iTcplen);
		
// #if ENABLE_SINGLE_EPOLL
// 		struct ng_tcp_table *table = tcpInstance();
// 		epoll_event_callback(table->ep, stream->fd, EPOLLIN);
// #endif

// 		uint8_t hdrlen = pstTcphdr->data_off >> 4;
// 		int payloadlen = iTcplen - hdrlen * 4;
		
// 		pstStream->rcv_nxt = ntohl(pstStream->rcv_nxt + payloadlen);
// 		pstStream->snd_nxt = ntohl(pstTcphdr->recv_ack);
		
// 		ng_tcp_send_ackpkt(pstStream, pstTcphdr);
// 	}
// 	// if(pstTcphdr->tcp_flags & RTE_TCP_ACK_FLAG)  // 异常：收到对端的ACK重传包
// 	// {
// 	// 	printf("RTE_TCP_ACK_FLAG\n");
// 	// }
// 	if (pstTcphdr->tcp_flags & RTE_TCP_FIN_FLAG)  // 对端关闭连接
// 	{
// 		printf("RTE_TCP_FIN_FLAG\n");
// 		pstStream->status = TCP_STATUS_CLOSE_WAIT;

// 		ng_tcp_enqueue_recvbuffer(pstStream, pstTcphdr, pstTcphdr->data_off >> 4);

// #if ENABLE_SINGLE_EPOLL

// 		struct ng_tcp_table *table = tcpInstance();
// 		epoll_event_callback(table->ep, stream->fd, EPOLLIN);

// #endif
// 		// send ack ptk
// 		pstStream->rcv_nxt = ntohl(pstStream->rcv_nxt + 1);
// 		pstStream->snd_nxt = ntohl(pstTcphdr->recv_ack);
		
// 		ng_tcp_send_ackpkt(pstStream, pstTcphdr);
// 	}

// 	return 0;
// }

static int tcp_handle_close_wait(struct tcp_stream *stream, struct rte_tcp_hdr *tcphdr) 
{
	if (tcphdr->tcp_flags & RTE_TCP_FIN_FLAG) 
	{ 
		if (stream->status == TCP_STATUS_CLOSE_WAIT) 
		{	
            //printf("v4 connect finish!!!\n");
    		stream->rcv_nxt = stream->rcv_nxt + 1;
    		stream->snd_nxt = ntohl(tcphdr->recv_ack);
    		ng_tcp_send_ackpkt(stream, tcphdr);
            stream->status = TCP_STATUS_TIME_WAIT;
            finish_v4_fd[stream->fd] = 1;
            // usleep(500000);
            // LL_REMOVE(stream, g_pstTcpTbl->tcb_set);

			// rte_ring_free(stream->sndbuf);
			// rte_ring_free(stream->rcvbuf);

			// rte_free(stream);
		}
	}
    else if (tcphdr->tcp_flags & RTE_TCP_RST_FLAG)
    {
        //printf("v4 connect finish!!!\n");
        stream->status = TCP_STATUS_TIME_WAIT;
        finish_v4_fd[stream->fd] = 1;
    }
    else{
        stream->rcv_nxt = stream->rcv_nxt;
    	stream->snd_nxt = ntohl(tcphdr->recv_ack);
    }
	
	return 0;
}

static int tcp_v6_handle_close_wait(struct tcp_v6_stream *stream, struct rte_tcp_hdr *tcphdr) 
{
	if (tcphdr->tcp_flags & RTE_TCP_FIN_FLAG) 
	{ 
		if (stream->status == TCP_STATUS_CLOSE_WAIT) 
		{	
            //printf("v6 connect finish!!!\n");
    		stream->rcv_nxt = stream->rcv_nxt + 1;
    		stream->snd_nxt = ntohl(tcphdr->recv_ack);
		
    		ng_tcp_v6_send_ackpkt(stream, tcphdr);
            stream->status = TCP_STATUS_TIME_WAIT;
            finish_v6_fd[stream->fd] = 1;
            // usleep(500000);
            // LL_REMOVE(stream, g_pstTcpTbl->tcb_set);

			// rte_ring_free(stream->sndbuf);
			// rte_ring_free(stream->rcvbuf);

			// rte_free(stream);
		}
	}
    else if (tcphdr->tcp_flags & RTE_TCP_RST_FLAG)
    {
        //printf("v6 connect finish!!!\n");
        stream->status = TCP_STATUS_TIME_WAIT;
        finish_v6_fd[stream->fd] = 1;
    }
    else{
        stream->rcv_nxt = stream->rcv_nxt;
    	stream->snd_nxt = ntohl(tcphdr->recv_ack);
    }
	
	return 0;
}

static int tcp_handle_last_ack(struct tcp_stream *stream, struct rte_tcp_hdr *tcphdr) 
{
	if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG || tcphdr->tcp_flags & RTE_TCP_RST_FLAG) 
	{
		if (stream->status == TCP_STATUS_LAST_ACK) 
		{
			stream->status = TCP_STATUS_CLOSED;
            //finish_v4_fd[stream->fd] = 1;
			printf("lsack~v4 connect finish!!!,port: %d\n", ntohs(stream->sport));
            pthread_mutex_lock(&g_pstTcpTbl->mutex_v4);
			LL_REMOVE(stream, g_pstTcpTbl->tcb_set);
            pthread_mutex_unlock(&g_pstTcpTbl->mutex_v4);
            while(pthread_mutex_trylock(&stream->mutex) != 0)
            {
            }
			rte_ring_free(stream->sndbuf);
            stream->sndbuf = NULL;
            pthread_mutex_unlock(&stream->mutex);
			//rte_ring_free(stream->rcvbuf);
            while(pthread_mutex_trylock(&stream->mutex) != 0)
            {
            }
			rte_free(stream);
            stream = NULL;
		}
	}

	return 0;
}

static int tcp_v6_handle_last_ack(struct tcp_v6_stream *stream, struct rte_tcp_hdr *tcphdr) 
{
	if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG || tcphdr->tcp_flags & RTE_TCP_RST_FLAG) 
	{
		if (stream->status == TCP_STATUS_LAST_ACK) 
		{
			stream->status = TCP_STATUS_CLOSED;
            //finish_v6_fd[stream->fd] = 1;
			printf("lsack~v6 connect finish!!!,port = %d\n",ntohs(stream->sport));
			pthread_mutex_lock(&g_pstTcpTbl->mutex_v6);
			LL_REMOVE(stream, g_pstTcpTbl->tcb_v6_set);
            pthread_mutex_unlock(&g_pstTcpTbl->mutex_v6);
            while(pthread_mutex_trylock(&stream->mutex) != 0)
            {
            }
			rte_ring_free(stream->sndbuf);
            stream->sndbuf = NULL;
			//rte_ring_free(stream->rcvbuf);
            rte_free(stream->request_payload);
            pthread_mutex_unlock(&stream->mutex);
            while(pthread_mutex_trylock(&stream->mutex) != 0)
            {
            }
			rte_free(stream);
            stream = NULL;
		}
	}

	return 0;
}


int tcp_process(struct rte_mbuf *pstTcpMbuf) 
{
    struct rte_ipv4_hdr *pstIpHdr;
    struct rte_tcp_hdr *pstTcpHdr;
    struct tcp_stream *pstTcpStream;
    struct syn_tcp_option *syn_opt;
    unsigned short usOldTcpCkSum;
    unsigned short usNewTcpCkSum;
    pstIpHdr = rte_pktmbuf_mtod_offset(pstTcpMbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    pstTcpHdr = (struct rte_tcp_hdr *)(pstIpHdr + 1);

    // 校验和
    // usOldTcpCkSum = pstTcpHdr->cksum;
    // pstTcpHdr->cksum = 0;
    // usNewTcpCkSum = rte_ipv4_udptcp_cksum(pstIpHdr, pstTcpHdr);
    // if (usOldTcpCkSum != usNewTcpCkSum) 
    // { 
	// 	printf("cksum: %x, tcp cksum: %x\n", usOldTcpCkSum, usNewTcpCkSum);
	// 	rte_pktmbuf_free(pstTcpMbuf);
	// 	return -1;
	// }

	// 搜索涵盖了半连接队列和全连接队列
	// 搜索的stream，根据status状态调用对应处理函数
    pstTcpStream = tcp_stream_search(pstIpHdr->src_addr, pstIpHdr->dst_addr, 
        pstTcpHdr->src_port, pstTcpHdr->dst_port);
    if (pstTcpStream == NULL) 
    { 
        puts("no tcb create!");
        printf("pstTcpHdr->dst_port: %d\n", pstTcpHdr->dst_port);
		rte_pktmbuf_free(pstTcpMbuf);
		return -2;
	}

    switch(pstTcpStream->status)
    {
        case TCP_STATUS_CLOSED: //client 
			break;
			
		case TCP_STATUS_LISTEN: // server
            syn_opt = (struct syn_tcp_option *)(pstTcpHdr + 1);
			tcp_handle_listen(pstTcpStream, pstTcpHdr, pstIpHdr, syn_opt);
			break;

		case TCP_STATUS_SYN_RCVD: // server
			tcp_handle_syn_rcvd(pstTcpStream, pstTcpHdr);
			break;

		case TCP_STATUS_SYN_SENT: // client
			break;

		case TCP_STATUS_ESTABLISHED:  // server | client
		{ 
            int tcplen = ntohs(pstIpHdr->total_length) - sizeof(struct rte_ipv4_hdr);
            uint8_t hdrlen = pstTcpHdr->data_off >> 4;
		    int payloadlen = tcplen - hdrlen * 4;
            if((pstTcpHdr->tcp_flags & RTE_TCP_FIN_FLAG) && payloadlen == 0)
            {
                pstTcpStream->rcv_nxt = pstTcpStream->rcv_nxt + 1;
    		    pstTcpStream->snd_nxt = ntohl(pstTcpHdr->recv_ack);
                ng_tcp_send_ackpkt(pstTcpStream, pstTcpHdr);
                ng_tcp_send_finpkt(pstTcpStream, pstTcpHdr);
                pstTcpStream -> status = TCP_STATUS_LAST_ACK;
            }
            else if ((pstTcpHdr->tcp_flags & RTE_TCP_ACK_FLAG) && payloadlen == 0)
            {
                pstTcpStream->snd_nxt = ntohl(pstTcpHdr->recv_ack);
            }
            else
            {
                rte_ring_sp_enqueue_burst(fs_proxyRingIns->proTranStoCRing, (void**)&pstTcpMbuf, 1, NULL);
                if(pstTcpStream->recv_ac == 0 | pstTcpStream->recv_ac != pstTcpHdr->sent_seq)
                {
                    pstTcpStream->recv_ac = pstTcpHdr->sent_seq;
                    pstTcpStream->rcv_nxt = pstTcpStream->rcv_nxt + payloadlen;
		            pstTcpStream->snd_nxt = ntohl(pstTcpHdr->recv_ack);
                }
                // pstTcpStream->rcv_nxt = pstTcpStream->rcv_nxt + payloadlen;
		        // pstTcpStream->snd_nxt = ntohl(pstTcpHdr->recv_ack);
            }
			//tcp_handle_established(pstTcpStream, pstTcpHdr, tcplen);
			break;
		}
		case TCP_STATUS_FIN_WAIT_1: //  ~client
			break;
			
		case TCP_STATUS_FIN_WAIT_2: // ~client
			break;
			
		case TCP_STATUS_CLOSING: // ~client
			break;
			
		case TCP_STATUS_TIME_WAIT: // ~client
			break;

		case TCP_STATUS_CLOSE_WAIT: // ~server
			tcp_handle_close_wait(pstTcpStream, pstTcpHdr);
			break;
			
		case TCP_STATUS_LAST_ACK:  // ~server
			tcp_handle_last_ack(pstTcpStream, pstTcpHdr);
			break;
    }
    rte_pktmbuf_free(pstTcpMbuf);
    return 0;
}

static int ng_encode_arp_pkt(unsigned char *msg, uint16_t opcode, unsigned char *dst_mac, 
    uint32_t sip, uint32_t dip) 
{
    struct rte_ether_hdr *pstEth = NULL;
    struct rte_arp_hdr *pstArp = NULL;
    unsigned char aucMac[RTE_ETHER_ADDR_LEN] = {0x0};

    // eth
    pstEth = (struct rte_ether_hdr*)msg;
    rte_memcpy(pstEth->src_addr.addr_bytes, &l2fwd_ports_eth_addr[2], RTE_ETHER_ADDR_LEN);
    if (!strncmp((const char *)dst_mac, (const char *)g_aucDefaultArpMac, RTE_ETHER_ADDR_LEN)) 
    {
		rte_memcpy(pstEth->dst_addr.addr_bytes, aucMac, RTE_ETHER_ADDR_LEN);
	} 
    else
    {
		rte_memcpy(pstEth->dst_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
	}
    pstEth->ether_type = htons(RTE_ETHER_TYPE_ARP);

    // arp
    pstArp = (struct rte_arp_hdr *)(pstEth + 1);
    pstArp->arp_hardware = htons(1);                    // 硬件类型：1 以太网
    pstArp->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);  // 协议类型：0x0800 IP地址
    pstArp->arp_hlen = RTE_ETHER_ADDR_LEN;              // 硬件地址长度：6
    pstArp->arp_plen = sizeof(uint32_t);                // 协议地址长度：4
    pstArp->arp_opcode = htons(opcode);                 // OP

    rte_memcpy(pstArp->arp_data.arp_sha.addr_bytes, &l2fwd_ports_eth_addr[2], RTE_ETHER_ADDR_LEN);
	rte_memcpy(pstArp->arp_data.arp_tha.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);

	pstArp->arp_data.arp_sip = sip;
	pstArp->arp_data.arp_tip = dip;
	
	return 0;
}

struct rte_mbuf *ng_send_arp(struct rte_mempool *mbuf_pool, uint16_t opcode, unsigned char *dst_mac, 
                                uint32_t sip, uint32_t dip) 
{
	const unsigned int uiTotalLen = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
    unsigned char *pucPktData;

	struct rte_mbuf *pstMbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!pstMbuf) 
		rte_exit(EXIT_FAILURE, "ng_send_arp rte_pktmbuf_alloc\n");

	pstMbuf->pkt_len = uiTotalLen;
	pstMbuf->data_len = uiTotalLen;

	pucPktData = rte_pktmbuf_mtod(pstMbuf, unsigned char *);
	ng_encode_arp_pkt(pucPktData, opcode, dst_mac, sip, dip);

	return pstMbuf;
}

static int ng_encode_tcp_apppkt(uint8_t *msg, uint32_t sip, uint32_t dip,
	uint8_t *srcmac, uint8_t *dstmac, struct tcp_fragment *fragment, unsigned int total_len) 
{
	struct rte_ether_hdr *pstEth;
	struct rte_ipv4_hdr *pstIp;
	struct rte_tcp_hdr *pstTcp;

	// 1 ethhdr
	pstEth = (struct rte_ether_hdr *)msg;
	rte_memcpy(pstEth->src_addr.addr_bytes, srcmac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(pstEth->dst_addr.addr_bytes, dstmac, RTE_ETHER_ADDR_LEN);
	pstEth->ether_type = htons(RTE_ETHER_TYPE_IPV4);
	
	// 2 iphdr 
	pstIp = (struct rte_ipv4_hdr *)(pstEth + 1);
	pstIp->version_ihl = 0x45;
	pstIp->type_of_service = 0;
	pstIp->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
	pstIp->packet_id = 0;
	pstIp->fragment_offset = 0;
	pstIp->time_to_live = 64; // ttl = 64
	pstIp->next_proto_id = IPPROTO_TCP;
	pstIp->src_addr = sip;
	pstIp->dst_addr = dip;
	pstIp->hdr_checksum = 0;
	pstIp->hdr_checksum = rte_ipv4_cksum(pstIp);

	// 3 tcphdr 
	pstTcp = (struct rte_tcp_hdr *)(pstIp + 1);
	pstTcp->src_port = fragment->sport;
	pstTcp->dst_port = fragment->dport;
	pstTcp->sent_seq = htonl(fragment->seqnum);
	pstTcp->recv_ack = htonl(fragment->acknum);
	pstTcp->data_off = fragment->hdrlen_off;
	pstTcp->rx_win = fragment->windows;
	pstTcp->tcp_urp = fragment->tcp_urp;
	pstTcp->tcp_flags = fragment->tcp_flags;
	if (fragment->data != NULL) 
	{
		uint8_t *payload = (uint8_t*)(pstTcp + 1) + fragment->optlen * sizeof(uint32_t);
		rte_memcpy(payload, fragment->data, fragment->length);
	}
	pstTcp->cksum = 0;
	pstTcp->cksum = rte_ipv4_udptcp_cksum(pstIp, pstTcp);

	return 0;
}

static struct rte_mbuf * ng_tcp_pkt(struct rte_mempool *mbuf_pool, uint32_t sip, uint32_t dip,
	uint8_t *srcmac, uint8_t *dstmac, struct tcp_fragment *fragment) 
{
	unsigned int uiTotalLen;
	struct rte_mbuf *pstMbuf;
    unsigned char *pucPktData;

	uiTotalLen = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr) + 
							fragment->optlen * sizeof(uint32_t) + fragment->length;  
	
	pstMbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!pstMbuf) 
		rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
	
	pstMbuf->pkt_len = uiTotalLen;
    pstMbuf->data_len = uiTotalLen;
    pucPktData = rte_pktmbuf_mtod(pstMbuf, unsigned char*);

	ng_encode_tcp_apppkt(pucPktData, sip, dip, srcmac, dstmac, fragment, uiTotalLen);

	return pstMbuf;
}

int tcp_out(struct rte_mempool *pstMbufPool) 
{
	struct tcp_table *pstTable = tcpInstance();
	struct tcp_stream *pstStream = NULL;
	for(pstStream = pstTable->tcb_set; pstStream != NULL; pstStream = pstStream->next)
	{
        if(pthread_mutex_trylock(&pstStream->mutex) != 0) return 0;
		if(pstStream->sndbuf == NULL)
        {
            pthread_mutex_unlock(&pstStream->mutex);
            continue;
        }
			
		struct tcp_fragment *pstFragment = NULL;		
		int iSendCnt = rte_ring_mc_dequeue(pstStream->sndbuf, (void**)&pstFragment);
		if (iSendCnt < 0) 
        {
            pthread_mutex_unlock(&pstStream->mutex);
            continue;
        }

		// struct in_addr addr;
		// addr.s_addr = pstStream->sip;
        
		//printf("tcp_out_p0 ---> dst: %s:%d \n", inet_ntoa(addr), ntohs(pstFragment->dport));

		//uint8_t *dstmac = ng_get_dst_macaddr(pstStream->sip); // 这里的源ip指的是对端ip
        uint8_t *dstmac = clientMAC;
		if (dstmac == NULL)  // 先广播发个arp包确定对端mac地址 
		{
			printf("ng_send_arp\n");
			struct rte_mbuf *pstArpbuf = ng_send_arp(pstMbufPool, RTE_ARP_OP_REQUEST, g_aucDefaultArpMac, 
				pstStream->dip, pstStream->sip);

			rte_ring_mp_enqueue_burst(g_pstRingIns->pstOutRing, (void **)&pstArpbuf, 1, NULL);

			rte_ring_mp_enqueue(pstStream->sndbuf, pstFragment);  // 将取出的数据再次放入队列
		} 
		else 
		{
            if(pstStream->sip == 0)
            {
                rte_free(pstFragment);
                pthread_mutex_unlock(&pstStream->mutex);
                continue;
            }
			struct rte_mbuf *pstTcpBuf = ng_tcp_pkt(pstMbufPool, pstStream->dip, pstStream->sip, 
												pstStream->localmac, dstmac, pstFragment);

			rte_ring_mp_enqueue_burst(g_pstRingIns->pstOutRing, (void **)&pstTcpBuf, 1, NULL);

			if (pstFragment->data != NULL)
				rte_free(pstFragment->data);
			
			rte_free(pstFragment);
		}
        pthread_mutex_unlock(&pstStream->mutex);
	}

    return 0;
}

static int pkt_process(void *arg)
{
    struct rte_mempool *pstMbufPool;
    int iRxNum;
	int i;
	struct rte_ether_hdr *pstEthHdr;
    struct rte_ipv4_hdr *pstIpHdr;

    pstMbufPool = (struct rte_mempool *)arg;
    while(!force_quit)
    {
		struct rte_mbuf *pstMbuf[1024];
        iRxNum = rte_ring_mc_dequeue_burst(g_pstRingIns->pstInRing, (void**)pstMbuf, D_BURST_SIZE, NULL);
        
        if(iRxNum <= 0)
        {
            //tcp_out(pstMbufPool);
            continue;
        }
			
        
        for(i = 0; i < iRxNum; ++i)
        {
            pstEthHdr = rte_pktmbuf_mtod_offset(pstMbuf[i], struct rte_ether_hdr *, 0);
            if (pstEthHdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))   //IPv4: 0800 
            {
                pstIpHdr = rte_pktmbuf_mtod_offset(pstMbuf[i], struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
                
				// 维护一个arp表
				ng_arp_entry_insert(pstIpHdr->src_addr, pstEthHdr->src_addr.addr_bytes);
                if(pstIpHdr->next_proto_id == IPPROTO_TCP)  // tcp
                {
                    // printf("tcp_process ---\n");
					tcp_process(pstMbuf[i]);
                }
				else
				{
                    continue;
					//rte_kni_tx_burst(g_pstKni, pstMbuf, iRxNum);
					// printf("tcp/udp --> rte_kni_handle_request\n");
				}
            }
			else 
			{
				// ifconfig vEth0 192.168.181.169 up
				//rte_kni_tx_burst(g_pstKni, pstMbuf, iRxNum);
				// printf("ip --> rte_kni_handle_request\n");
                continue;
			}   
        }

		//rte_kni_handle_request(g_pstKni);

        // to send
        //*udp_out(pstMbufPool);
        //tcp_out(pstMbufPool);
    }
    return 0;
}

static int faas_process(void *arg)
{
    struct rte_mempool *pstMbufPool;
    int iRxNum;
	int i;
	struct rte_ether_hdr *pstEthHdr;
    struct rte_ipv6_hdr *pstIpHdr;
    struct rte_tcp_hdr *pstTcpHdr;
    unsigned short usOldTcpCkSum;
    unsigned short usNewTcpCkSum;
    struct tcp_v6_stream *pstStream;

    pstMbufPool = (struct rte_mempool *)arg;

    while(!force_quit)
    {

        struct rte_mbuf *pstMbuf[1024];
        iRxNum = rte_ring_mc_dequeue_burst(fs_proxyRingIns->proInRing, (void**)pstMbuf, D_BURST_SIZE, NULL);
        
        if(iRxNum <= 0)
        {
            //tcp_v6_out(pstMbufPool);
            continue;
        }
			
        for(i = 0; i < iRxNum; ++i)
        {
            pstEthHdr = rte_pktmbuf_mtod_offset(pstMbuf[i], struct rte_ether_hdr *, 0);
            pstIpHdr = rte_pktmbuf_mtod_offset(pstMbuf[i], struct rte_ipv6_hdr *, sizeof(struct rte_ether_hdr));
            pstTcpHdr = (struct rte_tcp_hdr *)(pstIpHdr + 1);
            //校验和
            // usOldTcpCkSum = pstTcpHdr->cksum;
            // pstTcpHdr->cksum = 0;
            // usNewTcpCkSum = rte_ipv6_udptcp_cksum(pstIpHdr, pstTcpHdr);
            // if (usOldTcpCkSum != usNewTcpCkSum) 
            // { 
		    //     printf("cksum: %x, tcp cksum: %x\n", usOldTcpCkSum, usNewTcpCkSum);
		    //     rte_pktmbuf_free(pstMbuf[i]);
		    //     return -1;
	        // }
            
            pstStream = tcp_v6_stream_search_2(pstIpHdr->dst_addr, pstIpHdr->src_addr, pstTcpHdr->dst_port, pstTcpHdr->src_port);
            if (pstStream == NULL) 
            { 
                puts("no v6tcb create!");
		        rte_pktmbuf_free(pstMbuf[i]);
		        continue;
	        }
            switch(pstStream->status)
            {
                case TCP_STATUS_CLOSED: //client 
			        break;

                case TCP_STATUS_SYN_SENT: // client
                    pstStream->recv_ac = ntohl(pstTcpHdr->sent_seq);
                    printf("recv seq: %u, next exp seq: %u\n", ntohl(pstTcpHdr->sent_seq), pstStream->recv_ac + 1);
                    fconnect_third_handle(pstStream, pstTcpHdr);
                    pstStream->snd_nxt++;
                    send_http_request(pstStream);
                    pstStream->snd_nxt--;
			        break;
                case TCP_STATUS_ESTABLISHED: // client
                    if(pstTcpHdr->tcp_flags & RTE_TCP_SYN_FLAG)
                    {
                        pstStream->recv_ac = pstTcpHdr->sent_seq;
                        printf("recv seq: %u, next exp seq: %u\n", pstTcpHdr->sent_seq, pstStream->recv_ac);
                        fconnect_third_handle(pstStream, pstTcpHdr);
                        pstStream->snd_nxt++;
                        send_http_request(pstStream);
                        pstStream->snd_nxt--;
                    }
                    else
                    {
                        rte_ring_sp_enqueue_burst(fs_proxyRingIns->proTranCtoSRing, (void**)&pstMbuf, 1, NULL);
                    }
                    break;
                case TCP_STATUS_FIN_WAIT_1: 
                    pstStream->rcv_nxt = pstStream->rcv_nxt + 1;
		            pstStream->snd_nxt = ntohl(pstTcpHdr->recv_ack);
                    ng_tcp_v6_send_finpkt_2(pstStream, pstTcpHdr);
                    break;
                case TCP_STATUS_FIN_WAIT_2:
                    LL_REMOVE(pstStream, g_pstTcpTbl->tcb_v6_set);

			        rte_ring_free(pstStream->sndbuf);
			        //rte_ring_free(pstStream->rcvbuf);

			        rte_free(pstStream);
                    break;
                case TCP_STATUS_CLOSE_WAIT:
                    tcp_v6_handle_close_wait(pstStream, pstTcpHdr);
                case TCP_STATUS_TIME_WAIT:
                    break;
                case TCP_STATUS_LAST_ACK:
                    tcp_v6_handle_last_ack(pstStream, pstTcpHdr);
                    break;
                
            }
            rte_pktmbuf_free(pstMbuf[i]);
        }
        //tcp_v6_out(pstMbufPool);
    }

    return 0;
}

int finish_v6(void *arg)
{
    int i;
    struct rte_mempool *pstMbufPool;
    pstMbufPool = (struct rte_mempool *)arg;
    while(!force_quit)
    {
        tcp_v6_out(pstMbufPool);
        // for(i = 4;i < D_MAX_FD_COUNT - 1;i++)
        // {
        //     if(finish_v6_fd[i] == 1)
        //     {
        //         //usleep(200000);
        //         void *pstHostInfo = get_hostinfo_fromfd(i);
        //         struct tcp_v6_stream *pstStream = (struct tcp_v6_stream *)pstHostInfo;
        //         pstStream->status = TCP_STATUS_CLOSED;
        //         set_fd_frombitmap(i);
        //         LL_REMOVE(pstStream, g_pstTcpTbl->tcb_v6_set);
		// 	    rte_ring_free(pstStream->sndbuf);
		// 	    //rte_ring_free(pstStream->rcvbuf);
        //         rte_free(pstStream->request_payload);
		// 	    rte_free(pstStream);
        //         printf("v6 connect finish!!!\n\n");
        //         finish_v6_fd[i] = 0;
        //     }
        //     else if(finish_v4_fd[i] == 1)
        //     {
        //         //usleep(200000);
        //         void *pstHostInfo = get_hostinfo_fromfd(i);
        //         struct tcp_stream *pstStream = (struct tcp_stream *)pstHostInfo;
        //         pstStream->status = TCP_STATUS_CLOSED;
        //         set_fd_frombitmap(i);
        //         LL_REMOVE(pstStream, g_pstTcpTbl->tcb_set);
		// 	    rte_ring_free(pstStream->sndbuf);
		// 	    //rte_ring_free(pstStream->rcvbuf);

		// 	    rte_free(pstStream);
        //         printf("v4 connect finish!!!\n");
        //         finish_v4_fd[i] = 0;
        //     }
        //     else continue;
        // }
    }
}

int tcp_server_entry(void *arg)  
{
    struct rte_mempool *pstMbufPool;
    pstMbufPool = (struct rte_mempool *)arg;
	int listenfd;
	int iRet = -1;
	struct sockaddr_in servaddr;
	
	listenfd = nsocket(AF_INET, SOCK_STREAM, 0);
	if (listenfd == -1) 
	{
		printf("[%s][%d] nsocket error!\n", __FUNCTION__, __LINE__);
		return -1;
	}

	memset(&servaddr, 0, sizeof(struct sockaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl((in_addr_t)0xC0A80A64);
	servaddr.sin_port = htons(8080);
	iRet = nbind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr));
	if(iRet < 0)
	{
		printf("nbind error!\n");
		return -1;
	}

	nlisten(listenfd, 10);

	while (!force_quit) 
	{
        tcp_out(pstMbufPool);
		// struct sockaddr_in client;
		// socklen_t len = sizeof(client);
		// int connfd = naccept(listenfd, (struct sockaddr*)&client, &len);

		// char buff[D_TCP_BUFFER_SIZE] = {0};
		// while (1) 
		// {
		// 	int n = nrecv(connfd, buff, D_TCP_BUFFER_SIZE, 0); //block
		// 	if (n > 0) 
		// 	{
		// 		printf("recv: %s\n", buff);
		// 		nsend(connfd, buff, n, 0);
		// 	} 
		// 	else if (n == 0) 
		// 	{
		// 		printf("nclose()\n");
		// 		nclose(connfd);
		// 		break;
		// 	} 
		// 	else 
		// 	{ //nonblock

		// 	}
        //     void *info = NULL;

        //     info = (struct tcp_stream *)get_hostinfo_fromfd(connfd);
        //     if(info == NULL) 
        //         return -1;
            
        //     struct tcp_stream *pstStream = (struct tcp_stream*)info;
            
        //     if (pstStream->status == TCP_STATUS_TIME_WAIT)
        //     {
        //         LL_REMOVE(pstStream, g_pstTcpTbl->tcb_set);

		// 	    rte_ring_free(pstStream->sndbuf);
		// 	    rte_ring_free(pstStream->rcvbuf);

		// 	    rte_free(pstStream);
        //         set_fd_frombitmap(connfd); 
        //         printf("close v4 stream--------------------------------\n");
        //         break;
        //     }
		    
        // }
	}
	nclose(listenfd);

    return 0;
}

int tcp_v6_send(void *arg)  
{
    struct rte_mempool *pstMbufPool;
    pstMbufPool = (struct rte_mempool *)arg;

	while (!force_quit) 
	{
        tcp_v6_out(pstMbufPool);
	}

    return 0;
}

int
main(int argc, char **argv)
{
    struct lcore_queue_conf *qconf;
    struct rte_eth_dev_info stDevInfo;
    int ret;
    uint16_t nb_ports;
    uint16_t nb_ports_available = 0;
    uint16_t portid;
    unsigned lcore_id, rx_lcore_id;;
    unsigned int nb_lcores = 0;
    unsigned int nb_mbufs;
    struct St_InOut_Ring *pstRing;
    struct proxy_Ring *faasRing;
    unsigned int uiCoreId;
    struct rte_mbuf *pstRecvMbuf[1024] = {NULL};
    struct rte_mbuf *pstSendMbuf[512] = {NULL};
    int iRxNum;
    int iTotalNum;
    int iOffset;
    int iTxNum;

    /* init EAL */
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
    argc -= ret;
    argv += ret;

    force_quit = false;
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* parse application arguments (after the EAL ones) */
    ret = l2fwd_parse_args(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid L2FWD arguments\n");


    /* convert to number of cycles */
    timer_period *= rte_get_timer_hz();

    nb_ports = rte_eth_dev_count_avail();
    printf("nb_ports = %u\n", nb_ports);
    if (nb_ports == 0)
        rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");


    /* check port mask to possible port mask */
    if (l2fwd_enabled_port_mask & ~((1 << nb_ports) - 1))
        rte_exit(EXIT_FAILURE, "Invalid portmask; possible (0x%x)\n",
            (1 << nb_ports) - 1);

    nb_mbufs = RTE_MAX(nb_ports * (nb_rxd + nb_txd + MAX_PKT_BURST +
        nb_lcores * MEMPOOL_CACHE_SIZE), 131071U);

    rx_lcore_id = 0;
	qconf = NULL;

	/* Initialize the port/queue configuration of each logical core */
	RTE_ETH_FOREACH_DEV(portid) {
		/* skip ports that are not enabled */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;

		/* get the lcore_id for this port */
		while (rte_lcore_is_enabled(rx_lcore_id) == 0 ||
		       lcore_queue_conf[rx_lcore_id].n_rx_port ==
		       1) {
			rx_lcore_id++;
			if (rx_lcore_id >= RTE_MAX_LCORE)
				rte_exit(EXIT_FAILURE, "Not enough cores\n");
		}

        if (qconf != &lcore_queue_conf[rx_lcore_id]) {
			/* Assigned a new logical core in the loop above. */
			qconf = &lcore_queue_conf[rx_lcore_id];
			nb_lcores++;
		}

		qconf->rx_port_list[qconf->n_rx_port] = portid;
		qconf->n_rx_port++;
		printf("Lcore %u: RX port %u TX port %u\n", rx_lcore_id,
		       portid, l2fwd_dst_ports[portid]);
	}
    /* create the mbuf pool */
    l2fwd_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", nb_mbufs,
        MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
        rte_socket_id());
    if (l2fwd_pktmbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

    /* Initialise each port */
    RTE_ETH_FOREACH_DEV(portid) {
        struct rte_eth_rxconf rxq_conf;
        struct rte_eth_txconf txq_conf;
        struct rte_eth_conf local_port_conf = port_conf;
        struct rte_eth_dev_info dev_info;

        /* skip ports that are not enabled */
        if ((l2fwd_enabled_port_mask & (1 << portid)) == 0) {
            printf("Skipping disabled port %u\n", portid);
            continue;
        }
        nb_ports_available++;

        /* init port */
        printf("Initializing port %u... ", portid);
        fflush(stdout);

        ret = rte_eth_dev_info_get(portid, &dev_info);
        if (ret != 0)
            rte_exit(EXIT_FAILURE,
                "Error during getting device (port %u) info: %s\n",
                portid, strerror(-ret));

        if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
            local_port_conf.txmode.offloads |=
                RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
        ret = rte_eth_dev_configure(portid, 1, 1, &local_port_conf);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
                  ret, portid);

        ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd,
                               &nb_txd);
        if (ret < 0)
            rte_exit(EXIT_FAILURE,
                 "Cannot adjust number of descriptors: err=%d, port=%u\n",
                 ret, portid);

        ret = rte_eth_macaddr_get(portid,
                      &l2fwd_ports_eth_addr[portid]);
        if (ret < 0)
            rte_exit(EXIT_FAILURE,
                 "Cannot get MAC address: err=%d, port=%u\n",
                 ret, portid);

        /* init one RX queue */
        fflush(stdout);
        rxq_conf = dev_info.default_rxconf;
        rxq_conf.offloads = local_port_conf.rxmode.offloads;
        ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd,
                         rte_eth_dev_socket_id(portid),
                         &rxq_conf,
                         l2fwd_pktmbuf_pool);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n",
                  ret, portid);

        /* init one TX queue on each port */
        fflush(stdout);
        txq_conf = dev_info.default_txconf;
        txq_conf.offloads = local_port_conf.txmode.offloads;
        ret = rte_eth_tx_queue_setup(portid, 0, nb_txd,
                rte_eth_dev_socket_id(portid),
                &txq_conf);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n",
                ret, portid);

        // /* Initialize TX buffers */
        // tx_buffer[portid] = rte_zmalloc_socket("tx_buffer",
        //         RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
        //         rte_eth_dev_socket_id(portid));
        // if (tx_buffer[portid] == NULL)
        //     rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n",
        //             portid);

        // rte_eth_tx_buffer_init(tx_buffer[portid], MAX_PKT_BURST);

        ret = rte_eth_dev_set_ptypes(portid, RTE_PTYPE_UNKNOWN, NULL,
                         0);
        if (ret < 0)
            printf("Port %u, Failed to disable Ptype parsing\n",
                    portid);
        /* Start device */
        ret = rte_eth_dev_start(portid);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
                  ret, portid);

        printf("done: \n");

        ret = rte_eth_promiscuous_enable(portid);
        if (ret != 0)
            rte_exit(EXIT_FAILURE,
                 "rte_eth_promiscuous_enable:err=%s, port=%u\n",
                 rte_strerror(-ret), portid);

        printf("Port %u, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
                portid,
                l2fwd_ports_eth_addr[portid].addr_bytes[0],
                l2fwd_ports_eth_addr[portid].addr_bytes[1],
                l2fwd_ports_eth_addr[portid].addr_bytes[2],
                l2fwd_ports_eth_addr[portid].addr_bytes[3],
                l2fwd_ports_eth_addr[portid].addr_bytes[4],
                l2fwd_ports_eth_addr[portid].addr_bytes[5]);

    }

    if (!nb_ports_available) {
        rte_exit(EXIT_FAILURE,
            "All available ports are disabled. Please set portmask.\n");
    }

    check_all_ports_link_status(l2fwd_enabled_port_mask);

    pstRing = ringInstance();
	if(pstRing == NULL) 
		rte_exit(EXIT_FAILURE, "ring buffer init failed\n");

    pstRing->pstInRing = rte_ring_create("in ring", 8192, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    pstRing->pstOutRing = rte_ring_create("out ring", 8192, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);

    faasRing = proxy_RingInstance();
    if(faasRing == NULL) 
		rte_exit(EXIT_FAILURE, "faasring buffer init failed\n");
    
    faasRing->proInRing = rte_ring_create("faas in ring", 8192, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    faasRing->proOutRing = rte_ring_create("faas out ring", 8192, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    faasRing->proTranStoCRing = rte_ring_create("Tran to C ring", 8192, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    faasRing->proTranCtoSRing = rte_ring_create("Tran to S ring", 8192, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);


    uiCoreId = rte_lcore_id();
    printf("main core id = %u\n", uiCoreId);


    ret = 0;
    
    /* launch per-lcore init on every lcore */
    //rte_eal_mp_remote_launch(l2fwd_launch_one_lcore, NULL, CALL_MAIN);
    uiCoreId = rte_get_next_lcore(uiCoreId, 1, 0);
    printf("tcp_client_entry uCoreID: %u\n", uiCoreId);
    rte_eal_remote_launch(tcp_client_entry, l2fwd_pktmbuf_pool, uiCoreId);

    uiCoreId = rte_get_next_lcore(uiCoreId, 1, 0);
    printf("pkt_process uCoreID: %u\n", uiCoreId);
	rte_eal_remote_launch(pkt_process, l2fwd_pktmbuf_pool, uiCoreId);
 
    uiCoreId = rte_get_next_lcore(uiCoreId, 1, 0);
    printf("tcp_server_entry uCoreID: %u\n", uiCoreId);
    rte_eal_remote_launch(tcp_server_entry, l2fwd_pktmbuf_pool, uiCoreId);
    printf("tcp_v6_send uCoreID: %u\n", uiCoreId);
    rte_eal_remote_launch(tcp_v6_send, l2fwd_pktmbuf_pool, uiCoreId);

    uiCoreId = rte_get_next_lcore(uiCoreId, 1, 0);
    printf("tcp_client_process uCoreID: %u\n", uiCoreId);
    rte_eal_remote_launch(tcp_client_process, l2fwd_pktmbuf_pool, uiCoreId);

    uiCoreId = rte_get_next_lcore(uiCoreId, 1, 0);
    printf("faas_process uCoreID: %u\n", uiCoreId);
    rte_eal_remote_launch(faas_process, l2fwd_pktmbuf_pool, uiCoreId);

    uiCoreId = rte_get_next_lcore(uiCoreId, 1, 0);
    printf("tcp_server_process uCoreID: %u\n", uiCoreId);
    rte_eal_remote_launch(tcp_server_process, l2fwd_pktmbuf_pool, uiCoreId);

    uiCoreId = rte_get_next_lcore(uiCoreId, 1, 0);
    printf("tcp_v6_fd_process uCoreID: %u\n", uiCoreId);
    rte_eal_remote_launch(finish_v6, l2fwd_pktmbuf_pool, uiCoreId);

    printf("\n");
    printf("\n");
    printf("\n");

    while (!force_quit) 
    {
        // rx
        iRxNum = rte_eth_rx_burst(2, 0, pstRecvMbuf, D_BURST_SIZE);
        if(iRxNum > 0)
            rte_ring_sp_enqueue_burst(pstRing->pstInRing, (void**)pstRecvMbuf, iRxNum, NULL);
        
        // tx
        iTotalNum = rte_ring_sc_dequeue_burst(pstRing->pstOutRing, (void**)pstSendMbuf, D_BURST_SIZE, NULL);
		if(iTotalNum > 0)
		{
			iOffset = 0;
			while(iOffset < iTotalNum)
			{
				iTxNum = rte_eth_tx_burst(2, 0, &pstSendMbuf[iOffset], iTotalNum - iOffset);
				if(iTxNum > 0)
					iOffset += iTxNum;
			}
		}
    }


    RTE_ETH_FOREACH_DEV(portid) {
        if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
            continue;
        printf("Closing port %d...", portid);
        rte_eth_dev_stop(portid);
        rte_eth_dev_close(portid);
        printf(" Done\n");
    }
    printf("Bye...\n");

    return ret;
}
