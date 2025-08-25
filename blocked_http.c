#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/systm.h>     /* printf, strstr */
#include <sys/errno.h>
#include <sys/mbuf.h>

#include <net/if.h>
#include <net/pfil.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

/* Counters */
static unsigned int http_dropped = 0;
static unsigned int total_dropped_size = 0;

/*
 * Hook Function:
 * Checks TCP packets for "blocked.com" in the HTTP Host header and drops them.
 */
static pfil_return_t
http_block_hook(pfil_packet_t pkt, struct ifnet *ifp, int dir, void *arg, struct inpcb *inp)
{
    struct mbuf *m;
    struct ip *ip_hdr;
    struct tcphdr *tcp_hdr;
    int ip_hlen, tcp_hlen, payload_offset, payload_len, copy_len;
    char buf[1025];

    m = *(pkt.m);
    if (m == NULL)
        return PFIL_PASS;

    /* Only check outgoing packets from client to server */
    if (dir != PFIL_OUT)
        return PFIL_PASS;

    /* Get IP header */
    ip_hdr = mtod(m, struct ip *);
    if (ip_hdr->ip_p != IPPROTO_TCP)
        return PFIL_PASS;

    ip_hlen = ip_hdr->ip_hl << 2;
    if (m->m_len < ip_hlen)
        return PFIL_PASS;

    /* TCP header is after IP header */
    tcp_hdr = (struct tcphdr *)((char *)ip_hdr + ip_hlen);
    tcp_hlen = tcp_hdr->th_off << 2;

    /* Calculate HTTP payload position and length */
    payload_offset = ip_hlen + tcp_hlen;
    payload_len = ntohs(ip_hdr->ip_len) - payload_offset;
    if (payload_len <= 0)
        return PFIL_PASS;

    copy_len = (payload_len > 1024) ? 1024 : payload_len;
    m_copydata(m, payload_offset, copy_len, buf);
    buf[copy_len] = '\0';

    /* Look for Host header containing "blocked.com" */
    if (strstr(buf, "blocked.com") != NULL) {
        http_dropped++;
        total_dropped_size += payload_len;
        printf("blocked_http: Dropped HTTP request #%u (size=%d) containing 'blocked.com'\n",
               http_dropped, payload_len);
        return PFIL_DROPPED;  /* Tell kernel to drop packet */
    }

    return PFIL_PASS;
}

/* Hook and link structures */
static struct pfil_hook *http_hook = NULL;

/* Module load/unload handler */
static int
load_handler(module_t mod, int event_type, void *arg)
{
    struct pfil_hook_args pha;
    struct pfil_link_args pla;

    switch (event_type) {
    case MOD_LOAD:
        bzero(&pha, sizeof(pha));
        pha.pa_version = PFIL_VERSION;
        pha.pa_flags = PFIL_OUT;           /* Outbound packets (client -> server) */
        pha.pa_type = PFIL_TYPE_IP4;       /* IPv4 packets */
        pha.pa_func = http_block_hook;
        pha.pa_ruleset = NULL;
        pha.pa_modname = "http_block_mod";
        pha.pa_rulname = "http_block_rule";

        http_hook = pfil_add_hook(&pha);
        if (http_hook == NULL) {
            printf("Failed to register HTTP block hook.\n");
            return EFAULT;
        }

        /* Link the hook to IPv4 ("inet") */
        bzero(&pla, sizeof(pla));
        pla.pa_version = PFIL_VERSION;
        pla.pa_flags = PFIL_OUT | PFIL_HOOKPTR;
        pla.pa_headname = "inet";
        pla.pa_hook = http_hook;

        if (pfil_link(&pla) != 0) {
            printf("Failed to link HTTP block hook.\n");
            pfil_remove_hook(http_hook);
            return EFAULT;
        }

        printf("HTTP Block Module loaded successfully.\n");
        break;

    case MOD_UNLOAD:
        if (http_hook != NULL) {
            pfil_remove_hook(http_hook);
            http_hook = NULL;
        }
        printf("HTTP Block Module unloaded. Total dropped: %u packets, %u bytes\n",
               http_dropped, total_dropped_size);
        break;

    default:
        return EOPNOTSUPP;
    }
    return 0;
}

static moduledata_t http_block_mod = {
    "blocked_http",
    load_handler,
    NULL
};

DECLARE_MODULE(blocked_http, http_block_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
