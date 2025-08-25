#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/mbuf.h>

#include <net/if.h>
#include <net/pfil.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

static unsigned int http_dropped = 0;
static unsigned int total_dropped_size = 0;

static pfil_return_t
http_block_mbuf(struct mbuf **mp, struct ifnet *ifp, int dir, void *arg, struct inpcb *inp)
{
    struct mbuf *m;
    struct ip *ip;
    struct tcphdr *th;
    int ip_hlen, tcp_hlen, payload_off, payload_len, copy_len;
    char buf[1025];

    // we filter only packets from client to VM B (middle man).
    if (dir != PFIL_OUT)
        return PFIL_PASS;

    m = *mp;
    if (m == NULL)
        return PFIL_PASS;

    // IP header at the start
    ip = mtod(m, struct ip *);
    if (ip->ip_v != 4)
        return PFIL_PASS;

    if (ip->ip_p != IPPROTO_TCP)
        return PFIL_PASS;

    ip_hlen = ip->ip_hl << 2;
    if (ip_hlen < (int)sizeof(struct ip))
        return PFIL_PASS;

    // TCP is after the IP header
    if (m->m_pkthdr.len < ip_hlen + (int)sizeof(struct tcphdr))
        return PFIL_PASS;

    /* Safely read the fixed TCP header fields */
    {
        struct tcphdr th_stack;
        m_copydata(m, ip_hlen, sizeof(th_stack), (caddr_t)&th_stack);
        th = &th_stack;
    }

    tcp_hlen = th->th_off << 2;
    if (tcp_hlen < (int)sizeof(struct tcphdr))
        return PFIL_PASS;

    payload_off = ip_hlen + tcp_hlen;

    /* Total IP length (header + TCP + payload) comes from ip->ip_len */
    {
        int ip_total = ntohs(ip->ip_len);
        if (ip_total <= payload_off)
            return PFIL_PASS;
        payload_len = ip_total - payload_off;
    }

    /* Copy up to 1024 bytes of payload into buf and NUL-terminate */
    copy_len = (payload_len > 1024) ? 1024 : payload_len;
    m_copydata(m, payload_off, copy_len, (caddr_t)buf);
    buf[copy_len] = '\0';

    /* Look for blocked host token anywhere in the HTTP payload */
    if (strstr(buf, "blocked.com") != NULL) {
        http_dropped++;
        total_dropped_size += payload_len;
        printf("blocked_http(14.x): drop #%u, payload=%d bytes, matched 'blocked.com'\n",
               http_dropped, payload_len);
        return PFIL_DROPPED; /* tell pfil to drop this packet */
    }

    return PFIL_PASS;
}

/* Keep the hook handle so we can unregister on unload */
static struct pfil_hook *http_hook = NULL;

static int
load_handler(module_t mod, int evt, void *arg)
{
    switch (evt) {
    case MOD_LOAD: {
        struct pfil_hook_args pha;
        struct pfil_link_args pla;

        bzero(&pha, sizeof(pha));
        pha.pa_version   = PFIL_VERSION;
        pha.pa_flags     = PFIL_OUT;
        pha.pa_type      = PFIL_TYPE_IP4;
        pha.pa_mbuf_chk  = http_block_mbuf;
        pha.pa_modname   = "http_block_mod";
        pha.pa_rulname   = "http_block_rule";
        pha.pa_ruleset   = NULL;

        http_hook = pfil_add_hook(&pha);
        if (http_hook == NULL) {
            printf("blocked_http: pfil_add_hook failed\n");
            return EFAULT;
        }

        bzero(&pla, sizeof(pla));
        pla.pa_version   = PFIL_VERSION;
        pla.pa_flags     = PFIL_OUT | PFIL_HOOKPTR;
        pla.pa_headname  = "inet";             /* IPv4 head */
        pla.pa_hook      = http_hook;

        if (pfil_link(&pla) != 0) {
            printf("blocked_http: pfil_link failed\n");
            pfil_remove_hook(http_hook);
            http_hook = NULL;
            return EFAULT;
        }

        printf("blocked_http: loaded (FreeBSD 14.x pfil API)\n");
        break;
    }

    case MOD_UNLOAD:
        if (http_hook != NULL) {
            pfil_remove_hook(http_hook);
            http_hook = NULL;
        }
        printf("blocked_http: unloaded. dropped=%u, total_bytes=%u\n",
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
