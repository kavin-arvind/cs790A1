/*
 * blocked_http.c
 * Simple pfil hook: drop IPv4 TCP packets whose TCP payload contains "blocked.com"
 *
 * Build: make
 * Load:  kldload ./blocked_http.ko
 * Unload: kldunload blocked_http
 *
 * Note: tested against FreeBSD 13.x/14.x kernel pfil interface.
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <machine/atomic.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/pfil.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <sys/systm.h>

static pfil_hook_t http_hook = NULL;
static long blocked_packets = 0;
static long blocked_bytes = 0;

/* Hook function called by pfil for packets */
static pfil_return_t
http_block_hook(struct mbuf **mp, struct ifnet *ifp, int dir, void *ctx, struct inpcb *inp)
{
    struct mbuf *m;
    u_char hdrbuf[256];
    struct ip *ip;
    struct tcphdr *th;
    int iphlen, thlen;
    int payload_offset, payload_len, copy_len;
    char payload[1025];

    if (mp == NULL || *mp == NULL)
        return (0);

    m = *mp;

    /* Not enough packet to even have IP header */
    if (m->m_pkthdr.len < (int)sizeof(struct ip))
        return (0);

    /* Copy first bytes (IP + TCP header area) into hdrbuf safely */
    {
        int need = sizeof(struct ip) + sizeof(struct tcphdr);
        if (need > (int)sizeof(hdrbuf))
            need = sizeof(hdrbuf);
        m_copydata(m, 0, need, hdrbuf);
    }

    ip = (struct ip *)hdrbuf;
    if (ip->ip_v != 4)
        return (0);
    if (ip->ip_p != IPPROTO_TCP)
        return (0);

    iphlen = ip->ip_hl << 2;
    if (iphlen <= 0 || iphlen > (int)sizeof(hdrbuf))
        return (0);

    th = (struct tcphdr *)(hdrbuf + iphlen);
    thlen = th->th_off << 2;
    if (thlen <= 0)
        return (0);

    payload_offset = iphlen + thlen;
    if (m->m_pkthdr.len <= payload_offset)
        return (0);

    payload_len = m->m_pkthdr.len - payload_offset;
    copy_len = payload_len > 1024 ? 1024 : payload_len;

    /* Copy HTTP payload (first up to 1024 bytes) */
    m_copydata(m, payload_offset, copy_len, payload);
    payload[copy_len] = '\0';

    /* Simple substring match — if blocked.com appears anywhere, drop */
    if (strstr(payload, "blocked.com") != NULL) {
        atomic_add_long(&blocked_packets, 1);
        atomic_add_long(&blocked_bytes, payload_len);
        printf("blocked_http: dropped packet #%ld size=%d bytes (contains 'blocked.com')\n",
               blocked_packets, payload_len);
        /* free the mbuf and stop further processing */
        m_freem(m);
        *mp = NULL;
        return (EACCES); /* non-zero errno stops processing (packet dropped) */
    }

    return (0); /* let packet continue */
}

static int
load(struct module *module, int cmd, void *arg)
{
    int error = 0;

    switch (cmd) {
    case MOD_LOAD: {
        struct pfil_hook_args pha = {
            .pa_version = PFIL_VERSION,
            .pa_flags = PFIL_IN,        /* intercept incoming packets */
            .pa_ruleset = NULL,
            .pa_modname = "blocked_http",
            .pa_mbuf_chk = http_block_hook
        };
        http_hook = pfil_add_hook(&pha);
        if (http_hook == NULL) {
            printf("blocked_http: pfil_add_hook failed\n");
            error = EINVAL;
            break;
        }
        printf("blocked_http: loaded - blocking HTTP requests containing 'blocked.com'\n");
        break;
    }
    case MOD_UNLOAD:
        if (http_hook != NULL) {
            pfil_remove_hook(http_hook);
            http_hook = NULL;
        }
        printf("blocked_http: unloaded; total blocked %ld packets (%ld bytes)\n",
               blocked_packets, blocked_bytes);
        break;
    default:
        error = EOPNOTSUPP;
        break;
    }
    return (error);
}

static moduledata_t blocked_http_mod = {
    "blocked_http",
    load,
    NULL
};
DECLARE_MODULE(blocked_http, blocked_http_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
