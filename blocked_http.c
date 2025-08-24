/* blocked_http.c  — pfil hook dropping HTTP requests containing "blocked.com"
 *
 * Build : make
 * Load  : kldload ./blocked_http.ko
 * Test  : curl -H "Host: blocked.com" http://<server>  (should be dropped)
 * Unload: kldunload blocked_http
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/systm.h>     /* printf, strstr, etc. */
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/errno.h>

#include <net/if.h>
#include <net/pfil.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

/* Simple counters (assignment scope; not SMP-safe) */
static long blocked_packets = 0;
static long blocked_bytes   = 0;

static int
http_block_hook(void *arg, struct mbuf **mp, struct ifnet *ifp, int dir,
                struct inpcb *inp)
{
    struct mbuf *m;
    u_char hdrbuf[256];
    struct ip *ip;
    struct tcphdr *th;
    int iphlen, thlen, pay_off, pay_len, copy_len;
    char payload[1025];

    if (mp == NULL || *mp == NULL)
        return (0);

    m = *mp;

    if (m->m_pkthdr.len < (int)sizeof(struct ip))
        return (0);

    /* Copy enough for IP+TCP fixed headers */
    {
        int need = sizeof(struct ip) + sizeof(struct tcphdr);
        if (need > (int)sizeof(hdrbuf))
            need = sizeof(hdrbuf);
        m_copydata(m, 0, need, hdrbuf);
    }

    ip = (struct ip *)hdrbuf;
    if (ip->ip_v != 4 || ip->ip_p != IPPROTO_TCP)
        return (0);

    iphlen = ip->ip_hl << 2;
    if (iphlen <= 0 || iphlen > (int)sizeof(hdrbuf))
        return (0);

    th = (struct tcphdr *)(hdrbuf + iphlen);
    thlen = th->th_off << 2;
    if (thlen <= 0)
        return (0);

    pay_off = iphlen + thlen;
    if (m->m_pkthdr.len <= pay_off)
        return (0);

    pay_len = m->m_pkthdr.len - pay_off;
    copy_len = (pay_len > 1024) ? 1024 : pay_len;

    m_copydata(m, pay_off, copy_len, payload);
    payload[copy_len] = '\0';

    if (strstr(payload, "blocked.com") != NULL) {
        blocked_packets++;
        blocked_bytes += pay_len;
        printf("blocked_http: dropped packet #%ld size=%d (contains 'blocked.com')\n",
               blocked_packets, pay_len);
        m_freem(m);
        *mp = NULL;
        return (EACCES); /* non-zero → drop */
    }
    return (0);
}

static pfil_hook_t hnd = NULL;

static int
mod_event(struct module *m, int cmd, void *arg)
{
    int error = 0;

    switch (cmd) {
    case MOD_LOAD: {
        struct pfil_hook_args pha;
        bzero(&pha, sizeof(pha));
        pha.pa_version = PFIL_VERSION;
        pha.pa_flags   = PFIL_IN;               /* intercept inbound */
        pha.pa_type    = PFIL_TYPE_AF;          /* attach to address family hook head */
        pha.pa_modname = "blocked_http";
        pha.pa_func    = http_block_hook;       /* <-- older field name */
        pha.pa_rulname = NULL;
        pha.pa_headname = PFIL_HEAD_INET;       /* IPv4 */
        hnd = pfil_add_hook(&pha);
        if (hnd == NULL) {
            printf("blocked_http: pfil_add_hook failed\n");
            error = EINVAL;
        } else {
            printf("blocked_http: loaded (pa_func API)\n");
        }
        break;
    }
    case MOD_UNLOAD:
        if (hnd != NULL) {
            pfil_remove_hook(hnd);
            hnd = NULL;
        }
        printf("blocked_http: unloaded; totals: %ld pkts, %ld bytes\n",
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
    mod_event,
    NULL
};

DECLARE_MODULE(blocked_http, blocked_http_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
