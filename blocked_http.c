#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <net/pfil.h>
#include <sys/mbuf.h>

static unsigned int icmp_dropped = 0;
static unsigned int total_dropped_size = 0;

/* Hook Function */
static pfil_return_t icmp_block_hook(pfil_packet_t pkt, struct ifnet *ifp, int dir, void *arg, struct inpcb *inp) {
    struct mbuf *m;
    struct ip *ip_hdr;
    struct icmp *icmp_hdr;
    
    m = *(pkt.m);
    if (m == NULL) return PFIL_PASS;

    if (dir != PFIL_IN) return PFIL_PASS;  // Only process incoming packets

    ip_hdr = mtod(m, struct ip *);
    if (ip_hdr->ip_p == IPPROTO_ICMP) {
        icmp_hdr = (struct icmp *)((char *)ip_hdr + (ip_hdr->ip_hl << 2));
        if (icmp_hdr->icmp_type == ICMP_ECHO) {  // Echo Request
            icmp_dropped++;
            total_dropped_size += ntohs(ip_hdr->ip_len);
            printf("ICMP Echo Request blocked. Total dropped: %u, Total size: %u bytes\n",
                   icmp_dropped, total_dropped_size);
            return PFIL_DROPPED;  // Drop the packet
        }
    }
    return PFIL_PASS;  // Allow other packets
}

static struct pfil_hook *icmp_hook = NULL;

/* Module Load/Unload Handler */
static int load_handler(module_t mod, int event_type, void *arg) {
    struct pfil_hook_args pha;
    struct pfil_link_args pla;

    switch (event_type) {
        case MOD_LOAD:
            bzero(&pha, sizeof(pha));
            pha.pa_version = PFIL_VERSION;
            pha.pa_flags = PFIL_IN;
            pha.pa_type = PFIL_TYPE_IP4;
            pha.pa_func = icmp_block_hook;
            pha.pa_ruleset = NULL;
            pha.pa_modname = "icmp_block_mod";
            pha.pa_rulname = "icmp_block_rule";

            icmp_hook = pfil_add_hook(&pha);

            if (icmp_hook == NULL) {
                printf("Failed to register ICMP block hook.\n");
                return EFAULT;
            }

            pla.pa_version = PFIL_VERSION;
            pla.pa_flags = PFIL_IN | PFIL_HOOKPTR;
            pla.pa_headname = "inet";
            pla.pa_hook = icmp_hook;

            if (pfil_link(&pla) != 0) {
                printf("Failed to link ICMP block hook.\n");
                pfil_remove_hook(icmp_hook);
                return EFAULT;
            }

            printf("ICMP Block Module loaded successfully.\n");
            break;

        case MOD_UNLOAD:
            if (icmp_hook != NULL) {
                pfil_remove_hook(icmp_hook);
                printf("ICMP Block Module unloaded.\n");
            }
            break;

        default:
            return EOPNOTSUPP;
    }
    return 0;
}

static moduledata_t icmp_block_mod = {
    "icmp_block",      // Module name
    load_handler,      // Event handler
    NULL               // Extra data
};

DECLARE_MODULE(icmp_block, icmp_block_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);