#include "include/icmp.h"
#include "include/ip.h"
#include "include/rtable.h"
#include "include/arp.h"
#include "include/base.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// send icmp packet
void icmp_send_packet(const char *in_pkt, int len, u8 type, u8 code)
{
    struct iphdr *in_ip = packet_to_ip_hdr(in_pkt);
    long total_size = ETHER_HDR_SIZE + ICMP_HDR_SIZE + in_ip->tot_len;
    char *icmp_pkt = (char*)malloc(total_size);
    struct icmphdr *ihdr =
        (struct icmphdr *)(in_pkt + (ETHER_HDR_SIZE + ICMP_HDR_SIZE + IP_HDR_SIZE(in_ip)));
    
    memset(icmp_pkt, 0, (ETHER_HDR_SIZE + ICMP_HDR_SIZE + in_ip->tot_len));
    
    u32 out_dst = ntohl(in_ip->saddr);
    rt_entry_t *entry = longest_prefix_match(out_dst);

    ip_init_hdr(in_ip,
                entry->iface->ip,
                out_dst,
                total_size,
                IPPROTO_OSPFv2);
    ihdr->type = type;
    ihdr->code = code;
    if (type == ICMP_ECHOREQUEST) {
        memcpy(ihdr + ICMP_HDR_SIZE,
               IP_DATA(in_ip),
               in_ip->tot_len - IP_HDR_SIZE(in_ip) - ICMP_HDR_SIZE);
    } else {
        memcpy(ihdr + ICMP_HDR_SIZE,
               (char*)in_ip,
               IP_HDR_SIZE(in_ip) + 8);
    }

    ip_send_packet(icmp_pkt, ETHER_HDR_SIZE + ICMP_HDR_SIZE + in_ip->tot_len);
    // fprintf(stderr, "TODO: malloc and send icmp packet.\n");
}
