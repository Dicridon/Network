#include "include/arp.h"
#include "include/base.h"
#include "include/types.h"
#include "include/packet.h"
#include "include/ether.h"
#include "include/arpcache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// #include "log.h"

// send an arp request: encapsulate an arp request packet, send it out through
// iface_send_packet
void arp_send_request(iface_info_t *iface, u32 dst_ip)
{
    struct ether_arp arp;
    bzero(&arp, sizeof(struct ether_arp));
    arp.arp_hrd = htons(0x01);
    arp.arp_pro = htons(0x0800);
    arp.arp_hln = 6;
    arp.arp_pln = 4;
    arp.arp_op = htonl(ARPOP_REQUEST);
    memcpy(arp.arp_sha, iface->mac, ETH_ALEN);
    arp.arp_spa = htonl(iface->ip);
    arp.arp_tpa = htonl(dst_ip);
    int packet_size = ETHER_HDR_SIZE + sizeof(struct ether_arp);
    char *packet = (char*)malloc(packet_size);
    struct ether_header *eh = (struct ether_header *)packet;
    memset(eh->ether_dhost, 0xff, ETH_ALEN);
    memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
    eh->ether_type = htons(ETH_P_ARP);
    memcpy(packet+2*ETH_ALEN+2, &arp, sizeof(struct ether_arp));
    iface_send_packet(iface, packet, packet_size);
    //fprintf(stderr, "DONE: send arp request when lookup failed in arpcache.\n");
}

// send an arp reply packet: encapsulate an arp reply packet, send it out
// through iface_send_packet
void arp_send_reply(iface_info_t *iface, struct ether_arp *req_hdr)
{
    struct ether_arp arp;
    bzero(&arp, sizeof(struct ether_arp));
    arp.arp_hrd = htons(0x01);
    arp.arp_pro = htons(0x0800);
    arp.arp_hln = 6;
    arp.arp_pln = 4;
    arp.arp_op = htons(ARPOP_REPLY);
    memcpy(arp.arp_sha, iface->mac, ETH_ALEN);
    arp.arp_spa = htonl(iface->ip);
    memcpy(arp.arp_tha, req_hdr->arp_sha, ETH_ALEN);
    arp.arp_tpa = req_hdr->arp_spa;
    int packet_size = ETHER_HDR_SIZE + sizeof(struct ether_arp);
    char *packet = (char*)malloc(packet_size);
    struct ether_header *eh = (struct ether_header *)packet;
    memcpy(eh->ether_dhost, req_hdr->arp_sha, ETH_ALEN);
    memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
    eh->ether_type = htons(ETH_P_ARP);
    memcpy(packet+2*ETH_ALEN+2, &arp, sizeof(struct ether_arp));
    iface_send_packet(iface, packet, packet_size);
    //fprintf(stderr, "DONE: send arp reply when receiving arp request.\n");
}

void handle_arp_packet(iface_info_t *iface, char *packet, int len)
{
    struct ether_arp *arp = (struct ether_arp *)(packet + ETHER_HDR_SIZE);
    u32 source_ip = ntohl(arp->arp_spa);
    u32 target_ip = ntohl(arp->arp_tpa);
    u16 op = ntohs(arp->arp_op);

    switch(op) {
    case ARPOP_REQUEST:
        if (target_ip == iface->ip) {
            arp_send_reply(iface, arp);
            arpcache_insert(source_ip, arp->arp_sha);
        } else {
            //  iface_send_packet(iface, packet, len);
            iface_send_packet_by_arp(iface, target_ip, packet, len);
        }
        break;
    case ARPOP_REPLY:
        if (target_ip == iface->ip) {
            arpcache_insert(source_ip, arp->arp_sha);
        } else {
            // iface_send_packet(iface, packet, len);
            iface_send_packet_by_arp(iface, target_ip, packet, len);
        }
    default:
        fprintf(stdout, "NOT A ARP PACKET in handle_arp_packet\n");
    }

    //fprintf(stderr, "DONE: process arp packet: arp request & arp reply.\n");
}

// send (IP) packet through arpcache lookup 
//
// Lookup the mac address of dst_ip in arpcache. If it is found, fill the
// ethernet header and emit the packet by iface_send_packet, otherwise, pending 
// this packet into arpcache, and send arp request.
void iface_send_packet_by_arp(iface_info_t *iface, u32 dst_ip, char *packet, int len)
{
    struct ether_header *eh = (struct ether_header *)packet;
    memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
    eh->ether_type = htons(ETH_P_IP);

    u8 dst_mac[ETH_ALEN];
    int found = arpcache_lookup(dst_ip, dst_mac);
    if (found) {
        // log(DEBUG, "found the mac of %x, send this packet", dst_ip);
        memcpy(eh->ether_dhost, dst_mac, ETH_ALEN);
        iface_send_packet(iface, packet, len);
    }
    else {
        // log(DEBUG, "lookup %x failed, pend this packet", dst_ip);
        arpcache_append_packet(iface, dst_ip, packet, len);
    }
}
