#include "include/arpcache.h"
#include "include/arp.h"
#include "include/ether.h"
#include "include/packet.h"
#include "include/icmp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

static arpcache_t arpcache;

static void dump_arpcache() {
    fprintf(stdout, "dumping arpcache\n");
    struct arp_req *req_entry = NULL, *req_q;
    list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list) {
        fprintf(stdout, "req_entry->ip4: %ud\n", req_entry->ip4);
        fprintf(stdout, "requests of %ud:\n", req_entry->ip4);
        struct cached_pkt *cpkt = NULL, *cq;
        list_for_each_entry_safe(cpkt, cq, &req_entry->cached_packets, list){
            fprintf(stdout, "pending packet: %p\n", cpkt->packet);
        }
        fprintf(stdout, "\n");
    }   
}

// initialize IP->mac mapping, request list, lock and sweeping thread
void arpcache_init()
{
    bzero(&arpcache, sizeof(arpcache_t));

    init_list_head(&(arpcache.req_list));

    pthread_mutex_init(&arpcache.lock, NULL);

    pthread_create(&arpcache.thread, NULL, arpcache_sweep, NULL);
}

// release all the resources when exiting
void arpcache_destroy()
{
    pthread_mutex_lock(&arpcache.lock);

    struct arp_req *req_entry = NULL, *req_q;
    list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list) {
        struct cached_pkt *pkt_entry = NULL, *pkt_q;
        list_for_each_entry_safe(pkt_entry, pkt_q, &(req_entry->cached_packets), list) {
            list_delete_entry(&(pkt_entry->list));
            free(pkt_entry->packet);
            free(pkt_entry);
        }

        list_delete_entry(&(req_entry->list));
        free(req_entry);
    }

    pthread_kill(arpcache.thread, SIGTERM);

    pthread_mutex_unlock(&arpcache.lock);
}

// lookup the IP->mac mapping
//
// traverse the hash table to find whether there is an entry with the same IP
// and mac address with the given arguments
int arpcache_lookup(u32 ip4, u8 mac[ETH_ALEN])
{
    for (int i = 0; i < MAX_ARP_SIZE; i++) {
        if (arpcache.entries[i].ip4 == ip4) {
            for (int j = 0; j < ETH_ALEN; j++) {
                mac[j] = arpcache.entries[i].mac[j];
            }
            return 1;
        }
    }
    // fprintf(stderr, "DONE: lookup ip address in arp cache.\n");
    return 0;
}

// append the packet to arpcache
//
// Lookup in the hash table which stores pending packets, if there is already an
// entry with the same IP address and iface (which means the corresponding arp
// request has been sent out), just append this packet at the tail of that entry
// (the entry may contain more than one packet); otherwise, malloc a new entry
// with the given IP address and iface, append the packet, and send arp request.
void arpcache_append_packet(iface_info_t *iface, u32 ip4, char *packet, int len)
{
    struct cached_pkt *cpkt =
        (struct cached_pkt *)malloc(sizeof(struct cached_pkt));
    if (!cpkt) {
        return;
    }

    cpkt->packet = (char*)malloc(len);
    if (!cpkt->packet) {
        return;
    }
    cpkt->len = len;
    strncpy(cpkt->packet, packet, len);

    // same ip and same interface
    struct arp_req *req = NULL;
    struct arp_req *req_entry = NULL, *req_q;
    pthread_mutex_lock(&arpcache.lock);
    
    // debug start
    fprintf(stdout, "\nBefore arpcache_append_packet for %ud\n", ip4);
    dump_arpcache();
    // debug end
    
    list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list) {
        if (req_entry->ip4 == ip4 && req_entry->iface == iface) {
            list_add_tail((struct list_head*)cpkt, &(arpcache.req_list));
            pthread_mutex_unlock(&arpcache.lock);
            return;
        }
    }

    // new request
    req = (struct arp_req *)malloc(sizeof(struct arp_req));
    if (!req) {
        pthread_mutex_unlock(&arpcache.lock);
        return;
    }

    init_list_head((struct list_head *)(&req->cached_packets));
    list_add_tail((struct list_head *)cpkt, &(req->cached_packets));
    req->ip4 = ip4;
    req->iface = iface;
    req->sent = time(NULL);
    req->retries = 1;
    list_add_tail((struct list_head *)req, &(arpcache.req_list));
    // debug start
    fprintf(stdout, "\nAfter arpcache_append_packet for %ud\n", ip4);
    dump_arpcache();
    // debug end
    pthread_mutex_unlock(&arpcache.lock);
    arp_send_request(iface, ip4);
    
    // fprintf(stderr, "DONE: append the ip address if lookup failed, and send arp request if necessary.\n");
}

// insert the IP->mac mapping into arpcache, if there are pending packets
// waiting for this mapping, fill the ethernet header for each of them, and send
// them out
void arpcache_insert(u32 ip4, u8 mac[ETH_ALEN])
{
    pthread_mutex_lock(&arpcache.lock);
    struct arp_req *req_entry = NULL, *q;
    // debug start
    fprintf(stdout, "\nBefore arpcache_insert for %ud\n", ip4);
    dump_arpcache();
    // debug end
    list_for_each_entry_safe(req_entry, q, &(arpcache.req_list), list) {
        if (req_entry->ip4 == ip4) {
            struct cached_pkt *cpkt = NULL, *cq;
            list_for_each_entry_safe(cpkt, cq, &req_entry->cached_packets, list){
                struct ether_header *eh = (struct ether_header *)cpkt->packet;
                memcpy(eh->ether_dhost, mac, ETH_ALEN);
                iface_send_packet(req_entry->iface, cpkt->packet, cpkt->len);
            }
            delete_list((struct list_head *)(&req_entry->cached_packets),
                        struct cached_pkt,
                        list);
            list_delete_entry((struct list_head *)req_entry);
            free(req_entry);
            req_entry = NULL;
            break;
        }
    }

    int index = MAX_ARP_SIZE;
    for (int i = 0; i < MAX_ARP_SIZE; i++) {
        if (!arpcache.entries[i].valid) {
            index = i;
            break;
        }
    }
    if (index == MAX_ARP_SIZE) {
        srandom(time(NULL));
        index = random() % MAX_ARP_SIZE;        
    }
    arpcache.entries[index].ip4 = ip4;
    arpcache.entries[index].added = time(NULL);
    arpcache.entries[index].valid = 1;
    memcpy(&arpcache.entries[index].mac, mac, ETH_ALEN);
    // debug start
    fprintf(stdout, "\nAfter arpcache_insert for %ud\n", ip4);
    dump_arpcache();
    // debug end
    pthread_mutex_unlock(&arpcache.lock);
    // fprintf(stderr, "DONE: insert ip->mac entry, and send all the pending packets.\n");
}

// sweep arpcache periodically
//
// For the IP->mac entry, if the entry has been in the table for more than 15
// seconds, remove it from the table.
// For the pending packets, if the arp request is sent out 1 second ago, while 
// the reply has not been received, retransmit the arp request. If the arp
// request has been sent 5 times without receiving arp reply, for each
// pending packet, send icmp packet (DEST_HOST_UNREACHABLE), and drop these
// packets.
void *arpcache_sweep(void *arg) 
{
    while (1) {
        sleep(1);
        pthread_mutex_lock(&arpcache.lock);
        time_t cur_time = time(NULL);
        for (int i = 0; i < MAX_ARP_SIZE; i++) {
            if (cur_time - arpcache.entries[i].added > 15) {
                arpcache.entries[i].valid = 0;
            }
        }

        struct arp_req *req_entry = NULL, *q;
        // debug
        fprintf(stdout, "\nBefore arpcache_sweep\n");
        dump_arpcache();
        // debug
        list_for_each_entry_safe(req_entry, q, &arpcache.req_list, list) {
            if (cur_time - req_entry->sent >= 1) {
                if ((++req_entry->retries) > 5) {
                    struct cached_pkt *cpkt = NULL, *cq;
                    list_for_each_entry_safe(cpkt,
                                             cq,
                                             &req_entry->cached_packets,
                                             list) {
                        icmp_send_packet(cpkt->packet,
                                         cpkt->len,
                                         ICMP_DEST_UNREACH,
                                         ICMP_HOST_UNREACH);
                    }
                    delete_list((struct list_head *)(&req_entry->cached_packets),
                                struct cached_pkt,
                                list);
                    list_delete_entry((struct list_head *)req_entry);
                    free(req_entry);
                    req_entry = NULL;
                } else {
                    arp_send_request(req_entry->iface, req_entry->ip4);
                }
            }
        }
        // debug
        fprintf(stdout, "\nAfter arpcache_sweep\n");
        dump_arpcache();
        // debug
        pthread_mutex_unlock(&arpcache.lock);
    // fprintf(stderr, "DONE: sweep arpcache periodically: remove old entries, resend arp requests .\n");
    }
    return NULL;
}
