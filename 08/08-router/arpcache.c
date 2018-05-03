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

// DO NOT USE MACRO delete_list

static arpcache_t arpcache;

static void check_packet(char* pkt, int len) {
    for (int i = 0; i < len; i++) {
        fprintf(stdout, "%c",pkt[i]);
    }
    fprintf(stdout, "\n");
}

static void dump_arpcache() {
    fprintf(stdout, "dumping arpcache\n");
    struct arp_req *req_entry = NULL, *req_q;
    list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list) {
        fprintf(stdout, "req_entry->ip4: %ud\n", req_entry->ip4);
        fprintf(stdout, "requests of %ud:\n", req_entry->ip4);
        struct cached_pkt *cpkt = NULL, *cq;
        list_for_each_entry_safe(cpkt, cq, &req_entry->cached_packets, list){
            fprintf(stdout, "pending packet: %p: ", cpkt->packet);
            check_packet(cpkt->packet, cpkt->len);
        }
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
    memcpy(cpkt->packet, packet, len);

// same ip and same interface
    struct arp_req *req = NULL;
    struct arp_req *req_entry = NULL, *req_q;
    pthread_mutex_lock(&arpcache.lock);
    
    list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list) {
        if (req_entry->ip4 == ip4 && req_entry->iface == iface) {
            list_add_tail(&cpkt->list, &(req_entry->cached_packets));
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

    init_list_head(&req->cached_packets);
    init_list_head(&req->list);
    list_add_tail(&cpkt->list, &(req->cached_packets));
    req->ip4 = ip4;
    req->iface = iface;
    req->sent = time(NULL);
    req->retries = 1;
    list_add_tail(&req->list, &(arpcache.req_list));
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
    list_for_each_entry_safe(req_entry, q, &(arpcache.req_list), list) {
        if (req_entry->ip4 == ip4) {
            struct cached_pkt *cpkt = NULL, *cq;
            list_for_each_entry_safe(cpkt, cq, &req_entry->cached_packets, list){
                struct ether_header *eh = (struct ether_header *)cpkt->packet;
                memcpy(eh->ether_dhost, mac, ETH_ALEN);
                iface_send_packet(req_entry->iface, cpkt->packet, cpkt->len);
                list_delete_entry(&cpkt->list);
                // do not free here, or you would see double free
            }
            list_delete_entry(&req_entry->list);
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
    pthread_mutex_unlock(&arpcache.lock);
    fprintf(stdout, "arpcache_insert unlock\n");
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
        list_for_each_entry_safe(req_entry, q, &arpcache.req_list, list) {
            if (cur_time - req_entry->sent >= 1) {
                if ((++req_entry->retries) > 5) {
                    struct cached_pkt *cpkt = NULL, *cq;
                    list_for_each_entry_safe(cpkt,
                                             cq,
                                             &req_entry->cached_packets,
                                             list) {
                        pthread_mutex_unlock(&arpcache.lock);
                        icmp_send_packet(cpkt->packet,
                                         cpkt->len,
                                         ICMP_DEST_UNREACH,
                                         ICMP_HOST_UNREACH);
                        pthread_mutex_lock(&arpcache.lock);
                        list_delete_entry(&(cpkt->list));
                        free(cpkt->packet);
                        cpkt->packet = NULL;
                    }
                } else {
                    arp_send_request(req_entry->iface, req_entry->ip4);
                }
            }
            if (list_empty(&req_entry->list)) {
                list_delete_entry(&req_entry->list);
                free(req_entry);
                req_entry = NULL;
            }
        }
        pthread_mutex_unlock(&arpcache.lock);
    }
    return NULL;
}
