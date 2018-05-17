#include "include/nat.h"
#include "include/ip.h"
#include "include/icmp.h"
#include "include/tcp.h"
#include "include/rtable.h"
#include "include/log.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

static struct nat_table nat;

// get the interface from iface name
static iface_info_t *if_name_to_iface(const char *if_name)
{
    iface_info_t *iface = NULL;
    list_for_each_entry(iface, &instance->iface_list, list) {
        if (strcmp(iface->name, if_name) == 0)
            return iface;
    }
 
    log(ERROR, "Could not find the desired interface according to if_name '%s'", if_name);
    return NULL;
}

static void print_log(char *in) {
    fprintf(stdout, "%s", in);
}

// determine the direction of the packet, DIR_IN / DIR_OUT / DIR_INVALID
static int get_packet_direction(char *packet)
{
    print_log("Enter get_packet_direction\n");
    struct iphdr * ip = packet_to_ip_hdr(packet);
    u32 saddr = ntohl(ip->saddr);
    u32 daddr = ntohl(ip->daddr);
    rt_entry_t *entry_to_d = longest_prefix_match(daddr);
    rt_entry_t *entry_to_s = longest_prefix_match(saddr);
    if (strcmp(entry_to_s->iface->name, nat.internal_iface->name) == 0) {
        if (strcmp(entry_to_d->iface->name, nat.external_iface->name) == 0) {
            return DIR_OUT;
        }
    }
    else if (strcmp(entry_to_s->iface->name, nat.external_iface->name) == 0 &&
             strcmp(entry_to_d->iface->name, nat.external_iface->name) == 0) {
        return DIR_IN;
    }
    
    // fprintf(stdout, "TODO: determine the direction of this packet.\n");
    print_log("Leave get_packet_direction\n");
    return DIR_INVALID;
}

static int assign_external_port() {
    print_log("Enter assign_external_port\n");
    for (int i = 0; i < 65536; i++) {
        if (nat.assigned_ports[i] == 0)
            return i + 1;
    }
    fprintf(stdout, "Not enough ports\n");
    print_log("Leave assign_external_port\n");
    exit(-1);
}

static void to_public(iface_info_t *iface, char *packet, int len) {
    print_log("Enter to_public\n");
    struct iphdr *ip = packet_to_ip_hdr(packet);
    struct tcphdr *tcp = packet_to_tcp_hdr(packet);
    u32 private_saddr = ntohl(ip->saddr);
    u32 public_daddr = ntohl(ip->daddr);
    u32 private_sport = ntohs(tcp->sport);
    int hash_index = hash8((char*)&public_daddr, 4);
    struct nat_mapping * mapping = NULL;
    if (list_empty(&nat.nat_mapping_list[hash_index])) {
        pthread_mutex_lock(&nat.lock);
        struct nat_mapping *new_mapping =
            (struct nat_mapping *) malloc(sizeof(struct nat_mapping));
        new_mapping->internal_ip = private_saddr;
        new_mapping->external_ip = nat.external_iface->ip;
        new_mapping->internal_port = private_sport;
        new_mapping->external_port = assign_external_port();
        new_mapping->update_time = time(NULL);
        memset(&new_mapping->conn, 0, sizeof(struct nat_connection));
        list_add_tail(&new_mapping->list, &nat.nat_mapping_list[hash_index]);
        pthread_mutex_unlock(&nat.lock);
    }
    
//     struct nat_mapping * mapping =
//         (struct nat_mapping *)nat.nat_mapping_list[hash_index].next;
//     mapping->update_time = time(NULL);
    struct list_head *p = nat.nat_mapping_list[hash_index].next;
    int found = 0;
    while (p != &nat.nat_mapping_list[hash_index]) {
        mapping = (struct nat_mapping *)p;
        if (mapping->internal_ip == private_saddr &&
            mapping->internal_port == private_sport){
            found = 1;
            break;
        }
        p = p->next;
    }

    if (!found) {
        print_log("No translation entry found\n");
        exit(-1);
    }

    pthread_mutex_unlock(&nat.lock);
    ip->saddr = htonl(nat.external_iface->ip);
    tcp->sport = htons(mapping->external_port);
    ip->checksum = ip_checksum(ip);
    tcp->checksum = tcp_checksum(ip, tcp);
    ip_send_packet(packet, len);
    print_log("Leave to_public\n");
}

static void to_private(iface_info_t *iface, char *packet, int len) {
    print_log("Enter to_private\n");
    struct iphdr *ip = packet_to_ip_hdr(packet);
    struct tcphdr *tcp = packet_to_tcp_hdr(packet);
    u32 public_saddr = ntohl(ip->saddr);
    u32 private_daddr = ntohl(ip->daddr);
    u16 private_dport = ntohs(tcp->dport);
    int hash_index = hash8((char*)&public_saddr, 4);

    if (list_empty(&nat.nat_mapping_list[hash_index])) {
        icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
        return;
    }

    struct nat_mapping * mapping = NULL;
    
    struct list_head *p = nat.nat_mapping_list[hash_index].next;
    int found = 0;
    while (p != &nat.nat_mapping_list[hash_index]) {
        mapping = (struct nat_mapping *)p;
        if (mapping->external_ip == private_daddr &&
            mapping->external_port == private_dport){
            found = 1;
            break;
        }
        p = p->next;
    }

    if (!found) {
        print_log("No translation entry found\n");
        exit(-1);
    }

    
    pthread_mutex_lock(&nat.lock);
    mapping->update_time = time(NULL);
    pthread_mutex_unlock(&nat.lock);
    
    ip->daddr = htonl(mapping->internal_ip);
    tcp->dport = htons(mapping->internal_port);
    ip->checksum = ip_checksum(ip);
    tcp->checksum = tcp_checksum(ip, tcp);
    ip_send_packet(packet, len);
    print_log("Leave to_public\n");
}

// do translation for the packet: replace the ip/port, recalculate ip & tcp
// checksum, update the statistics of the tcp connection
void do_translation(iface_info_t *iface, char *packet, int len, int dir)
{
    print_log("Enter do_translation\n");
    if (dir == DIR_IN) {
        to_private(iface, packet, len);
    } else if (dir == DIR_OUT){
        to_public(iface, packet, len);
    } else {
        icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
    }
    print_log("Leave do_translation\n");
    // fprintf(stdout, "TODO: do translation for this packet.\n");
}

void nat_translate_packet(iface_info_t *iface, char *packet, int len)
{

    int dir = get_packet_direction(packet);
    if (dir == DIR_INVALID) {
        log(ERROR, "invalid packet direction, drop it.");
        icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
        free(packet);
        return ;
    }

    struct iphdr *ip = packet_to_ip_hdr(packet);
    if (ip->protocol != IPPROTO_TCP) {
        log(ERROR, "received non-TCP packet (0x%0hhx), drop it", ip->protocol);
        free(packet);
        return ;
    }

    do_translation(iface, packet, len, dir);
}

// nat timeout thread: find the finished flows, remove them and free port
// resource
void *nat_timeout()
{
    print_log("Enter nat_timeout\n");
    print_rtable();        
    while (1) {
        pthread_mutex_lock(&nat.lock);
        for (int i = 0; i < 256; i++) {
            struct nat_mapping *mapping;
            list_for_each_entry(mapping, &nat.nat_mapping_list[i], list) {
                if ((mapping->conn.external_ack &&
                    mapping->conn.external_fin &&
                    mapping->conn.internal_ack &&
                    mapping->conn.internal_fin) ||
                    time(NULL) - mapping->update_time >= 60) {
                    list_delete_entry(&mapping->list);
                    free(mapping);
                }
            }
        }
        pthread_mutex_unlock(&nat.lock);
        sleep(1);
    }
    print_log("Leave nat_timeout\n");
    return NULL;
}

// initialize nat table
void nat_table_init()
{
    memset(&nat, 0, sizeof(nat));

    for (int i = 0; i < HASH_8BITS; i++)
        init_list_head(&nat.nat_mapping_list[i]);

    nat.internal_iface = if_name_to_iface("n1-eth0");
    nat.external_iface = if_name_to_iface("n1-eth1");
    if (!nat.internal_iface || !nat.external_iface) {
        log(ERROR, "Could not find the desired interfaces for nat.");
        exit(1);
    }

    memset(nat.assigned_ports, 0, sizeof(nat.assigned_ports));

    pthread_mutex_init(&nat.lock, NULL);

    pthread_create(&nat.thread, NULL, nat_timeout, NULL);
}

// destroy nat table
void nat_table_destroy()
{
    pthread_mutex_lock(&nat.lock);

    for (int i = 0; i < HASH_8BITS; i++) {
        struct list_head *head = &nat.nat_mapping_list[i];
        struct nat_mapping *mapping_entry, *q;
        list_for_each_entry_safe(mapping_entry, q, head, list) {
            list_delete_entry(&mapping_entry->list);
            free(mapping_entry);
        }
    }

    pthread_kill(nat.thread, SIGTERM);

    pthread_mutex_unlock(&nat.lock);
}
