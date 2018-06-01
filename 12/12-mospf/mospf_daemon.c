/*******************************************************************
 *   This file is deprecated, check branch ping_work, which works
 *   correctly.
 ******************************************************************/
#include "include/mospf_daemon.h"
#include "include/mospf_proto.h"
#include "include/mospf_nbr.h"
#include "include/mospf_database.h"

#include "include/ip.h"

#include "include/list.h"
#include "include/log.h"
#include "include/packet.h"

#include "include/rtable.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#define false 0
#define true 1
// #define __DEBUG__
// #define __DEBUG_HELPERS__

#ifdef __DEBUG__
#define ENTER (0)
#define LEAVE (1)
#endif

#ifdef __DEBUG_HELPERS__
static void dump_nbrs(iface_info_t *iface) {
    mospf_nbr_t *nbr = NULL;
    fprintf(stdout, "iface " IP_FMT " has following nbrs: \n", LE_IP_FMT_STR(iface->ip));
    int i = 0;
    list_for_each_entry(nbr, &iface->nbr_list, list) {
        fprintf(stdout, "nbr %d\n", i++);
        fprintf(stdout, "nbr_ip: " IP_FMT "\n", LE_IP_FMT_STR(nbr->nbr_ip));
        fprintf(stdout, "nbr_id: " IP_FMT "\n", LE_IP_FMT_STR(nbr->nbr_id));
    }
}

static void inspect_forwarding(u32 src, u32 dest, u32 fdest) {
    fprintf(stdout,
            "forwarding packet from " IP_FMT " with dest " IP_FMT " to " IP_FMT "\n",
            LE_IP_FMT_STR(src),
            LE_IP_FMT_STR(dest),
            LE_IP_FMT_STR(fdest));
}

static void inspect_hello_packet(struct iphdr *ip, struct mospf_hello *hello) {
    u32 saddr = ntohl(ip->saddr);
    u32 daddr = ntohl(ip->daddr);
    u32 mask = ntohl(hello->mask);
    fprintf(stdout,
            "Hello packet from " IP_FMT " to " IP_FMT " with mask " IP_FMT "\n",
            LE_IP_FMT_STR(saddr),
            LE_IP_FMT_STR(daddr),
            LE_IP_FMT_STR(mask));
}

static void inspect_lsu_packet(struct iphdr *ip,
                               struct mospf_hdr *hdr,
                               struct mospf_lsu *lsu,
                               struct mospf_lsa *lsa) {
    u32 saddr = ntohl(ip->saddr);
    u32 daddr = ntohl(ip->daddr);

    u32 rid = ntohl(hdr->rid);
    u32 num_of_nbrs = ntohl(lsu->nadv);

    fprintf(stdout,
            "packet from " IP_FMT " to " IP_FMT "\n",
            LE_IP_FMT_STR(saddr), LE_IP_FMT_STR(daddr));
    fprintf(stdout,
            "rid is " IP_FMT "\n",
            LE_IP_FMT_STR(rid));
    fprintf(stdout,
            "having %d nbrs\n",
            num_of_nbrs);
    fprintf(stdout, "nbrs are: \n");
    
    for (u32 i = 0; i < num_of_nbrs; i++) {
        u32 nbr_rid = ntohl(lsa[i].rid);
        u32 nbr_mask = ntohl(lsa[i].mask);
        u32 nbr_subnet = ntohl(lsa[i].subnet);
        fprintf(stdout,
                "nbr rid: " IP_FMT " \n",
                LE_IP_FMT_STR(nbr_rid));
        fprintf(stdout,
                "nbr mask: " IP_FMT " \n",
                LE_IP_FMT_STR(nbr_mask));
        fprintf(stdout,
                "nbr subnet: " IP_FMT " \n",
                LE_IP_FMT_STR(nbr_subnet));
    }
    sleep(2);
}

#define print_packet(packet, len) {                             \
        int i;                                                  \
        fprintf(stdout, "Ether: \n");                           \
        for (i = 0; i < ETHER_HDR_SIZE; i++) {                  \
            fprintf(stdout, "0x%02x ", packet[i] & 0xff);       \
        }                                                       \
        fprintf(stdout, "\n");                                  \
        fprintf(stdout, "IP: \n");                              \
        for (; i < ETHER_HDR_SIZE + IP_BASE_HDR_SIZE; i++) {    \
            fprintf(stdout, "0x%02x ", packet[i] & 0xff);       \
        }                                                       \
        fprintf(stdout, "\n");                                  \
        fprintf(stdout, "MOSPF: \n");                           \
        for (; i < len; i++) {                                  \
            fprintf(stdout, "0x%02x ", packet[i] & 0xff);       \
        }                                                       \
        fprintf(stdout, "\n");                                  \
        fprintf(stdout, "__DEBUG__ print done\n\n");            \
    }

#define track_function(op)                              \
    if ((op) == ENTER) {                                \
        fprintf(stdout,                                 \
                "Enter %s in %s at line: %d\n" ,        \
                __FUNCTION__, __FILE__, __LINE__);      \
    } else if ((op) == LEAVE) {                         \
        fprintf(stdout,                                 \
                "Leave %s in %s at line: %d\n" ,        \
                __FUNCTION__, __FILE__, __LINE__);      \
    }
#endif

#define MALLOC_FAILED(name) {                                           \
        if ((name) == NULL) {                                           \
            fprintf(stdout, "No memory for %s in %s", (#name), __FUNCTION__); \
            exit(-ENOMEM);                                              \
        }                                                               \
    }

extern ustack_t *instance;

static const u8 HELLO_MAC[6] = {0x10, 0x00, 0x5E, 0x00, 0x00, 0x05};

pthread_mutex_t mospf_lock;

void mospf_init()
{
    pthread_mutex_init(&mospf_lock, NULL);
    instance->area_id = 0;
    // get the ip address of the first interface
    iface_info_t *iface = list_entry(instance->iface_list.next, iface_info_t, list);
    instance->router_id = iface->ip;
    instance->sequence_num = 0;
    instance->lsuint = MOSPF_DEFAULT_LSUINT;

    iface = NULL;
    list_for_each_entry(iface, &instance->iface_list, list) {
        iface->helloint = MOSPF_DEFAULT_HELLOINT;
        iface->num_nbr = 0;
        init_list_head(&iface->nbr_list);
    }
    init_mospf_db();
}

void *sending_mospf_hello_thread(void *param);
void *sending_mospf_lsu_thread(void *param);
void *checking_nbr_thread(void *param);

void mospf_run()
{
    pthread_t hello, lsu, nbr;
    pthread_create(&hello, NULL, sending_mospf_hello_thread, NULL);
    pthread_create(&lsu, NULL, sending_mospf_lsu_thread, NULL);
    pthread_create(&nbr, NULL, checking_nbr_thread, NULL);
}

static void init_mospf_ether(char *packet, iface_info_t *iface, u8 mac[ETH_ALEN]) {
    struct ether_header *eth = (struct ether_header *)packet;
    memcpy(eth->ether_dhost, mac, ETH_ALEN);
    memcpy(eth->ether_shost, iface->mac, ETH_ALEN);
    eth->ether_type = htons(ETH_P_IP);
}

static void init_mospf_ip(char *packet, iface_info_t *iface, u32 daddr) {
    struct iphdr *ip = packet_to_ip_hdr(packet);
    u32 saddr = iface->ip;
    ip_init_hdr(ip, saddr, daddr, IP_BASE_HDR_SIZE, IPPROTO_MOSPF);
    ip->checksum = ip_checksum(ip);
}

static void init_mospf_mospfhdr(char *packet, int type, u32 size,
                                u32 rid, u32 area_id) {
    struct mospf_hdr * mospf =
        (struct mospf_hdr *)(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE);
    mospf_init_hdr(mospf,
                   type,
                   size,
                   rid,
                   area_id);
}

static void init_mospf_hello_ether(char *packet, iface_info_t *iface) {
    init_mospf_ether(packet, iface, HELLO_MAC);
}

static void init_mospf_hello_ip(char *packet, iface_info_t *iface) {
    init_mospf_ip(packet, iface, MOSPF_ALLSPFRouters);
}

static void init_mospf_hello_mospfhdr(char *packet) {
    init_mospf_mospfhdr(packet,
                        MOSPF_TYPE_HELLO,
                        MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE,
                        instance->router_id,
                        0);
}

static void init_mospf_hello_hello(char *packet, iface_info_t *iface) {
    char * hdr = packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE;
    struct mospf_hello *hello = (struct mospf_hello *)(hdr + MOSPF_HDR_SIZE);
    mospf_init_hello(hello, iface->mask);
    struct iphdr *ip = packet_to_ip_hdr(packet);
    ip->checksum = ip_checksum(ip);
    struct mospf_hdr *mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));
    mospf->checksum = mospf_checksum(mospf);
}

static void generate_mospf_hello(char *packet, iface_info_t *iface, int len) {
    init_mospf_hello_ether(packet, iface);
    init_mospf_hello_ip(packet, iface);
    init_mospf_hello_mospfhdr(packet);
    init_mospf_hello_hello(packet, iface);
}

static void init_mospf_lsu(char *packet, iface_info_t *iface, int nbrs) {
    struct mospf_lsu *lsu =
        (struct mospf_lsu *)(packet + ETHER_HDR_SIZE +
                             IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE);

    lsu->seq = htons(instance->sequence_num++);
    lsu->ttl = MOSPF_DEFAULT_LSU_TTL;
    lsu->nadv = htonl(nbrs);
}

static void init_mospf_lsa(char *packet, iface_info_t *iface) {
    struct mospf_hdr *hdr =
        (struct mospf_hdr *)(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE);
    struct mospf_lsa *lsa =
        (struct mospf_lsa *)((char *)hdr + MOSPF_HDR_SIZE + MOSPF_LSU_SIZE);
    iface_info_t *walk = NULL;
    int i = 0;
    list_for_each_entry(walk, &instance->iface_list, list) {
        mospf_nbr_t *nbr = NULL;
        if (list_empty(&walk->nbr_list)) {
            lsa[i].mask = htonl(walk->mask);
            lsa[i].rid = 0;
            lsa[i].subnet = htonl(walk->ip & walk->mask);
            i++;
            continue;
        }
        list_for_each_entry(nbr, &walk->nbr_list, list) {
            lsa[i].mask = htonl(nbr->nbr_mask);
            lsa[i].rid = htonl(nbr->nbr_id);
            lsa[i].subnet = htonl(nbr->nbr_ip) & htonl(nbr->nbr_mask);
            i++;
        }
    }
    hdr->checksum = mospf_checksum(hdr);
}

static void bcast_mospf_lsu_packet() {
#ifdef __DEBUG_HELPERS__
    track_function(ENTER);
#endif
    int num_of_nbrs = 0;
    iface_info_t *walk = NULL;
    list_for_each_entry(walk, &instance->iface_list, list) {
        if (list_empty(&walk->nbr_list))
            num_of_nbrs++;
        else
            num_of_nbrs += walk->num_nbr;
    }
    int head_size = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE;
    int message_len = MOSPF_LSU_SIZE + num_of_nbrs * MOSPF_LSA_SIZE;
    int len =  head_size + message_len;

    list_for_each_entry(walk, &instance->iface_list, list) {
        mospf_nbr_t *nbr = NULL;
        list_for_each_entry(nbr, &walk->nbr_list, list) {
            // HELLO_MAC will be replaced
            char *packet = (char *)malloc(len);
            MALLOC_FAILED(packet);
            init_mospf_ether(packet, walk, HELLO_MAC);
            init_mospf_ip(packet, walk, nbr->nbr_ip);
            init_mospf_mospfhdr(packet,
                                MOSPF_TYPE_LSU,
                                MOSPF_HDR_SIZE + message_len,
                                instance->router_id,
                                0);
            init_mospf_lsu(packet, walk, num_of_nbrs);
            init_mospf_lsa(packet, walk);
            iface_send_packet(walk, packet, len);
        }
    }
#ifdef __DEBUG_HELPERS__
    track_function(LEAVE);
#endif
}

static void send_mospf_lsu_packet(iface_info_t *iface) {
    int num_of_nbrs = 0;
    iface_info_t *walk = NULL;
    list_for_each_entry(walk, &instance->iface_list, list) {
        if (list_empty(&walk->nbr_list))
            num_of_nbrs++;
        else
            num_of_nbrs += walk->num_nbr;
    }
    int head_size = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE;
    int message_len = MOSPF_LSU_SIZE + num_of_nbrs * MOSPF_LSA_SIZE;
    int len =  head_size + message_len;
    
    list_for_each_entry(walk, &instance->iface_list, list) {
        mospf_nbr_t *nbr = NULL;
        if (iface == walk)
            continue;
        list_for_each_entry(nbr, &walk->nbr_list, list) {
            // HELLO_MAC will be replaced
            char *packet = (char *)malloc(len);
            MALLOC_FAILED(packet);
            init_mospf_ether(packet, walk, HELLO_MAC);
            init_mospf_ip(packet, walk, nbr->nbr_ip);
            init_mospf_mospfhdr(packet,
                                MOSPF_TYPE_LSU,
                                MOSPF_HDR_SIZE + message_len,
                                instance->router_id,
                                0);
            init_mospf_lsu(packet, walk, num_of_nbrs);
            init_mospf_lsa(packet, walk);
            iface_send_packet(walk, packet, len);
        }
    }
}

void *sending_mospf_hello_thread(void *param)
{
#ifdef __DEBUG__
    track_function(ENTER);
#endif
    while(1) {
        int len =
            ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE;

        iface_info_t *iface = NULL;
        list_for_each_entry(iface, &instance->iface_list, list) {
            char *packet = (char*)malloc(len);
            MALLOC_FAILED(packet);
            generate_mospf_hello(packet, iface, len);
            iface_send_packet(iface, packet, len);        
        }

        sleep(MOSPF_DEFAULT_HELLOINT);
    }
#ifdef __DEBUG__
    track_function(LEAVE);
#endif
    return NULL;
}

void *checking_nbr_thread(void *param)
{
#ifdef __DEBUG__
    track_function(ENTER);
#endif
    iface_info_t *iface = NULL, *q = NULL, *qq = NULL;
    mospf_nbr_t *nbr = NULL;
    int removed = 0;
    
    pthread_mutex_lock(&mospf_lock);
    list_for_each_entry_safe(iface, q, &instance->iface_list, list) {
        int hello_interval = iface->helloint;
        list_for_each_entry_safe(nbr, qq, &iface->nbr_list, list) {
            if (++nbr->alive >= 3 * hello_interval) {
                mospf_db_entry_t *db = NULL, *dq = NULL;
                list_for_each_entry_safe(db, dq, &mospf_db, list) {
                    if (db->rid == nbr->nbr_id) {
                        list_delete_entry(&db->list);
                        free(db->array);
                        free(db);
                        break;
                    }
                }
                list_delete_entry(&nbr->list);
                free(nbr);
                iface->num_nbr--;
            }
        }
    }

    pthread_mutex_unlock(&mospf_lock);
    if (removed) {
        bcast_mospf_lsu_packet();
    }
#ifdef __DEBUG__
    track_function(LEAVE);
#endif
    // fprintf(stdout, "DONE: neighbor list timeout operation.\n");
    return NULL;
}


void handle_mospf_hello(iface_info_t *iface, const char *packet, int len)
{
#ifdef __DEBUG__
    track_function(ENTER);
#endif
    struct iphdr *ip = packet_to_ip_hdr(packet);
    struct mospf_hdr *hdr =
        (struct mospf_hdr *)(packet + ETHER_HDR_SIZE + IP_HDR_SIZE(ip));
    struct mospf_hello *hello =
        (struct mospf_hello *)((char*)hdr + MOSPF_HDR_SIZE);
    u32 id = ntohl(hdr->rid);
#ifdef __DEBUG_HELPERS__
    inspect_hello_packet(ip, hello);
#endif
    mospf_nbr_t *nbr = NULL;
    list_for_each_entry(nbr, &iface->nbr_list, list) {
        if (nbr->nbr_id == id) {
#ifdef __DEBUG__
            track_function(LEAVE);
#endif
            return;
        }
    }
    pthread_mutex_lock(&mospf_lock);
    nbr = (mospf_nbr_t *) malloc(sizeof(mospf_nbr_t));
    MALLOC_FAILED(nbr);
    iface->num_nbr++;
    nbr->alive = 0;
    nbr->nbr_id = ntohl(hdr->rid);
    nbr->nbr_ip = ntohl(ip->saddr);
    nbr->nbr_mask = ntohl(hello->mask);
    fprintf(stdout, "iface added " IP_FMT " to its nbr list\n", LE_IP_FMT_STR(nbr->nbr_ip));
    list_add_tail(&nbr->list, &iface->nbr_list);
#ifdef __DEBUG_HELPERS__
    dump_nbrs(iface);
#endif
    pthread_mutex_unlock(&mospf_lock);
    send_mospf_lsu_packet(iface);
#ifdef __DEBUG__
    track_function(LEAVE);
#endif
    // fprintf(stdout, "DONE: handle mOSPF Hello message.\n");
}

static void dump_database() {
#ifdef __DEBUG__
    track_function(ENTER);
#endif
    mospf_db_entry_t *db = NULL;
    list_for_each_entry(db, &mospf_db, list) {
        fprintf(stdout, "Database entry IP " IP_FMT " \n", LE_IP_FMT_STR(db->rid));
        for (int i = 0; i < db->nadv; i++) {
            fprintf(stdout,
                    "nbt rid: " IP_FMT " \n",
                    LE_IP_FMT_STR(db->array[i].rid));
            fprintf(stdout,
                    "nbr mask: " IP_FMT " \n",
                    LE_IP_FMT_STR(db->array[i].mask));
            fprintf(stdout,
                    "nbt subnet: " IP_FMT " \n",
                    LE_IP_FMT_STR(db->array[i].subnet));
        }
    }
    fprintf(stdout, "\n");
#ifdef __DEBUG__
    track_function(LEAVE);
#endif
}

void *sending_mospf_lsu_thread(void *param)
{
    
    while(1) {
#ifdef __DEBUG__
        track_function(ENTER);
#endif
        bcast_mospf_lsu_packet();
        sleep(MOSPF_DEFAULT_LSUINT);
#ifdef __DEBUG__
        track_function(LEAVE);
#endif
    }
    // fprintf(stdout, "DONE: send mOSPF LSU message periodically.\n");
    return NULL;
}



static void update_database(iface_info_t *iface, char *packet, int len) {
    struct iphdr *ip = packet_to_ip_hdr(packet);
    struct mospf_hdr *hdr =
        (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));
    struct mospf_lsu* lsu =
        (struct mospf_lsu *)((char *)hdr + MOSPF_HDR_SIZE);
    struct mospf_lsa* lsa =
        (struct mospf_lsa *)((char *)lsu + MOSPF_LSU_SIZE);
    u32 ird = ntohl(hdr->rid);
    u16 seq = ntohs(lsu->seq);
    u32 num_of_nbrs = ntohl(lsu->nadv);

#ifdef __DEBUG_HELPERS__
    inspect_lsu_packet(ip, hdr, lsu, lsa);
#endif
    mospf_db_entry_t *db = NULL;
    int found = 0;
    list_for_each_entry(db, &mospf_db, list) {
        if (db->rid == ird) {
            found = 1;
            break;
        }
    }

    pthread_mutex_lock(&mospf_lock);
    if (found) {
        if (seq > db->seq) {
            db->seq = seq;
            db->nadv = num_of_nbrs;
            db->array = (struct mospf_lsa *)realloc(db->array,
                                                    num_of_nbrs * MOSPF_LSA_SIZE);
        } else {
            pthread_mutex_unlock(&mospf_lock);
            return ;
        }
    } else {
        db = (struct mospf_db_entry_t *)malloc(sizeof(mospf_db_entry_t));
        MALLOC_FAILED(db);
        db->array =
            (struct mospf_lsa *)malloc(num_of_nbrs * MOSPF_LSA_SIZE);
        MALLOC_FAILED(db->array);
        db->rid = ird;
        db->nadv = num_of_nbrs;
        db->seq = seq;
        list_add_tail(&db->list, &mospf_db);
    }

    for (int i = 0; i < num_of_nbrs; i++) {
        db->array[i].mask = ntohl(lsa[i].mask);
        db->array[i].rid = ntohl(lsa[i].rid);
        db->array[i].subnet = ntohl(lsa[i].subnet);
    }
    dump_database();
    pthread_mutex_unlock(&mospf_lock);
}


static void forward_lsu(iface_info_t *iface, char *packet, int len) {
#ifdef __DEBUG__
    track_function(ENTER);
#endif    
    struct iphdr *ip = NULL;
    struct mospf_hdr *hdr = NULL;
    char *pkt = NULL;
    mospf_nbr_t *nbr = NULL;
    list_for_each_entry(nbr, &iface->nbr_list, list) {
        pkt = (char *)malloc(len);
        MALLOC_FAILED(pkt);
        memcpy(pkt, packet, len);
        ip = packet_to_ip_hdr(pkt);
#ifdef __DEBUG_HELPERS__
        inspect_forwarding(ntohl(ip->saddr), ntohl(ip->daddr), nbr->nbr_ip);
#endif
        /* if (ntohl(ip->saddr) == nbr->nbr_ip) */
        /*     continue; */
        hdr = (struct mospf_hdr *)((char*)ip + IP_HDR_SIZE(ip));
        ip->daddr = htonl(nbr->nbr_ip);
        ip->checksum = ip_checksum(ip);
        hdr->checksum = mospf_checksum(hdr);
        ip_send_packet(pkt, len);
        pkt = NULL;
    }
#ifdef __DEBUG__
    track_function(LEAVE);
#endif    
}


static int mark_router_to_host(int *distance){
    mospf_db_entry_t *db = NULL;
    int idx = 0;
    int marked = 0;
    list_for_each_entry(db, &mospf_db, list) {
        for (int i = 0; i < db->nadv; i++, idx++) {
            if (db->array[i].rid == 0) {
                distance[idx] = 1;
                marked = 1;
            }
        }
    }
    return marked;
}

static int rid_to_index(u32 rid) {
    return rid & 0x000000f;
}

static int find_nearest_entry(int *visited, int *distance, int num) {
    int dis = INT32_MAX;
    int idx = 0;
    for (int i = 0; i < num; i++) {
        if (dis > distance[i] && visited[i] == false) {
            dis = distance[i];
            idx = i;
        }
    }
    return idx;
}

static mospf_db_entry_t *index_to_db_entry(int index) {
    mospf_db_entry_t *db = NULL;
    list_for_each_entry(db, &mospf_db, list) {
        if (rid_to_index(db->rid) == index)
            return db;
    }
}

static void mark_all_nbrs(int nearest, int *visited, int *distance, int num) {
    int index = 0;
    mospf_db_entry_t *nr = index_to_db_entry(nearest);
    for (int i = 0; i < nr->nadv; i++) {
        index = rid_to_index(nr->array[i].rid);
        if (visited[i] == false && distance[index] > distance[nearest] + 1 &&
            distance[nearest] != INT32_MAX) {
            distance[index] = distance[nearest] + 1;
        }
    }
}

static u32 find_host_subnet() {
    mospf_db_entry_t *db = NULL;
    list_for_each_entry(db, &mospf_db, list) {
        for (int i = 0; i < db->nadv; i++) {
            if (db->array[i].rid == 0)
                return db->array[i].subnet;
        }
    }
}

static u32 find_host_mask() {
    mospf_db_entry_t *db = NULL;
    list_for_each_entry(db, &mospf_db, list) {
        for (int i = 0; i < db->nadv; i++) {
            if (db->array[i].rid == 0)
                return db->array[i].mask;
        }
    }
}

static mospf_nbr_t *find_best_nbr(iface_info_t *iface, int *distance) {
    mospf_nbr_t *nbr = NULL;
    mospf_nbr_t *best = NULL;
    int best_distance = INT32_MAX;
    list_for_each_entry(nbr, &iface->nbr_list, list) {
        if (distance[rid_to_index(nbr->nbr_id)] <= best_distance) {
            best_distance = distance[rid_to_index(nbr->nbr_id)];
            best = nbr;
        }
    }
    return best;
}

static void add_new_entry(mospf_nbr_t *best, iface_info_t *iface) {
    rt_entry_t *old_entry = longest_prefix_match(find_host_subnet());
     if(old_entry != NULL) {
        return;
    }
        
    rt_entry_t *new_entry = (rt_entry_t *)malloc(sizeof(rt_entry_t));
    MALLOC_FAILED(new_entry);
    new_entry->dest = find_host_subnet();
    new_entry->mask = find_host_mask();
    new_entry->gw = best->nbr_ip;
    strcpy(new_entry->if_name, iface->name);
    new_entry->flags = 0;
    add_rt_entry(new_entry);
}

void update_rtable(iface_info_t *iface){
    if (list_empty(&mospf_db))
        return;
    
    pthread_mutex_lock(&mospf_lock);
    int num_of_entries = 0;
    int router_to_host = -1;
    int index = 0;
    mospf_db_entry_t *dbe = NULL;
    list_for_each_entry(dbe, &mospf_db, list) {
        num_of_entries++;
    }
    num_of_entries++;
    
    int *visited = (int *)malloc(num_of_entries * sizeof(int));
    MALLOC_FAILED(visited);
    int *distance = (int *)malloc(num_of_entries * sizeof(int));
    MALLOC_FAILED(distance);
    int *prev = (int *)malloc(num_of_entries * sizeof(int));
    MALLOC_FAILED(prev);
    for (int i = 0; i < num_of_entries; i++) {
        visited[i] = false;
        distance[i] = INT32_MAX;
        prev[i] = -1;
    }
    
    if (!mark_router_to_host(distance)) {
        fprintf(stdout, "Host is not detected yet\n");
        free(visited);
        free(distance);
        pthread_mutex_unlock(&mospf_lock);
        return;
    }

    // find the shortest path from dest to source
    for (int i = 0; i < num_of_entries-2; i++) {
        int nearest = find_nearest_entry(visited, distance, num_of_entries);
        visited[nearest] = true;
        mark_all_nbrs(nearest, visited, distance, num_of_entries);
    }

    // find the nearest nbr
    mospf_nbr_t *best = find_best_nbr(iface, distance);
    if (best == NULL) {
        free(visited);
        free(distance);
        pthread_mutex_unlock(&mospf_lock);
        return;           // nbrs are not detected yet
    }
    // add new rtable ENTRIES(notice that more than one entry might be added)
    // to rtable
    add_new_entry(best, iface);
    print_rtable();
    free(visited);
    free(distance);
    pthread_mutex_unlock(&mospf_lock);
}

void handle_mospf_lsu(iface_info_t *iface, char *packet, int len)
{
#ifdef __DEBUG__
    track_function(ENTER);
#endif
    struct iphdr *in_ip = packet_to_ip_hdr(packet);
    struct mospf_hdr *hdr =
        (struct mospf_hdr *)((char *)in_ip + IP_HDR_SIZE(in_ip));
    struct mospf_lsu *lsu = (struct mospf_lsu *)((char *)hdr + MOSPF_HDR_SIZE);
    if (--lsu->ttl <= 0 || (instance->router_id == ntohl(hdr->rid))) {
        return ;
    } else {
        hdr->checksum = mospf_checksum(hdr);
    }
    update_database(iface, packet, len);
    iface_info_t *walk = NULL;
    char *new_packet = NULL;
    list_for_each_entry(walk, &instance->iface_list, list) {
        if (walk != iface) {
            char *new_packet = (char *)malloc(len * sizeof(char));
            MALLOC_FAILED(new_packet);
            memcpy(new_packet, packet, len);
            forward_lsu(walk, new_packet, len);
            new_packet = NULL;
        }
    }
    update_rtable(iface);
#ifdef __DEBUG__
    track_function(LEAVE);
#endif
    // fprintf(stdout, "DONE: handle mOSPF LSU message.\n");
}

void handle_mospf_packet(iface_info_t *iface, char *packet, int len)
{
    struct iphdr *ip = (struct iphdr *)(packet + ETHER_HDR_SIZE);
    struct mospf_hdr *mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));

    if (mospf->version != MOSPF_VERSION) {
        log(ERROR, "received mospf packet with incorrect version (%d)", mospf->version);
        return ;
    }
    if (mospf->checksum != mospf_checksum(mospf)) {
        log(ERROR, "received mospf packet with incorrect checksum");
        return ;
    }
    if (ntohl(mospf->aid) != instance->area_id) {
        log(ERROR, "received mospf packet with incorrect area id");
        return ;
    }

    // log(DEBUG, "received mospf packet, type: %d", mospf->type);

    switch (mospf->type) {
    case MOSPF_TYPE_HELLO:
        handle_mospf_hello(iface, packet, len);
        break;
    case MOSPF_TYPE_LSU:
        handle_mospf_lsu(iface, packet, len);
        break;
    default:
        log(ERROR, "received mospf packet with unknown type (%d).", mospf->type);
        break;
    }

}
