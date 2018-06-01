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

#define NUM_OF_NODES 4
#define false 0
#define true 1
// #define __DEBUG__
#define __DEBUG_HELPERS__

#ifdef __DEBUG__
#define ENTER (0)
#define LEAVE (1)
#endif

#ifdef __DEBUG_HELPERS__
static void dump_distance(int *dis, int size) {
    for (int i = 0; i < size; i++) {
        fprintf(stdout, "%d ", dis[i]);
    }
    fprintf(stdout, "\n");
}

static void dump_matrix(int **matrix, int size) {
    for (int i = 0; i < size; i++) {
        for (int j = 0; j < size; j++) {
            fprintf(stdout, "%d ", matrix[i][j]);
        }
        fprintf(stdout, "\n");
    }
}

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

static void inspect_ip(u32 ip) {
    fprintf(stdout, IP_FMT "\n", LE_IP_FMT_STR(ip));
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

static void dump_database() {
    mospf_db_entry_t *db = NULL;
    fprintf(stdout,
            "------------------------------------------------------------\n");
    list_for_each_entry(db, &mospf_db, list) {
        fprintf(stdout,
                "database entry      nbr rid      nbr mask      nbr subnet\n");
        for (int i = 0; i < db->nadv; i++) {
            fprintf(stdout, IP_FMT "   ", LE_IP_FMT_STR(db->rid));
            fprintf(stdout, IP_FMT "   ", LE_IP_FMT_STR(db->array[i].rid));
            fprintf(stdout, IP_FMT "   ", LE_IP_FMT_STR(db->array[i].mask));
            fprintf(stdout, IP_FMT "\n", LE_IP_FMT_STR(db->array[i].subnet));
        }
    }
    fprintf(stdout,
            "------------------------------------------------------------\n");
}

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
    return NULL;
}

void *checking_nbr_thread(void *param)
{
    iface_info_t *iface = NULL, *q = NULL;
    mospf_nbr_t *nbr = NULL, *qq = NULL;
    int removed = 0;
    while(1) {
        sleep(5);
        pthread_mutex_lock(&mospf_lock);
        list_for_each_entry_safe(iface, q, &instance->iface_list, list) {
            int hello_interval = iface->helloint;
            list_for_each_entry_safe(nbr, qq, &iface->nbr_list, list) {
                fprintf(stdout, "nbr " IP_FMT " has lived for %d, ttl is %d\n",
                        LE_IP_FMT_STR(nbr->nbr_id),
                        nbr->alive+5,
                        3 * hello_interval);
                nbr->alive += 5;
                if (nbr->alive >= 3 * hello_interval) {
                    removed = 1;
                    mospf_db_entry_t *db = NULL, *dq = NULL;
                    list_for_each_entry_safe(db, dq, &mospf_db, list) {
                        if (db->rid == nbr->nbr_id) {
                            list_delete_entry(&db->list);
                            free(db->array);
                            free(db);
                            break;
                        }
                    }
                    // once the neighbor is offline
                    // remove rtable entries using this neighbor as gateway
                    rt_entry_t *rt = NULL, *rq = NULL;
                    list_for_each_entry_safe(rt, rq, &rtable, list) {
                        if (rt->gw == nbr->nbr_ip) {
                            remove_rt_entry(rt);
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
            fprintf(stdout, "a nbr is offline\n");
            dump_database();
            bcast_mospf_lsu_packet();
            removed = 0;
        }
    }
    // fprintf(stdout, "DONE: neighbor list timeout operation.\n");
    return NULL;
}


void handle_mospf_hello(iface_info_t *iface, const char *packet, int len)
{
    struct iphdr *ip = packet_to_ip_hdr(packet);
    struct mospf_hdr *hdr =
        (struct mospf_hdr *)(packet + ETHER_HDR_SIZE + IP_HDR_SIZE(ip));
    struct mospf_hello *hello =
        (struct mospf_hello *)((char*)hdr + MOSPF_HDR_SIZE);
    u32 id = ntohl(hdr->rid);
    fprintf(stdout, "Hello from " IP_FMT "\n", LE_IP_FMT_STR(id));
    mospf_nbr_t *nbr = NULL;
    pthread_mutex_lock(&mospf_lock);
    list_for_each_entry(nbr, &iface->nbr_list, list) {
        if (nbr->nbr_id == id) {
            nbr->alive = 0;
            pthread_mutex_unlock(&mospf_lock);
            return;
        }
    }

    nbr = (mospf_nbr_t *) malloc(sizeof(mospf_nbr_t));
    MALLOC_FAILED(nbr);
    iface->num_nbr++;
    nbr->alive = 0;
    nbr->nbr_id = ntohl(hdr->rid);
    nbr->nbr_ip = ntohl(ip->saddr);
    nbr->nbr_mask = ntohl(hello->mask);
    list_add_tail(&nbr->list, &iface->nbr_list);
    pthread_mutex_unlock(&mospf_lock);
    send_mospf_lsu_packet(iface);
    // fprintf(stdout, "DONE: handle mOSPF Hello message.\n");
}

void *sending_mospf_lsu_thread(void *param)
{
    
    while(1) {
        bcast_mospf_lsu_packet();
        sleep(MOSPF_DEFAULT_LSUINT);
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
    struct iphdr *ip = NULL;
    struct mospf_hdr *hdr = NULL;
    char *pkt = NULL;
    mospf_nbr_t *nbr = NULL;
    list_for_each_entry(nbr, &iface->nbr_list, list) {
        pkt = (char *)malloc(len);
        MALLOC_FAILED(pkt);
        memcpy(pkt, packet, len);
        ip = packet_to_ip_hdr(pkt);
        /* if (ntohl(ip->saddr) == nbr->nbr_ip) */
        /*     continue; */
        hdr = (struct mospf_hdr *)((char*)ip + IP_HDR_SIZE(ip));
        ip->daddr = htonl(nbr->nbr_ip);
        ip->checksum = ip_checksum(ip);
        hdr->checksum = mospf_checksum(hdr);
        ip_send_packet(pkt, len);
        pkt = NULL;
    }
}


static inline int rid_to_index(u32 rid) {
    return rid & 0x000000ff;
}

static void record_neighbors(int **matrix, int size) {
    iface_info_t *iface = NULL;
    list_for_each_entry(iface, &instance->iface_list, list) {
        mospf_nbr_t *nbr = NULL;
        list_for_each_entry(nbr, &iface->nbr_list, list) {
            if (nbr->nbr_id == 0)
                continue;
            else {
                int root_row = rid_to_index(instance->router_id);
                matrix[root_row][rid_to_index(nbr->nbr_id)] = 1;
                matrix[rid_to_index(nbr->nbr_id)][root_row] = 1;
            }
        }
    }
}

static void db_to_matrix(int **matrix, int size) {
    record_neighbors(matrix, size);   // iface is not in db, add it manually
    mospf_db_entry_t *db = NULL;
    list_for_each_entry(db, &mospf_db, list) {
        int row = rid_to_index(db->rid);
        int column = 0;
        for (int i = 0; i < db->nadv; i++) {
            if (db->array[i].rid == 0)
                continue;     // we do not handle host nodes here
            else {
                column = rid_to_index(db->array[i].rid);
                matrix[row][column] = 1;
            }
        }
    }
}

static int find_nearest(int *distance, int *visited, int size) {
    int min = INT32_MAX;
    int index = 1;
    for (int i = 1; i < size; i++) {
        if (min >= distance[i] && visited[i] == false) {
            min = distance[i];
            index = i;
        }
    }
    return index;
}

static void dijkstra(int *visited, int *distance, int *prev,
                     int **matrix, int size) {
    // be careful
    // here we begin with 1 rather than 0;
    for (int i = 1; i < size; i++) {
        visited[i] = false;
        distance[i] = INT32_MAX;
        prev[i] = -1;
    }
    int root_index = rid_to_index(instance->router_id);
    visited[root_index] = true;
    for (int j = 1; j < size; j++) {
            distance[j] = matrix[root_index][j];
            if (distance[j] != INT32_MAX)
                prev[j] = root_index;
    }

    for (int i = 1; i < size-1; i++) {
        int nearest = find_nearest(distance, visited, size);
        visited[nearest] = true;
        for (int j = 1; j < size; j++) {
            if (visited[j] == false &&
                matrix[nearest][j] != INT32_MAX &&
                distance[nearest] + matrix[nearest][j] < distance[j]) {
                distance[j] = distance[nearest] + matrix[nearest][j];
                prev[j] = nearest;
            }
        }
    }
}

static int find_shortest_path_then_delete(int *distance, int size) {
    int min = INT32_MAX;
    int index = 1;
    for (int i = 1; i < size; i++) {
        if (min > distance[i]) {
            min = distance[i];
            index = i;
        }
    }
    if (distance[index] == INT32_MAX)
        return 0;
    distance[index] = INT32_MAX;
    return index;
}

static mospf_db_entry_t * index_to_dbentry(int index) {
    mospf_db_entry_t *walk = NULL;
    list_for_each_entry(walk, &mospf_db, list) {
        if (rid_to_index(walk->rid) == index) {
            return walk;
        }
    }
    return walk;
}

static void index_to_iface_and_nbr(int index, iface_info_t **iface,
                                   mospf_nbr_t **nbr) {
    iface_info_t *walk = NULL;
    list_for_each_entry(walk, &instance->iface_list, list) {
        mospf_nbr_t *nb = NULL;
        list_for_each_entry(nb, &walk->nbr_list, list) {
            if (rid_to_index(nb->nbr_id) == index) {
                *iface = walk;
                *nbr = nb;
                return;
            }
        }
    }
}

static void expand_rtable(int *distance, int *prev, int size) {
    rt_entry_t *rt = NULL, *rq = NULL;
    list_for_each_entry_safe(rt, rq, &rtable, list) {
        if (rt->gw != 0)
            remove_rt_entry(rt);
    }
    int root = rid_to_index(instance->router_id);
    for (int i = 1; i < size; i++) {
        int index = find_shortest_path_then_delete(distance, size);
        if (index == root || index == 0)
            continue;
        else {
            mospf_db_entry_t *db = NULL;
            db = index_to_dbentry(index);
            for (int j = 0; j < db->nadv; j++) {
                if (longest_prefix_match(db->array[j].subnet) != NULL) {
                    continue;
                }
     
                u32 dest = db->array[j].subnet;
                int hop = rid_to_index(db->rid);
                while(prev[hop] != root) {
                    hop = prev[hop];
                }
                iface_info_t *iface = NULL;
                mospf_nbr_t *nbr = NULL;
                index_to_iface_and_nbr(hop, &iface, &nbr);
                u32 gw = nbr->nbr_ip;
                rt = (rt_entry_t *)malloc(sizeof(rt_entry_t));
                MALLOC_FAILED(rt);
                rt->dest = dest;
                rt->flags = 0;
                rt->gw = gw;
                strcpy(rt->if_name, iface->name);
                rt->mask = nbr->nbr_mask;
                rt->iface = iface;
                add_rt_entry(rt);
            }
        }
    }
}

void update_rtable(iface_info_t *iface){
    pthread_mutex_lock(&mospf_lock);
    int num_of_entries = NUM_OF_NODES + 1;
    
    int *visited = (int *)malloc(num_of_entries * sizeof(int));
    MALLOC_FAILED(visited);
    int *distance = (int *)malloc(num_of_entries * sizeof(int));
    MALLOC_FAILED(distance);
    int *prev = (int *)malloc(num_of_entries * sizeof(int));
    MALLOC_FAILED(prev);

    // initialize a matrix
    int **matrix = (int **)malloc(num_of_entries * (sizeof(int *)));
    MALLOC_FAILED(matrix);
    for (int i = 0; i < num_of_entries; i++) {
        matrix[i] = (int *)malloc(num_of_entries * sizeof(int));
        MALLOC_FAILED(matrix[i]);
    }
    for (int i = 0; i < num_of_entries; i++) {
        for (int j = 0; j < num_of_entries; j++) {
            matrix[i][j] = (i == j) ? 0 : INT32_MAX;
        }
    }
    db_to_matrix(matrix, num_of_entries);
    dijkstra(visited, distance, prev, matrix, num_of_entries);
    expand_rtable(distance, prev, num_of_entries);

    free(visited);
    free(distance);
    free(prev);
    for (int i = 0; i < num_of_entries; i++) {
        free(matrix[i]);
    }
    free(matrix);
    pthread_mutex_unlock(&mospf_lock);
}

void handle_mospf_lsu(iface_info_t *iface, char *packet, int len)
{
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
    list_for_each_entry(walk, &instance->iface_list, list) {
        if (walk != iface) {
            char *new_packet = (char *)malloc(len * sizeof(char));
            MALLOC_FAILED(new_packet);
            memcpy(new_packet, packet, len);
            forward_lsu(walk, new_packet, len);
            new_packet = NULL;
        }
    }
    /* int num_of_entries = 0; */
    /* mospf_db_entry_t *dbe = NULL; */
    /* list_for_each_entry(dbe, &mospf_db, list) { */
    /*     num_of_entries++; */
    /* } */
    /* if (num_of_entries == 3) */
    update_rtable(iface);
    print_rtable();
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