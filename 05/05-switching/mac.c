#include "mac.h"
#include "headers.h"
#include "log.h"

mac_port_map_t mac_port_map;

void init_mac_hash_table()
{
    bzero(&mac_port_map, sizeof(mac_port_map_t));

    pthread_mutexattr_init(&mac_port_map.attr);
    pthread_mutexattr_settype(&mac_port_map.attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&mac_port_map.lock, &mac_port_map.attr);

    pthread_create(&mac_port_map.tid, NULL, sweeping_mac_port_thread, NULL);
}

void destory_mac_hash_table()
{
    pthread_mutex_lock(&mac_port_map.lock);
    mac_port_entry_t *tmp, *entry;
    for (int i = 0; i < HASH_8BITS; i++) {
	entry = mac_port_map.hash_table[i];
	if (!entry) 
	    continue;

	tmp = entry->next;
	while (tmp) {
	    entry->next = tmp->next;
	    free(tmp);
	    tmp = entry->next;
	}
	free(entry);
    }
    pthread_mutex_unlock(&mac_port_map.lock);
}

iface_info_t *lookup_port(u8 mac[ETH_ALEN])
{
    // TODO: implement the lookup process here
    int result =  hash8(mac, ETH_ALEN);
    int found = 1;
    mac_port_entry_t *entry = mac_port_map.hash_table[result];
    while (entry) {
	for (int i = 0; i < ETH_ALEN; i++) {
	    if (entry->mac[i] != mac[i]) {
		found = 0;
		break;
	    }
	}

	if (found) {
	    entry->visited = time(NULL);
	    return entry->iface;
	} else if (!found && !entry->next) {
	    return NULL;
	}

	entry = entry->next;
    }
    return NULL;
//    fprintf(stdout, "DONE: lookup mac port here, dumping table:\n");
//    dump_mac_port_table();
}

void insert_mac_port(u8 mac[ETH_ALEN], iface_info_t *iface)
{
    // DONE: implement the insertion process here
    int result = hash8(mac, ETH_ALEN);
    mac_port_entry_t *entry = mac_port_map.hash_table[result];

    pthread_mutex_lock(&mac_port_map.lock);
    while (entry) {
	entry = entry->next;
    }

    mac_port_map.hash_table[result] = (mac_port_entry_t *)malloc(sizeof(mac_port_entry_t));
    memcpy(mac_port_map.hash_table[result]->mac, mac, ETH_ALEN);
    mac_port_map.hash_table[result]->iface = iface;
    mac_port_map.hash_table[result]->next = NULL;
    mac_port_map.hash_table[result]->visited = time(NULL);
    pthread_mutex_unlock(&mac_port_map.lock);
//    fprintf(stdout, "DONE: insert mac port here, dumping table:\n");
}

void dump_mac_port_table()
{
    mac_port_entry_t *entry = NULL;
    time_t now = time(NULL);

    fprintf(stdout, "dumping the mac_port table:\n");
    pthread_mutex_lock(&mac_port_map.lock);
    for (int i = 0; i < HASH_8BITS; i++) {
	entry = mac_port_map.hash_table[i];
	while (entry) {
	    fprintf(stdout, ETHER_STRING " -> %s, %d\n", ETHER_FMT(entry->mac), \
		    entry->iface->name, (int)(now - entry->visited));

	    entry = entry->next;
	}
    }

    pthread_mutex_unlock(&mac_port_map.lock);
}

int sweep_aged_mac_port_entry()
{
    // DONE: implement the sweeping process here
    mac_port_entry_t *entry = NULL;
    mac_port_entry_t *pre = NULL;
    time_t now = time(NULL);

    for (int i = 0; i < HASH_8BITS; i++) {
	// if the head is timed out
	entry = mac_port_map.hash_table[i];
	pthread_mutex_lock(&mac_port_map.lock);
	while(entry && now - entry->visited >= MAC_PORT_TIMEOUT) {
	    mac_port_map.hash_table[i] = entry->next;
	    free(entry);
	    entry = mac_port_map.hash_table[i];
	}
	pthread_mutex_unlock(&mac_port_map.lock);

	// the head is not timed out
	pre = mac_port_map.hash_table[i];
	if(!pre) {
	    continue;
	} else {
	    entry = pre->next;
	    pthread_mutex_lock(&mac_port_map.lock);
	    while(entry) {
		if (now - entry->visited >= MAC_PORT_TIMEOUT) {
		    pre->next = entry->next;
		    free(entry);
		    entry = pre->next;		    
		} else {
		    pre = entry;
		    entry = entry->next;
		}
	    }
	    pthread_mutex_unlock(&mac_port_map.lock);
	}
    }
    
    return 0;
}

void *sweeping_mac_port_thread(void *nil)
{
    while (1) {
	sleep(1);
	int n = sweep_aged_mac_port_entry();

	if (n > 0)
	    log(DEBUG, "%d aged entries in mac_port table are removed.\n", n);
    }

    return NULL;
}
