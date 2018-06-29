#include "include/tcp.h"
#include "include/tcp_sock.h"
#include "include/tcp_timer.h"

#include "include/log.h"
#include "include/ring_buffer.h"

#include <stdlib.h>

#define enter_function() fprintf(stdout, "Enter %s\n", __FUNCTION__);
#define leave_function() fprintf(stdout, "Leave %s\n", __FUNCTION__);


#ifndef max
#define max(x,y) ((x)>(y) ? (x) : (y))
#endif

// handling incoming packet for TCP_LISTEN state
//
// 1. malloc a child tcp sock to serve this connection request; 
// 2. send TCP_SYN | TCP_ACK by child tcp sock;
// 3. hash the child tcp sock into established_table (because the 4-tuple 
//    is determined).
static int listen_state_check(struct tcp_sock *tsk, struct tcp_cb *cb) {
    // packet is not SYN
    if ((cb->flags & TCP_SYN) == 0) {
        if ((cb->flags & TCP_RST) == 0)
            tcp_send_control_packet(tsk, TCP_RST);
        return -1;
    }

    // ACK is optional here, so no check is needed

    return 0;
}

static void init_csk(struct tcp_sock *tsk, struct tcp_cb *cb, struct tcp_sock *csk) {
    csk->parent = tsk;
    csk->sk_sip   = cb->daddr;
    csk->sk_sport = cb->dport;
    csk->sk_dip   = cb->saddr;
    csk->sk_dport = cb->sport;
    csk->rcv_nxt = cb->seq + 1;
    csk->snd_nxt = cb->ack;
}

void tcp_state_listen(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
    if (listen_state_check(tsk, cb) == -1)
        return;
    // 1. malloc a child tcp sock
    struct tcp_sock *csk = alloc_tcp_sock();
    init_csk(tsk, cb, csk);
    list_add_tail(&csk->list, &tsk->listen_queue);
    // tsk->rcv_nxt = cb->seq + 1;
    // tsk->snd_nxt = cb->ack;
    // 2. send TCP_SYN | TCP_ACK by child tcp sock;
    tcp_send_control_packet(csk, TCP_SYN | TCP_ACK);
    // 3. hash the child tcp sock into established_table (because the 4-tuple 
    tcp_set_state(csk, TCP_SYN_RECV);
    tcp_hash(csk);
    // fprintf(stdout, "DONE: implement this function please.\n");
}

// handling incoming packet for TCP_CLOSED state, by replying TCP_RST
void tcp_state_closed(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
    tcp_send_reset(cb);
}

// handling incoming packet for TCP_SYN_SENT state
//
// If everything goes well (the incoming packet is TCP_SYN|TCP_ACK), reply with 
// TCP_ACK, and enter TCP_ESTABLISHED state, notify tcp_sock_connect; otherwise, 
// reply with TCP_RST.
void tcp_state_syn_sent(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
    // (cb->flags & (TCP_ACK | TCP_SYN) == (TCP_ACK | TCP_SYN)) shall not
    // be used since the packet may be wrong containing multiple flags
    if ( (cb->flags & TCP_ACK) == 0 && (cb->flags & TCP_SYN) == 0) {
        tcp_send_reset(cb);
        return;
    }

    tsk->rcv_nxt = cb->seq + 1;
    tsk->snd_nxt = cb->ack;

    tcp_send_control_packet(tsk, TCP_ACK);
    tcp_set_state(tsk, TCP_ESTABLISHED);
    tsk->snd_wnd = cb->rwnd;
    wake_up(tsk->wait_connect);
    // fprintf(stdout, "DONE: implement this function please.\n");
}

// update the snd_wnd of tcp_sock
//
// if the snd_wnd before updating is zero, notify tcp_sock_send (wait_send)
static inline void tcp_update_window(struct tcp_sock *tsk, struct tcp_cb *cb)
{
    u16 old_snd_wnd = tsk->snd_wnd;
    tsk->snd_wnd = cb->rwnd;
    if (old_snd_wnd == 0)
        wake_up(tsk->wait_send);
}

// update the snd_wnd safely: cb->ack should be between snd_una and snd_nxt
static inline void tcp_update_window_safe(struct tcp_sock *tsk, struct tcp_cb *cb)
{
    if (less_or_equal_32b(tsk->snd_una, cb->ack) && less_or_equal_32b(cb->ack, tsk->snd_nxt))
        tcp_update_window(tsk, cb);
}

// handling incoming ack packet for tcp sock in TCP_SYN_RECV state
//
// 1. remove itself from parent's listen queue;
// 2. add itself to parent's accept queue;
// 3. wake up parent (wait_accept) since there is established connection in the
//    queue.
void tcp_state_syn_recv(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
    if ((cb->flags & TCP_ACK) == 0) {
        return;
    }
    
    tsk->rcv_nxt = cb->seq + 1;
    tsk->snd_nxt = cb->ack;
    
    tcp_set_state(tsk, TCP_ESTABLISHED);
    tsk->snd_wnd = cb->rwnd;
    list_delete_entry(&tsk->list);
    tcp_sock_accept_enqueue(tsk);
    wake_up(tsk->parent->wait_accept);
}



// check whether the sequence number of the incoming packet is in the receiving
// window
static inline int is_tcp_seq_valid(struct tcp_sock *tsk, struct tcp_cb *cb)
{
    u32 rcv_end = tsk->rcv_nxt + max(tsk->rcv_wnd, 1);
    if (less_than_32b(cb->seq, rcv_end) && less_or_equal_32b(tsk->rcv_nxt, cb->seq_end)) {
        return 1;
    }
    else {
        log(ERROR, "received packet with invalid seq, drop it.");
        return 0;
    }
}

// Process an incoming packet as follows:
// 	 1. if the state is TCP_CLOSED, hand the packet over to tcp_state_closed;
// 	 2. if the state is TCP_LISTEN, hand it over to tcp_state_listen;
// 	 3. if the state is TCP_SYN_SENT, hand it to tcp_state_syn_sent;
// 	 4. check whether the sequence number of the packet is valid, if not, drop
// 	    it;
// 	 5. if the TCP_RST bit of the packet is set, close this connection, and
// 	    release the resources of this tcp sock;
// 	 6. if the TCP_SYN bit is set, reply with TCP_RST and close this connection,
// 	    as valid TCP_SYN has been processed in step 2 & 3;
// 	 7. check if the TCP_ACK bit is set, since every packet (except the first 
//          SYN) should set this bit;
//       8. process the ack of the packet: if it ACKs the outgoing SYN packet, 
//          establish the connection; (if it ACKs new data, update the window;)
//          if it ACKs the outgoing FIN packet, switch to correpsonding state;
//       9. (process the payload of the packet: call tcp_recv_data to receive data;)
//      10. if the TCP_FIN bit is set, update the TCP_STATE accordingly;
//      11. at last, do not forget to reply with TCP_ACK if the connection is alive.
void tcp_recv_data(struct tcp_sock *tsk, struct tcp_cb *cb) {
    fprintf(stdout, "%s: writing data to ring buffer\n", __FUNCTION__);
    pthread_mutex_lock(&tsk->rcv_buf->ring_lock);
    int free_size = ring_buffer_free(tsk->rcv_buf);
    if (free_size == 0 || free_size < cb->pl_len) {
        fprintf(stdout,
                "%s: ring buffer does not have enough space\n", __FUNCTION__);
        tsk->rcv_wnd = 0;
        pthread_mutex_unlock(&tsk->rcv_buf->ring_lock);
        return;
    } else if (cb->pl_len <= 0) {
        fprintf(stdout, "%s: data length is zero or negative\n", __FUNCTION__);
        pthread_mutex_unlock(&tsk->rcv_buf->ring_lock);
        return;
    }
 
    else {
        tsk->rcv_wnd = free_size - cb->pl_len;
        tsk->rcv_nxt = cb->seq + cb->pl_len;
        fprintf(stdout,
                "%s, %d: writing to ring buffer finished\n",
                __FUNCTION__, __LINE__);
        write_ring_buffer(tsk->rcv_buf, cb->payload, cb->pl_len);

        // pthread_cond_signal(&tsk->rcv_buf->block_read_cond);
        fprintf(stdout, "%s, %d: wake up %p\n", __FUNCTION__, __LINE__, tsk);
        wake_up(tsk->wait_recv);
        pthread_mutex_unlock(&tsk->rcv_buf->ring_lock);
    }
}

void tcp_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
    if (tsk == NULL) {
        fprintf(stdout, "tsk is NULL\n");
        return;
    }  // code below may set tsk to NULL
    // 	 1. if the state is TCP_CLOSED, hand the packet over to tcp_state_closed;
    // 	 2. if the state is TCP_LISTEN, hand it over to tcp_state_listen;
    // 	 3. if the state is TCP_SYN_SENT, hand it to tcp_state_syn_sent;
    switch (tsk->state) {
    case TCP_CLOSED:
        fprintf(stdout, "**** process close\n");
        tcp_state_closed(tsk, cb, packet);
        return;
    case TCP_LISTEN:
        fprintf(stdout, "**** process listen\n");
        tcp_state_listen(tsk, cb, packet);
        return;
    case TCP_SYN_SENT:
        fprintf(stdout, "**** process syn_sent\n");
        tcp_state_syn_sent(tsk, cb, packet);
        return;
    default:
        break;
    }
    // 	 4. check whether the sequence number of the packet is valid, if not, drop
    // 	    it;
    if (!is_tcp_seq_valid(tsk, cb)) {
        fprintf(stdout, "**** tcp seq is not valid\n");
        return;
    }
    // 	 5. if the TCP_RST bit of the packet is set, close this connection, and
    // 	    release the resources of this tcp sock;
    if (cb->flags & TCP_RST) {
        fprintf(stdout, "**** RST is received\n");
        tcp_sock_close(tsk);
        free_tcp_sock(tsk);
        tsk = NULL;
        return;
    }
    // 	 6. if the TCP_SYN bit is set, reply with TCP_RST and close this connection,
    // 	    as valid TCP_SYN has been processed in step 2 & 3;
    if (cb->flags & TCP_SYN) {
        fprintf(stdout, "**** SYN is received while not in listen state\n");
        tcp_send_reset(cb);
        tcp_sock_close(tsk);
        free_tcp_sock(tsk);
        tsk = NULL;
        return;
    }
    // 	 7. check if the TCP_ACK bit is set, since every packet (except the first
    //      SYN) should set this bit;
    if((cb->flags & TCP_ACK) == 0){
        fprintf(stdout, "**** No ACK bit\n");
        tcp_send_reset(cb);
        return;
    }
    //   8. process the ack of the packet: if it ACKs the outgoing SYN packet,
    //      establish the connection; (if it ACKs new data, update the window;)
    //      if it ACKs the outgoing FIN packet, switch to correpsonding state;
    if (tsk->state == TCP_SYN_RECV) {
        fprintf(stdout, "**** process syn_recv\n");
        tcp_state_syn_recv(tsk, cb, packet);
        return;
    } else if (tsk->state == TCP_ESTABLISHED) {
        fprintf(stdout, "**** update window\n");
        tcp_update_window_safe(tsk, cb);
    } else if ((cb->flags & TCP_FIN) == 0) {
        switch(tsk->state){
        case TCP_FIN_WAIT_1:
            fprintf(stdout, "**** ready to be TCP_FIN_WAIT_2\n");
            tcp_set_state(tsk, TCP_FIN_WAIT_2);
            tsk->rcv_nxt += 1;
            return;
        case TCP_FIN_WAIT_2:
            tcp_set_state(tsk, TCP_TIME_WAIT);
            tcp_set_timewait_timer(tsk);
            tcp_send_control_packet(tsk, TCP_ACK);
            return;
        case TCP_CLOSING:
            fprintf(stdout, "**** ddl to close\n");
            tcp_set_state(tsk, TCP_TIME_WAIT);
            tcp_set_timewait_timer(tsk);
            return;
        case TCP_LAST_ACK:
            fprintf(stdout, "**** TCP Connection closed\n");
            tcp_set_state(tsk, TCP_CLOSED);
            free_tcp_sock(tsk);
            return;
        default:
            break;
        }
    }
    //   9. (process the payload of the packet: call tcp_recv_data to receive data;)
    if (cb->pl_len > 0) {
        fprintf(stdout, "**** receiving data\n");
        tcp_recv_data(tsk, cb);
        return;
    } else {
        fprintf(stdout, "**** data is null");
        char flags[32];
        tcp_copy_flags_to_str(cb->flags, flags);
        fprintf(stdout, "packet flasgs are %s\n", flags);
    }

    //  10. if the TCP_FIN bit is set, update the TCP_STATE accordingly;
    if(cb->flags & TCP_FIN){
        tsk->rcv_nxt += 1;
        fprintf(stdout, "**** TCP_FIN is received\n");
        switch(tsk->state){
        case TCP_CLOSE_WAIT:
            tcp_set_state(tsk, TCP_LAST_ACK);
            break;
        case TCP_ESTABLISHED:
            tcp_send_control_packet(tsk, TCP_ACK);
            tcp_set_state(tsk, TCP_CLOSE_WAIT);
            tcp_send_control_packet(tsk, TCP_ACK|TCP_FIN);
            tcp_set_state(tsk, TCP_LAST_ACK);
            return;
        case TCP_FIN_WAIT_1:
            tcp_set_state(tsk, TCP_CLOSING);
            break;
        case TCP_FIN_WAIT_2:
            tcp_set_state(tsk, TCP_TIME_WAIT);
            tcp_set_timewait_timer(tsk);
            break;
        default:
            break;
        }
    }
    // 11. at last, do not forget to reply with TCP_ACK if the connection is alive.
    fprintf(stdout, "Sending TCP_ACK in tcp process\n");
    tcp_send_control_packet(tsk, TCP_ACK);                

    // fprintf(stdout, "DONE: implement this function please.\n");
}
