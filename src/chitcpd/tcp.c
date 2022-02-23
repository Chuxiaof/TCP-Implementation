/*
 *  chiTCP - A simple, testable TCP stack
 *
 *  Implementation of the TCP protocol.
 *
 *  chiTCP follows a state machine approach to implementing TCP.
 *  This means that there is a handler function for each of
 *  the TCP states (CLOSED, LISTEN, SYN_RCVD, etc.). If an
 *  event (e.g., a packet arrives) while the connection is
 *  in a specific state (e.g., ESTABLISHED), then the handler
 *  function for that state is called, along with information
 *  about the event that just happened.
 *
 *  Each handler function has the following prototype:
 *
 *  int f(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event);
 *
 *  si is a pointer to the chiTCP server info. The functions in
 *       this file will not have to access the data in the server info,
 *       but this pointer is needed to call other functions.
 *
 *  entry is a pointer to the socket entry for the connection that
 *          is being handled. The socket entry contains the actual TCP
 *          data (variables, buffers, etc.), which can be extracted
 *          like this:
 *
 *            tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
 *
 *          Other than that, no other fields in "entry" should be read
 *          or modified.
 *
 *  event is the event that has caused the TCP thread to wake up. The
 *          list of possible events corresponds roughly to the ones
 *          specified in http://tools.ietf.org/html/rfc793#section-3.9.
 *          They are:
 *
 *            APPLICATION_CONNECT: Application has called socket_connect()
 *            and a three-way handshake must be initiated.
 *
 *            APPLICATION_SEND: Application has called socket_send() and
 *            there is unsent data in the send buffer.
 *
 *            APPLICATION_RECEIVE: Application has called socket_recv() and
 *            any received-and-acked data in the recv buffer will be
 *            collected by the application (up to the maximum specified
 *            when calling socket_recv).
 *
 *            APPLICATION_CLOSE: Application has called socket_close() and
 *            a connection tear-down should be initiated.
 *
 *            PACKET_ARRIVAL: A packet has arrived through the network and
 *            needs to be processed (RFC 793 calls this "SEGMENT ARRIVES")
 *
 *            TIMEOUT: A timeout (e.g., a retransmission timeout) has
 *            happened.
 *
 */

/*
 *  Copyright (c) 2013-2014, The University of Chicago
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or withsend
 *  modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 *  - Neither the name of The University of Chicago nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software withsend specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY send OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "chitcp/log.h"
#include "chitcp/utils.h"
#include "chitcp/buffer.h"
#include "chitcp/chitcpd.h"
#include "serverinfo.h"
#include "connection.h"
#include "tcp.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SEGMENT_FINISHED 1
#define SEGMENT_KEEP 2
#define SEGMENT_DROP -1

#define MS_TO_NS(n) ((long)n * 1000000)

#define G (MS_TO_NS(50))
#define K 4
#define RTO_ALPHA (1 / 8)
#define RTO_BETA (1 / 4)
#define RTO_INIT (MS_TO_NS(1000))
#define MAX_RTO (MS_TO_NS(60000))

#define TIMER_NUM 2
#define RTX_TIMER_ID 0
#define PST_TIMER_ID 1

#define PROBE_LENGTH 1

/* arguments for retransmission timer callback function */
typedef struct rtx_args {
    serverinfo_t *si;
    chisocketentry_t *entry;
} rtx_args_t;

/* arguments for persist timer callback function */
typedef struct pst_args {
    serverinfo_t *si;
    chisocketentry_t *entry;
} pst_args_t;

/**
 * @brief free both the raw content and tcp_packet_t itself
 *
 * @param pointer to packet you want to free
 */
static void deep_free_packet(tcp_packet_t *packet);

/**
 * @brief a helper function that handle the arrival of new packet
 *
 * @param si struct that stores the server global infomation
 * @param entry particular socket entry for this tcp connection
 */
static void chitcpd_tcp_handle_packet(serverinfo_t *si, chisocketentry_t *entry);

/**
 * @brief helper function of chitcpd_tcp_handle_packet() that helps dealing with the packet arrival event when tcp state is LISTEN
 *
 * @param si struct that stores the server global infomation
 * @param entry particular socket entry for this tcp connection
 * @param packet the arrival packet
 * @param return_packet packet to be sent to another side of tcp connection
 * @return int SEGMENT_FINISHED: send the return packet and free arrival packet; SEGMENT_KEEP: send the return packet and keep arrival packet; SEGMENT_DROP: discard the return packet and arrival packet
 */
static int listen_handler(serverinfo_t *si, chisocketentry_t *entry,
                          tcp_packet_t *packet, tcp_packet_t *return_packet);

/**
 * @brief helper function of chitcpd_tcp_handle_packet() that helps dealing with the packet arrival event when tcp state is SYN_SENT
 *
 * @param si struct that stores the server global infomation
 * @param entry particular socket entry for this tcp connection
 * @param packet the arrival packet
 * @param return_packet packet to be sent to another side of tcp connection
 * @return int SEGMENT_FINISHED: send the return packet and free arrival packet; SEGMENT_KEEP: send the return packet and keep arrival packet; SEGMENT_DROP: discard the return packet and arrival packet
 */
static int syn_sent_handler(serverinfo_t *si, chisocketentry_t *entry,
                            tcp_packet_t *packet, tcp_packet_t *return_packet);

/**
 * @brief helper function of chitcpd_tcp_handle_packet() that helps dealing with the packet arrival event when tcp state are not LISTEN or SYN_SENT
 *
 * @param si struct that stores the server global infomation
 * @param entry particular socket entry for this tcp connection
 * @param packet the arrival packet
 * @param return_packet packet to be sent to another side of tcp connection
 * @return int SEGMENT_FINISHED: send the return packet and free arrival packet; SEGMENT_KEEP: send the return packet and keep arrival packet; SEGMENT_DROP: discard the return packet and arrival packet
 */
static int other_states_handler(serverinfo_t *si, chisocketentry_t *entry,
                                tcp_packet_t *packet, tcp_packet_t *return_packet);

/**
 * @brief segment long message, keep sending until send buffer is empty
 *        or exhausting SND.WND
 *
 * @param si struct that stores the server global infomation
 * @param entry particular socket entry for this tcp connection
 * @return int, denoting success or not
 */
static int send_data(serverinfo_t *si, chisocketentry_t *entry);

/**
 * @brief for delayed sending of fin message
 *
 * @param si struct that stores the server global infomation
 * @param entry particular socket entry for this tcp connection
 */
static void send_fin(serverinfo_t *si, chisocketentry_t *entry);



/**
 * @brief add the packet to the retransmission queue
 *
 * @param entry particular socket entry for this tcp connection
 * @param packet packet to be added
 */
static void append_retransmission_queue(chisocketentry_t *entry, tcp_packet_t *packet);

/**
 * @brief creat a retransmission packet according to the given ordinary packet
 *
 * @param packet ordinary packet to be wrapped into retransmission packet
 * @param sent_time absolute time when this packet was sent by tcp
 * @return retransmission_packet_t* pointer to the created retransmission packet
 */
static retransmission_packet_t *retransmission_packet_create(tcp_packet_t *packet, struct timespec sent_time);

/**
 * @brief deep free retransmission packet
 *
 * @param re_packet retransmission packet to be freed
 */
static void retransmission_packet_free(retransmission_packet_t *re_packet);

/**
 * @brief Given the most recent acknowledge number, remove packets out of retransmission queue, take corresponding bytes out of send buffer,
 *        cancel/reset retransmission timer if necessary, update SRTT, RTTVAR and RTO according to RFC
 *
 * @param si struct that stores the server global infomation
 * @param entry particular socket entry for this tcp connection
 * @param ack_seq acknowledge number of the arrival packet
 */
static void sweep_away_acked_packets(serverinfo_t *si, chisocketentry_t *entry, tcp_seq ack_seq);

/**
 * @brief activate the retransmission timer
 *
 * @param si struct that stores the server global infomation
 * @param entry particular socket entry for this tcp connection
 */
static void set_retransmission_timer(serverinfo_t *si, chisocketentry_t *entry);

/**
 * @brief activate the persist timer
 *
 * @param si struct that stores the server global infomation
 * @param entry particular socket entry for this tcp connection
 */
static void set_persist_timer(serverinfo_t *si, chisocketentry_t *entry);

/**
 * @brief resend all the packets in retransmission queue
 *
 * @param si struct that stores the server global infomation
 * @param entry particular socket entry for this tcp connection
 */
static void resend_packets(serverinfo_t *si, chisocketentry_t *entry);

/**
 * @brief when persist timer times out, send a probe if there's data to send, reset the timer
 *
 * @param si struct that stores the server global infomation
 * @param entry particular socket entry for this tcp connection
 */
static void pst_timeout_handler(serverinfo_t *si, chisocketentry_t *entry);

/**
 * @brief callback function when retransmission timer times out
 *
 * @param mt pointer to multitimer
 * @param st pointer to particular single timer
 * @param rtx_args arguments for this callback function
 */
void rtx_callback_func(multi_timer_t *mt, single_timer_t *st, void *rtx_args);

/**
 * @brief callback function when persist timer times out
 *
 * @param mt pointer to multitimer
 * @param st pointer to particular single timer
 * @param pst_args arguments for this callback function
 */
void pst_callback_func(multi_timer_t *mt, single_timer_t *st, void *pst_args);

/**
 * @brief creat a out-of-order packet according to the given ordinary packet
 *
 * @param packet ordinary packet to be wrapped up
 * @return out_of_order_packet_t* pointer to the created out-of-order packet
 */
static out_of_order_packet_t *out_of_order_packet_create(tcp_packet_t *packet);

/**
 * @brief comparison function to be used by LL_INSERT_INORDER()
 *
 * @param x pointer to out-of-order packet to be compared
 * @param y pointer to out-of-order packet to be compared
 * @return negative int: the first item should sort before the second item;
 *         zero: the first item should sort equal to the second item;
 *         positive int: the first item should sort after the second item.
 */
static int out_of_order_packet_cmp(out_of_order_packet_t *x, out_of_order_packet_t *y);

void tcp_data_init(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

    tcp_data->pending_packets = NULL;
    pthread_mutex_init(&tcp_data->lock_pending_packets, NULL);
    pthread_cond_init(&tcp_data->cv_pending_packets, NULL);

    /* Initialization of additional tcp_data_t fields,
     * and creation of retransmission thread, goes here */
    mt_init(&tcp_data->mt, TIMER_NUM);
    tcp_data->retransmission_queue = NULL;
    tcp_data->is_first_measurement = true;
    tcp_data->out_of_order_packets_list = NULL;
    /* set initial RTO to 200 milliseconds*/
    tcp_data->RTO = RTO_INIT;
}

void tcp_data_free(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

    circular_buffer_free(&tcp_data->send);
    circular_buffer_free(&tcp_data->recv);
    chitcp_packet_list_destroy(&tcp_data->pending_packets);
    pthread_mutex_destroy(&tcp_data->lock_pending_packets);
    pthread_cond_destroy(&tcp_data->cv_pending_packets);

    /* Cleanup of additional tcp_data_t fields goes here */
    mt_free(&tcp_data->mt);
}

int chitcpd_tcp_state_handle_CLOSED(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == APPLICATION_CONNECT) {
        tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

        /* prepare and send SYN message */
        tcp_packet_t *packet = calloc(1, sizeof(tcp_packet_t));
        chitcpd_tcp_packet_create(entry, packet, NULL, 0);
        tcphdr_t *header = TCP_PACKET_HEADER(packet);
        /* set the initial sequence number randomly */
        srand(time(NULL));
        tcp_data->ISS = (rand() % 1000 + 1) * 100000;

        header->syn = 1;
        header->seq = chitcp_htonl(tcp_data->ISS);
        tcp_data->SND_UNA = tcp_data->ISS;
        tcp_data->SND_NXT = tcp_data->ISS + 1;
        /* set send buffer for client side */
        assert(circular_buffer_set_seq_initial(&tcp_data->send, tcp_data->SND_NXT) == CHITCP_OK);

        append_retransmission_queue(entry, packet);
        chitcpd_send_tcp_packet(si, entry, packet);
        set_retransmission_timer(si, entry);
        chitcpd_update_tcp_state(si, entry, SYN_SENT);
    } else if (event == CLEANUP) {
        /* Any additional cleanup goes here */
    } else
        chilog(WARNING, "In CLOSED state, received unexpected event.");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_LISTEN(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL) {
        chitcpd_tcp_handle_packet(si, entry);
    } else
        chilog(WARNING, "In LISTEN state, received unexpected event.");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_SYN_RCVD(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL) {
        chitcpd_tcp_handle_packet(si, entry);
    } else if (event == TIMEOUT_RTX) {
        /* Your code goes here */
        resend_packets(si, entry);
    } else
        chilog(WARNING, "In SYN_RCVD state, received unexpected event.");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_SYN_SENT(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL) {
        chitcpd_tcp_handle_packet(si, entry);
    } else if (event == TIMEOUT_RTX) {
        /* Your code goes here */
        resend_packets(si, entry);
    } else
        chilog(WARNING, "In SYN_SENT state, received unexpected event.");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_ESTABLISHED(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    if (event == APPLICATION_SEND) {
        send_data(si, entry);
    } else if (event == PACKET_ARRIVAL) {
        chitcpd_tcp_handle_packet(si, entry);
    } else if (event == APPLICATION_RECEIVE) {
        tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);
    } else if (event == APPLICATION_CLOSE) {
        /* in any case, enter FIN-WAIT-1 state */
        chitcpd_update_tcp_state(si, entry, FIN_WAIT_1);
        tcp_data->closing = true;
        send_fin(si, entry);
    } else if (event == TIMEOUT_RTX) {
        /* Your code goes here */
        resend_packets(si, entry);
    } else if (event == TIMEOUT_PST) {
        /* Your code goes here */
        pst_timeout_handler(si, entry);
    } else
        chilog(WARNING, "In ESTABLISHED state, received unexpected event (%i).", event);

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_FIN_WAIT_1(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL) {
        chitcpd_tcp_handle_packet(si, entry);
    } else if (event == APPLICATION_RECEIVE) {
        tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
        tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);
    } else if (event == TIMEOUT_RTX) {
        /* Your code goes here */
        resend_packets(si, entry);
    } else if (event == TIMEOUT_PST) {
        /* Your code goes here */
        pst_timeout_handler(si, entry);
    } else
        chilog(WARNING, "In FIN_WAIT_1 state, received unexpected event (%i).", event);

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_FIN_WAIT_2(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL) {
        chitcpd_tcp_handle_packet(si, entry);
    } else if (event == APPLICATION_RECEIVE) {
        tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
        tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);
    } else if (event == TIMEOUT_RTX) {
        /* Your code goes here */
        resend_packets(si, entry);
    } else
        chilog(WARNING, "In FIN_WAIT_2 state, received unexpected event (%i).", event);

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_CLOSE_WAIT(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    if (event == APPLICATION_CLOSE) {
        tcp_data->closing = true;
        send_fin(si, entry);
    } else if (event == PACKET_ARRIVAL) {
        chitcpd_tcp_handle_packet(si, entry);
    } else if (event == TIMEOUT_RTX) {
        /* Your code goes here */
        resend_packets(si, entry);
    } else if (event == TIMEOUT_PST) {
        /* Your code goes here */
        pst_timeout_handler(si, entry);
    } else
        chilog(WARNING, "In CLOSE_WAIT state, received unexpected event (%i).", event);

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_CLOSING(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL) {
        chitcpd_tcp_handle_packet(si, entry);
    } else if (event == TIMEOUT_RTX) {
        /* Your code goes here */
        resend_packets(si, entry);
    } else if (event == TIMEOUT_PST) {
        /* Your code goes here */
        pst_timeout_handler(si, entry);
    } else
        chilog(WARNING, "In CLOSING state, received unexpected event (%i).", event);

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_TIME_WAIT(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    chilog(WARNING, "Running handler for TIME_WAIT. This should not happen.");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_LAST_ACK(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL) {
        chitcpd_tcp_handle_packet(si, entry);
    } else if (event == TIMEOUT_RTX) {
        /* Your code goes here */
        resend_packets(si, entry);
    } else if (event == TIMEOUT_PST) {
        /* Your code goes here */
        pst_timeout_handler(si, entry);
    } else
        chilog(WARNING, "In LAST_ACK state, received unexpected event (%i).", event);

    return CHITCP_OK;
}

/*                                                           */
/*     Any additional functions you need should go here      */
/*                                                           */

/* see function declaration */
static void deep_free_packet(tcp_packet_t *packet)
{
    if (packet != NULL) {
        chitcp_tcp_packet_free(packet);
    }
    free(packet);
}

/* see function declaration */
static void retransmission_packet_free(retransmission_packet_t *re_packet)
{
    deep_free_packet(re_packet->packet);
    free(re_packet);
}

/* see function declaration */
static int listen_handler(serverinfo_t *si, chisocketentry_t *entry,
                          tcp_packet_t *packet, tcp_packet_t *return_packet)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    tcphdr_t *header = TCP_PACKET_HEADER(packet);
    tcphdr_t *return_header = TCP_PACKET_HEADER(return_packet);
    /* first check for an ACK */
    if (header->ack) {
        chilog(ERROR, "In LISTEN state, ACK packet arrives.");
        return SEGMENT_DROP;
    }
    /* second check for a SYN */
    if (header->syn) {
        tcp_data->RCV_NXT = SEG_SEQ(packet) + 1;
        tcp_data->IRS = SEG_SEQ(packet);
        /* select ISS */
        tcp_data->ISS = (rand() % 1000 + 1) * 100000;
        /* set return packet value */
        return_header->seq = chitcp_htonl(tcp_data->ISS);
        return_header->ack = 1;
        return_header->ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
        return_header->syn = 1;
        /* update propertiesn */
        tcp_data->SND_NXT = tcp_data->ISS + 1;
        tcp_data->SND_UNA = tcp_data->ISS;
        chitcpd_update_tcp_state(si, entry, SYN_RCVD);
        /* init send/recv buffer */
        assert(circular_buffer_set_seq_initial(&tcp_data->send, tcp_data->SND_NXT) == CHITCP_OK);
        assert(circular_buffer_set_seq_initial(&tcp_data->recv, tcp_data->RCV_NXT) == CHITCP_OK);
        tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);
        return SEGMENT_FINISHED;
    }
}

/* see function declaration */
static int syn_sent_handler(serverinfo_t *si, chisocketentry_t *entry,
                            tcp_packet_t *packet, tcp_packet_t *return_packet)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    tcphdr_t *header = TCP_PACKET_HEADER(packet);
    tcphdr_t *return_header = TCP_PACKET_HEADER(return_packet);
    /* first check ACK */
    if (SEG_ACK(packet) <= tcp_data->ISS || SEG_ACK(packet) > tcp_data->SND_NXT) {
        chilog(ERROR, "In SYN_SENT state, package has invalid ACK.");
        return SEGMENT_DROP;
    }
    /* second check SYN */
    if (header->syn) {
        tcp_data->RCV_NXT = SEG_SEQ(packet) + 1;
        tcp_data->IRS = SEG_SEQ(packet);
        if (header->ack) {
            tcp_data->SND_UNA = SEG_ACK(packet);
            /* update retransmission queue */
            sweep_away_acked_packets(si, entry, SEG_ACK(packet));
        }
        /* our SYN has been ACKed */
        if (tcp_data->SND_UNA > tcp_data->ISS) {
            chitcpd_update_tcp_state(si, entry, ESTABLISHED);
            return_header->seq = chitcp_htonl(tcp_data->SND_NXT);
            return_header->ack = 1;
            return_header->ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
        } else {
            chitcpd_update_tcp_state(si, entry, SYN_RCVD);
            return_header->seq = htonl(tcp_data->ISS);
            return_header->ack = 1;
            return_header->ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
            return_header->syn = 1;
        }
        /* update send window */
        tcp_data->SND_WND = SEG_WND(packet);
        /* init recv buffer */
        assert(circular_buffer_set_seq_initial(&tcp_data->recv, tcp_data->RCV_NXT) == CHITCP_OK);
        tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);
        return SEGMENT_FINISHED;
    }
    return SEGMENT_DROP;
}

/* see function declaration */
static int other_states_handler(serverinfo_t *si, chisocketentry_t *entry,
                                tcp_packet_t *packet, tcp_packet_t *return_packet)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    tcphdr_t *header = TCP_PACKET_HEADER(packet);
    tcphdr_t *return_header = TCP_PACKET_HEADER(return_packet);
    /* first check SEQ */
    uint32_t payload_len = TCP_PAYLOAD_LEN(packet);
    if (SEG_SEQ(packet) < tcp_data->RCV_NXT ||
            SEG_SEQ(packet) + payload_len - 1 >= tcp_data->RCV_NXT + tcp_data->RCV_WND) {
        /* unacceptable segment */
        return_header->seq = chitcp_htonl(tcp_data->SND_NXT);
        return_header->ack = 1;
        return_header->ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
        if (tcp_data->RCV_WND != 0)
            return SEGMENT_FINISHED;
    }

    /* second check SYN */
    if (header->syn) {
        chilog(ERROR, "unexpected SYN packet");
        return SEGMENT_DROP;
    }

    /* third check ACK */
    if (!header->ack) {
        /* drop the segment */
        return SEGMENT_DROP;
    }
    if (entry->tcp_state == SYN_RCVD) {
        if (SEG_ACK(packet) >= tcp_data->SND_UNA && SEG_ACK(packet) <= tcp_data->SND_NXT) {
            tcp_data->SND_UNA = SEG_ACK(packet);
            tcp_data->SND_WND = SEG_WND(packet);
            chitcpd_update_tcp_state(si, entry, ESTABLISHED);
        } else {
            chilog(ERROR, "In SYN_RCVD state, the segment acknowledgement is unacceptable.");
        }
    } else if (entry->tcp_state == LAST_ACK) {
        tcp_data->SND_UNA = SEG_ACK(packet);
        /* our FIN has been acked */
        if (tcp_data->SND_UNA == tcp_data->SND_NXT) {
            chitcpd_update_tcp_state(si, entry, CLOSED);
            return SEGMENT_DROP;
        }
    } else {
        /* ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2, CLOSE_WAIT, CLOSING */
        if (tcp_data->SND_UNA <= SEG_ACK(packet) && SEG_ACK(packet) <= tcp_data->SND_NXT) {
            tcp_data->SND_UNA = SEG_ACK(packet);
            tcp_data->SND_WND = SEG_WND(packet);
        }
        if (entry->tcp_state == FIN_WAIT_1 && !tcp_data->closing &&
                tcp_data->SND_NXT == tcp_data->SND_UNA) {
            /* our FIN has been sent and acknowledged */
            chitcpd_update_tcp_state(si, entry, FIN_WAIT_2);
        }
        if (entry->tcp_state == CLOSING && tcp_data->SND_NXT == tcp_data->SND_UNA) {
            chitcpd_update_tcp_state(si, entry, TIME_WAIT);
            chitcpd_update_tcp_state(si, entry, CLOSED);
        }
    }

    sweep_away_acked_packets(si, entry, SEG_ACK(packet));

    /* used to denote whether we need to send a return packet */
    bool is_reply = false;
    /* for out of order delivery,
       used to denote whether we need to keep current packet */
    bool is_keep = false;

    /* fourth process the segment text */
    if (payload_len > 0) {
        /* out of order delivery logic */
        if (SEG_SEQ(packet) == tcp_data->RCV_NXT) {
            uint8_t *payload_start = TCP_PAYLOAD_START(packet);
            uint32_t len = MIN(payload_len, circular_buffer_available(&tcp_data->recv));
            uint32_t bytes = circular_buffer_write(&tcp_data->recv, payload_start, len, false);
            if (bytes == CHITCP_EINVAL) {
                bytes = 0;
            }
            tcp_data->RCV_NXT += bytes;
            tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);

            /* check whether there are any contiguous segments in out-of-order list */
            if (tcp_data->out_of_order_packets_list != NULL) {
                tcp_packet_t *head_packet = tcp_data->out_of_order_packets_list->packet;
                if (SEG_SEQ(head_packet) == tcp_data->RCV_NXT) {
                    pthread_mutex_lock(&tcp_data->lock_pending_packets);
                    chitcp_packet_list_append(&tcp_data->pending_packets, head_packet);
                    pthread_mutex_unlock(&tcp_data->lock_pending_packets);
                    out_of_order_packet_t *tmp = tcp_data->out_of_order_packets_list;
                    LL_DELETE(tcp_data->out_of_order_packets_list, tmp);
                    free(tmp);
                }
            }
        } else {
            out_of_order_packet_t *o_packet = out_of_order_packet_create(packet);
            out_of_order_packet_t *elt;
            /* ensure there's no duplicate packet in out-of-order list */
            bool is_duplicate = false;
            LL_FOREACH(tcp_data->out_of_order_packets_list, elt) {
                if (out_of_order_packet_cmp(o_packet, elt) == 0) {
                    is_duplicate = true;
                    break;
                }
            }
            if (!is_duplicate) {
                LL_INSERT_INORDER(tcp_data->out_of_order_packets_list, o_packet,
                                  out_of_order_packet_cmp);
            }
            is_keep = true;
        }
        return_header->seq = chitcp_htonl(tcp_data->SND_NXT);
        return_header->ack = 1;
        return_header->ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
        is_reply = true;
    }

    /* fifth check FIN */
    if (header->fin) {
        /* ack this fin */
        tcp_data->RCV_NXT = SEG_SEQ(packet) + 1;
        return_header->seq = chitcp_htonl(tcp_data->SND_NXT);
        return_header->ack = 1;
        return_header->ack_seq = chitcp_htonl(tcp_data->RCV_NXT);

        if (entry->tcp_state == SYN_RCVD || entry->tcp_state == ESTABLISHED) {
            chitcpd_update_tcp_state(si, entry, CLOSE_WAIT);
        }
        if (entry->tcp_state == FIN_WAIT_1) {
            chitcpd_update_tcp_state(si, entry, CLOSING);
        }
        if (entry->tcp_state == FIN_WAIT_2) {
            chitcpd_update_tcp_state(si, entry, TIME_WAIT);
            chitcpd_update_tcp_state(si, entry, CLOSED);
        }

        is_reply = true;
    }

    if (is_reply && is_keep)
        return SEGMENT_KEEP;
    else if (is_reply)
        return SEGMENT_FINISHED;
    else
        return SEGMENT_DROP;
}

/* see function declaration */
static void chitcpd_tcp_handle_packet(serverinfo_t *si, chisocketentry_t *entry)
{
    /* extract a packet from pending list */
    tcp_packet_t *packet = NULL;
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    pthread_mutex_lock(&tcp_data->lock_pending_packets);
    packet = tcp_data->pending_packets->packet;
    chitcp_packet_list_pop_head(&tcp_data->pending_packets);
    pthread_mutex_unlock(&tcp_data->lock_pending_packets);
    /* check and set/cancel persist timer if necessary */
    if (tcp_data->SND_UNA <= SEG_ACK(packet) && SEG_ACK(packet) <= tcp_data->SND_NXT) {
        if (SEG_WND(packet) == 0) {
            /* if the timer is active, the function will return immediately */
            set_persist_timer(si, entry);
        } else {
            /* if the timer is inactive, the function will return immediately */
            mt_cancel_timer(&tcp_data->mt, PST_TIMER_ID);
        }
    }

    /* construct the responding packet to be sent */
    tcp_packet_t *return_packet = calloc(1, sizeof(tcp_packet_t));
    chitcpd_tcp_packet_create(entry, return_packet, NULL, 0);

    int rv;
    if (entry->tcp_state == LISTEN) {
        rv = listen_handler(si, entry, packet, return_packet);
    } else if (entry->tcp_state == SYN_SENT) {
        rv = syn_sent_handler(si, entry, packet, return_packet);
    } else {
        rv = other_states_handler(si, entry, packet, return_packet);
    }

    if (rv != SEGMENT_DROP) {
        /* in this case need to send a reply packet */
        tcphdr_t *return_header = TCP_PACKET_HEADER(return_packet);
        /* add window size */
        return_header->win = chitcp_htons(tcp_data->RCV_WND);
        chitcpd_send_tcp_packet(si, entry, return_packet);
        if (return_header->syn) {
            append_retransmission_queue(entry, return_packet);
            set_retransmission_timer(si, entry);
        } else {
            deep_free_packet(return_packet);
        }
    }

    /* send remaining data in the buffer */
    if (entry->tcp_state == ESTABLISHED || entry->tcp_state == FIN_WAIT_1)
        send_data(si, entry);

    /* try send fin */
    if (entry->tcp_state == FIN_WAIT_1 || entry->tcp_state == CLOSE_WAIT)
        send_fin(si, entry);

    if (rv != SEGMENT_KEEP)
        deep_free_packet(packet);
}

/* see function declaration */
static int send_data(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    if (tcp_data->SND_WND < (tcp_data->SND_NXT - tcp_data->SND_UNA)) {
        return CHITCP_OK;
    }
    uint32_t cnt_to_send = circular_buffer_next(&tcp_data->send) - tcp_data->SND_NXT;
    /* real_wnd: actually how many bytes can we send right now */
    uint16_t real_wnd = tcp_data->SND_WND - (tcp_data->SND_NXT - tcp_data->SND_UNA);
    while (cnt_to_send > 0 && real_wnd > 0) {
        /* extract data from send buffer */
        uint16_t size = MIN(cnt_to_send, TCP_MSS);
        size = MIN(size, real_wnd);
        uint8_t dst[size];
        uint16_t read_bytes = circular_buffer_peek_at(&tcp_data->send, dst, tcp_data->SND_NXT, size);
        if (read_bytes < 0) {
            chilog(CRITICAL, "fail to read bytes from send buffer");
            return -1;
        }

        /* construct packet */
        tcp_packet_t *packet = calloc(1, sizeof(tcp_packet_t));
        uint32_t packet_bytes = chitcpd_tcp_packet_create(entry, packet, dst, read_bytes);
        tcphdr_t *header = TCP_PACKET_HEADER(packet);
        header->ack = 1;
        header->ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
        header->seq = chitcp_htonl(tcp_data->SND_NXT);
        header->win = chitcp_htons(tcp_data->RCV_WND);

        append_retransmission_queue(entry, packet);
        chitcpd_send_tcp_packet(si, entry, packet);
        set_retransmission_timer(si, entry);

        tcp_data->SND_NXT += read_bytes;
        real_wnd -= read_bytes;
        cnt_to_send = circular_buffer_next(&tcp_data->send) - tcp_data->SND_NXT;
    }
    return CHITCP_OK;
}

/* see function declaration */
static void send_fin(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    if (tcp_data->closing && circular_buffer_count(&tcp_data->send) == 0) {
        tcp_packet_t *fin_packet = calloc(1, sizeof(tcp_packet_t));
        chitcpd_tcp_packet_create(entry, fin_packet, NULL, 0);
        tcphdr_t *fin_header = TCP_PACKET_HEADER(fin_packet);
        fin_header->fin = 1;
        fin_header->ack = 1;
        fin_header->ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
        fin_header->seq = chitcp_htonl(tcp_data->SND_NXT);
        tcp_data->SND_NXT += 1;
        fin_header->win = chitcp_htons(tcp_data->RCV_WND);

        append_retransmission_queue(entry, fin_packet);
        chitcpd_send_tcp_packet(si, entry, fin_packet);
        set_retransmission_timer(si, entry);

        if (entry->tcp_state == CLOSE_WAIT)
            chitcpd_update_tcp_state(si, entry, LAST_ACK);

        tcp_data->closing = false;
    }
}

/* see function declaration */
static retransmission_packet_t *retransmission_packet_create(tcp_packet_t *packet, struct timespec sent_time)
{
    retransmission_packet_t *re_packet = calloc(1, sizeof(retransmission_packet_t));
    re_packet->packet = packet;
    re_packet->sent_time = sent_time;
    re_packet->is_retransmitted = false;
    re_packet->next = NULL;
    return re_packet;
}

/* see function declaration */
static void append_retransmission_queue(chisocketentry_t *entry, tcp_packet_t *packet)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    /* construct retransmission packet */
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    retransmission_packet_t *re_packet = retransmission_packet_create(packet, now);
    /* add it to retransmission queue */
    LL_APPEND(tcp_data->retransmission_queue, re_packet);
}

/* see function declaration */
static void sweep_away_acked_packets(serverinfo_t *si, chisocketentry_t *entry, tcp_seq ack_seq)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    if (ack_seq < tcp_data->SND_UNA || ack_seq > tcp_data->SND_NXT) {
        return;
    }
    retransmission_packet_t *elt, *tmp;
    struct timespec st;
    bool is_update_rto = false;
    LL_FOREACH_SAFE(tcp_data->retransmission_queue, elt, tmp) {
        int payload_len = TCP_PAYLOAD_LEN(elt->packet);
        if (SEG_SEQ(elt->packet) + payload_len <= ack_seq) {
            mt_cancel_timer(&tcp_data->mt, RTX_TIMER_ID);
            LL_DELETE(tcp_data->retransmission_queue, elt);
            /* free related bytes in send buffer */
            if (payload_len > 0) {
                uint8_t des[payload_len];
                int bytes = circular_buffer_read(&tcp_data->send, des, payload_len, false);
                assert(bytes == payload_len);
            }
            /* exclude retransmitted segments */
            if (!elt->is_retransmitted) {
                is_update_rto = true;
                st = elt->sent_time;
            }
            retransmission_packet_free(elt);
            continue;
        }
        break;
    }

    /* update SRTT, RTTVAR, RTO */
    if (is_update_rto) {
        struct timespec diff, now;
        clock_gettime(CLOCK_REALTIME, &now);
        timespec_subtract(&diff, &now, &st);
        uint64_t R = MS_TO_NS(diff.tv_sec * 1000) + diff.tv_nsec;
        if (tcp_data->is_first_measurement) {
            tcp_data->SRTT = R;
            tcp_data->RTTVAR = R >> 1;
            tcp_data->is_first_measurement = false;
        } else {
            uint64_t temp = MAX(tcp_data->SRTT, R) - MIN(tcp_data->SRTT, R);
            tcp_data->RTTVAR = (1 - RTO_BETA) * tcp_data->RTTVAR + RTO_BETA * temp;
            tcp_data->SRTT = (1 - RTO_ALPHA) * tcp_data->SRTT + RTO_ALPHA * R;
        }
        tcp_data->RTO = tcp_data->SRTT + MAX(G, K * tcp_data->RTTVAR);
    }

    if (tcp_data->SND_UNA < tcp_data->SND_NXT)
        set_retransmission_timer(si, entry);
}

/* see function declaration */
static void set_retransmission_timer(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    rtx_args_t *rtx_args = calloc(1, sizeof(rtx_args_t));
    rtx_args->si = si;
    rtx_args->entry = entry;
    /* this function will return if the timer is already active */
    if (mt_set_timer(&tcp_data->mt, RTX_TIMER_ID, tcp_data->RTO, rtx_callback_func, rtx_args) == CHITCP_EINVAL)
        free(rtx_args);
}

/* see function declaration */
static void set_persist_timer(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    pst_args_t *pst_args = calloc(1, sizeof(pst_args_t));
    pst_args->si = si;
    pst_args->entry = entry;
    if (mt_set_timer(&tcp_data->mt, PST_TIMER_ID, tcp_data->RTO, pst_callback_func, pst_args) == CHITCP_EINVAL)
        free(pst_args);
}

/* see function declaration */
void rtx_callback_func(multi_timer_t *mt, single_timer_t *st, void *rtx_args)
{
    rtx_args_t *args = (rtx_args_t *)rtx_args;
    chitcpd_timeout(args->si, args->entry, RETRANSMISSION);
}

/* see function declaration */
void pst_callback_func(multi_timer_t *mt, single_timer_t *st, void *pst_args)
{
    pst_args_t *args = (pst_args_t *)pst_args;
    chitcpd_timeout(args->si, args->entry, PERSIST);
}

/* see function declaration */
static void resend_packets(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    retransmission_packet_t *re_queue = tcp_data->retransmission_queue;
    /* implement go-back-N */
    retransmission_packet_t *elt;
    LL_FOREACH(tcp_data->retransmission_queue, elt) {
        elt->is_retransmitted = true;
        /* update window size */
        tcphdr_t *header = TCP_PACKET_HEADER(elt->packet);
        header->win = chitcp_htons(tcp_data->RCV_WND);
        chitcpd_send_tcp_packet(si, entry, elt->packet);
    }
    /* RTO backoff */
    tcp_data->RTO = MIN(tcp_data->RTO * 2, MAX_RTO);
    set_retransmission_timer(si, entry);
}

/* see function declaration */
static void pst_timeout_handler(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    if (circular_buffer_count(&tcp_data->send) > 0) {
        tcp_packet_t *probe = calloc(1, sizeof(tcp_packet_t));
        uint8_t pay_load[PROBE_LENGTH];
        if (circular_buffer_peek_at(&tcp_data->send, pay_load, tcp_data->SND_UNA, PROBE_LENGTH) == CHITCP_EINVAL) {
            chilog(ERROR, "send buffer peek at invalid sequence.");
        }
        uint32_t packet_bytes = chitcpd_tcp_packet_create(entry, probe, pay_load, PROBE_LENGTH);
        tcphdr_t *header = TCP_PACKET_HEADER(probe);
        header->ack = 1;
        header->ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
        header->seq = chitcp_htonl(tcp_data->SND_UNA);
        header->win = chitcp_htons(tcp_data->RCV_WND);
        chitcpd_send_tcp_packet(si, entry, probe);
        /* whenever pst timeout happes, SND_NXT must be either exactly SND_UNA or (SND_UNA + 1) */
        if (tcp_data->SND_NXT > tcp_data->SND_UNA) {
            assert(tcp_data->SND_NXT == tcp_data->SND_UNA + 1);
        } else {
            tcp_data->SND_NXT = tcp_data->SND_UNA + PROBE_LENGTH;
        }
    }
    set_persist_timer(si, entry);
}

/* see function declaration */
static out_of_order_packet_t *out_of_order_packet_create(tcp_packet_t *packet)
{
    out_of_order_packet_t *o_packet = calloc(1, sizeof(out_of_order_packet_t));
    o_packet->packet = packet;
    return o_packet;
}

/* see function declaration */
static int out_of_order_packet_cmp(out_of_order_packet_t *x, out_of_order_packet_t *y)
{
    if (SEG_SEQ(x->packet) < SEG_SEQ(y->packet)) {
        return -1;
    } else if (SEG_SEQ(x->packet) > SEG_SEQ(y->packet)) {
        return 1;
    } else {
        return 0;
    }
}