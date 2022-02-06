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

/* free both the raw content and tcp_packet_t itself */
static void deep_free_packet(tcp_packet_t *packet);

/**
 * @brief a helper function that handle the arrival of new packet
 */
static void chitcpd_tcp_handle_packet(serverinfo_t *si, chisocketentry_t *entry);

void tcp_data_init(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

    tcp_data->pending_packets = NULL;
    pthread_mutex_init(&tcp_data->lock_pending_packets, NULL);
    pthread_cond_init(&tcp_data->cv_pending_packets, NULL);

    /* Initialization of additional tcp_data_t fields,
     * and creation of retransmission thread, goes here */
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
}

int chitcpd_tcp_state_handle_CLOSED(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == APPLICATION_CONNECT)
    {
        tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
        
        /*prepare and send SYN message*/
        tcp_packet_t *packet = malloc(sizeof(tcp_packet_t));
        chitcpd_tcp_packet_create(entry, packet, NULL, 0);
        tcphdr_t *header = TCP_PACKET_HEADER(packet);

        srand(time(NULL));
        tcp_data->ISS = (rand() % 1000 + 1) * 100000; // set the initial sequence number randomly
        header->syn = 1;                              // this is a SYN packet
        header->seq = htonl(tcp_data->ISS);
        tcp_data->SND_UNA = tcp_data->ISS;
        tcp_data->SND_NXT = tcp_data->ISS + 1;
        // set send buffer for client side
        assert(circular_buffer_set_seq_initial(&tcp_data->send, tcp_data->SND_NXT) == CHITCP_OK);
        // send package and update state
        chitcpd_send_tcp_packet(si, entry, packet);
        // free package
        chitcp_tcp_packet_free(packet);
        free(packet);
        // update state
        chitcpd_update_tcp_state(si, entry, SYN_SENT);
    }
    else if (event == CLEANUP)
    {
        /* Any additional cleanup goes here */
    }
    else
        chilog(WARNING, "In CLOSED state, received unexpected event.");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_LISTEN(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        /* Your code goes here */
        chitcpd_tcp_handle_packet(si, entry);
    }
    else
        chilog(WARNING, "In LISTEN state, received unexpected event.");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_SYN_RCVD(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        /* Your code goes here */
        chitcpd_tcp_handle_packet(si, entry);
    }
    else if (event == TIMEOUT_RTX)
    {
        /* Your code goes here */
    }
    else
        chilog(WARNING, "In SYN_RCVD state, received unexpected event.");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_SYN_SENT(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        /* Your code goes here */
        chitcpd_tcp_handle_packet(si, entry);
    }
    else if (event == TIMEOUT_RTX)
    {
        /* Your code goes here */
    }
    else
        chilog(WARNING, "In SYN_SENT state, received unexpected event.");

    return CHITCP_OK;
}

int send_data(serverinfo_t *si, chisocketentry_t *entry) {
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

    uint32_t cnt_to_send = circular_buffer_count(&tcp_data->send);

    while (cnt_to_send > 0 && tcp_data->SND_WND > 0) {
        // extract data from send buffer
        uint16_t size = MIN(cnt_to_send, TCP_MSS);
        uint8_t dst[size];
        uint16_t read_bytes = circular_buffer_read(&tcp_data->send, dst, size, false);
        if (read_bytes < 0) {
            chilog(CRITICAL, "fail to read bytes from send buffer");
            return -1;
        }

        // construct packet
        // TODO: packet_bytes   read_bytes
        tcp_packet_t *packet = calloc(1, sizeof(tcp_packet_t));
        uint16_t packet_bytes = chitcpd_tcp_packet_create(entry, packet, dst, read_bytes);
        tcphdr_t *header = TCP_PACKET_HEADER(packet);
        header->ack = 1;
        header->ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
        header->seq = chitcp_htonl(tcp_data->SND_NXT);
        header->win = chitcp_htons(tcp_data->RCV_WND);

        // send packet
        chitcpd_send_tcp_packet(si, entry, packet);
        deep_free_packet(packet);

        tcp_data->SND_NXT += read_bytes;
        cnt_to_send = circular_buffer_count(&tcp_data->send);
        tcp_data->SND_WND -= read_bytes;
    }
    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_ESTABLISHED(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    if (event == APPLICATION_SEND)
    {
        send_data(si, entry);
        return CHITCP_OK;
        // // extract the data out of send buffer and store in des[]
        // uint32_t cnt = circular_buffer_count(&tcp_data->send);
        // uint8_t dst[cnt];
        // uint16_t read_bytes = circular_buffer_read(&tcp_data->send, dst, cnt, false);
        // // construct packet
        // tcp_packet_t *packet = malloc(sizeof(tcp_packet_t));
        // int packet_bytes = chitcpd_tcp_packet_create(entry, packet, dst, read_bytes);
        // tcphdr_t *header = TCP_PACKET_HEADER(packet);
        // header->ack = 1;
        // header->ack_seq = htonl(tcp_data->RCV_NXT);
        // header->seq = htonl(tcp_data->SND_NXT);
        // header->win = htons(tcp_data->RCV_WND);
        // chitcpd_send_tcp_packet(si, entry, packet);
        // tcp_data->SND_NXT = tcp_data->SND_NXT + packet_bytes;
        // deep_free_packet(packet);
        // return CHITCP_OK;
    }
    else if (event == PACKET_ARRIVAL)
    {
        chitcpd_tcp_handle_packet(si, entry);
    }
    else if (event == APPLICATION_RECEIVE)
    {
        /* Your code goes here */
    }
    else if (event == APPLICATION_CLOSE)
    {
        /* Your code goes here */
    }
    else if (event == TIMEOUT_RTX)
    {
        /* Your code goes here */
    }
    else if (event == TIMEOUT_PST)
    {
        /* Your code goes here */
    }
    else
        chilog(WARNING, "In ESTABLISHED state, received unexpected event (%i).", event);

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_FIN_WAIT_1(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        /* Your code goes here */
    }
    else if (event == APPLICATION_RECEIVE)
    {
        /* Your code goes here */
    }
    else if (event == TIMEOUT_RTX)
    {
        /* Your code goes here */
    }
    else if (event == TIMEOUT_PST)
    {
        /* Your code goes here */
    }
    else
        chilog(WARNING, "In FIN_WAIT_1 state, received unexpected event (%i).", event);

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_FIN_WAIT_2(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        /* Your code goes here */
    }
    else if (event == APPLICATION_RECEIVE)
    {
        /* Your code goes here */
    }
    else if (event == TIMEOUT_RTX)
    {
        /* Your code goes here */
    }
    else
        chilog(WARNING, "In FIN_WAIT_2 state, received unexpected event (%i).", event);

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_CLOSE_WAIT(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == APPLICATION_CLOSE)
    {
        /* Your code goes here */
    }
    else if (event == PACKET_ARRIVAL)
    {
        /* Your code goes here */
    }
    else if (event == TIMEOUT_RTX)
    {
        /* Your code goes here */
    }
    else if (event == TIMEOUT_PST)
    {
        /* Your code goes here */
    }
    else
        chilog(WARNING, "In CLOSE_WAIT state, received unexpected event (%i).", event);

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_CLOSING(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        /* Your code goes here */
    }
    else if (event == TIMEOUT_RTX)
    {
        /* Your code goes here */
    }
    else if (event == TIMEOUT_PST)
    {
        /* Your code goes here */
    }
    else
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
    if (event == PACKET_ARRIVAL)
    {
        /* Your code goes here */
    }
    else if (event == TIMEOUT_RTX)
    {
        /* Your code goes here */
    }
    else if (event == TIMEOUT_PST)
    {
        /* Your code goes here */
    }
    else
        chilog(WARNING, "In LAST_ACK state, received unexpected event (%i).", event);

    return CHITCP_OK;
}

/*                                                           */
/*     Any additional functions you need should go here      */
/*                                                           */

static void deep_free_packet(tcp_packet_t *packet)
{
    chitcp_tcp_packet_free(packet);
    free(packet);
}

static void chitcpd_tcp_handle_packet(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_packet_t *packet = NULL;
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    if (tcp_data->pending_packets)
    {
        pthread_mutex_lock(&tcp_data->lock_pending_packets);
        packet = tcp_data->pending_packets->packet;
        chitcp_packet_list_pop_head(&tcp_data->pending_packets);
        pthread_mutex_unlock(&tcp_data->lock_pending_packets);
    }
    tcphdr_t *header = TCP_PACKET_HEADER(packet);

    // construct the responding packet to be sent
    tcp_packet_t *return_packet = calloc(1, sizeof(tcp_packet_t));
    chitcpd_tcp_packet_create(entry, return_packet, NULL, 0);
    tcphdr_t *return_header = TCP_PACKET_HEADER(return_packet);

    // Only LISTEN and SYN_STATE should accept SYN packet
    if (header->syn)
    {
        if (!(entry->tcp_state == LISTEN || entry->tcp_state == SYN_SENT))
        {
            chilog(ERROR, "In %i state, SYN packet arrives.", entry->tcp_state);
            deep_free_packet(return_packet);
            deep_free_packet(packet);
            return;
        }
    }

    if (header->ack)
    {
        switch (entry->tcp_state)
        {
        case SYN_RCVD:
            if (SEG_ACK(packet) >= tcp_data->SND_UNA && SEG_ACK(packet) <= tcp_data->SND_NXT)
            {
                tcp_data->SND_UNA = SEG_ACK(packet);
                //tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);
                tcp_data->SND_WND = SEG_WND(packet);
                chitcpd_update_tcp_state(si, entry, ESTABLISHED);
            }
            else
            {
                chilog(WARNING, "In SYN_RCVD state, the segment acknowledgement is unacceptable.");
            }
            deep_free_packet(return_packet);
            deep_free_packet(packet);
            return;
        case SYN_SENT:
            if (SEG_ACK(packet) <= tcp_data->ISS || SEG_ACK(packet) > tcp_data->SND_NXT)
            {
                chilog(WARNING, "In SYN_SENT state, package has invalid ACK.");
                deep_free_packet(return_packet);
                deep_free_packet(packet);
                return;
            }
            break;
        case ESTABLISHED:
            chilog(INFO, "SND_UNA:%i, SEG_ACK(packet): %i, SND_NXT:%i", tcp_data->SND_UNA, SEG_ACK(packet), tcp_data->SND_NXT);
            if (tcp_data->SND_UNA > SEG_ACK(packet))
            {
                // TODO chilog
                deep_free_packet(return_packet);
                deep_free_packet(packet);
                return;
            }
            if (tcp_data->SND_UNA <= SEG_ACK(packet) && SEG_ACK(packet) <= tcp_data->SND_NXT)
            {
                tcp_data->SND_UNA = SEG_ACK(packet);
                tcp_data->SND_WND = SEG_WND(packet); // update the send window
                // write packet payload into recv buffer(disable blocking)
                uint8_t *payload_start = TCP_PAYLOAD_START(packet);
                uint32_t len = TCP_PAYLOAD_LEN(packet);
                len = MIN(len, circular_buffer_available(&tcp_data->recv));
                uint32_t bytes = circular_buffer_write(&tcp_data->recv, payload_start, len, false);
                tcp_data->RCV_NXT += bytes;
                tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);
                // construct return packet
                return_header->ack = 1;
                return_header->ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
                return_header->seq = chitcp_htonl(tcp_data->SND_NXT);
                return_header->win = chitcp_htons(tcp_data->RCV_WND);
                chitcpd_send_tcp_packet(si, entry, return_packet);
                deep_free_packet(return_packet);
                deep_free_packet(packet);

                send_data(si, entry);
                return;
            }
            // TODO deal with segment out of order: SEG_ACK(packet) > tcp_data->SND_NXT

        default:
            chilog(ERROR, "In %i state, ACK packet arrives.", entry->tcp_state);
            deep_free_packet(return_packet);
            deep_free_packet(packet);
            return;
        }
    }

    if (header->syn)
    {
        tcp_data->RCV_NXT = SEG_SEQ(packet) + 1;
        tcp_data->IRS = SEG_SEQ(packet);
        return_header->ack = 1;
        // TODO chitcp_htonl
        return_header->ack_seq = htonl(tcp_data->RCV_NXT);

        switch (entry->tcp_state)
        {
        case LISTEN:
            return_header->syn = 1; // this is a SYN packet
            // set the initial sequence number randomly
            tcp_data->ISS = (rand() % 1000 + 1) * 100000;
            return_header->seq = htonl(tcp_data->ISS);
            tcp_data->SND_NXT = tcp_data->ISS + 1;
            tcp_data->SND_UNA = tcp_data->ISS;
            chitcpd_update_tcp_state(si, entry, SYN_RCVD);
            // set send and recv buffer for server side
            assert(circular_buffer_set_seq_initial(&tcp_data->send, tcp_data->SND_NXT) == CHITCP_OK);
            assert(circular_buffer_set_seq_initial(&tcp_data->recv, tcp_data->RCV_NXT) == CHITCP_OK);
            tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);
            chilog(INFO, "buffer size: %i", tcp_data->RCV_WND);
            return_header->win = chitcp_htons(tcp_data->RCV_WND);
            break;
        case SYN_SENT:
            // set receive buffer for client side
            assert(circular_buffer_set_seq_initial(&tcp_data->recv, tcp_data->RCV_NXT) == CHITCP_OK);
            tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);
            if (header->ack)
            {
                tcp_data->SND_UNA = SEG_ACK(packet);
            }
            // TODO why not +1
            if (tcp_data->SND_UNA > tcp_data->ISS)
            {
                return_header->seq = htonl(tcp_data->SND_NXT);
                chitcpd_update_tcp_state(si, entry, ESTABLISHED);
            }
            else
            // TODO
            {
                return_header->syn = 1;
                return_header->seq = htonl(tcp_data->ISS);
                chitcpd_update_tcp_state(si, entry, SYN_RCVD);
            }
            tcp_data->SND_WND = SEG_WND(packet);
            return_header->win = chitcp_htons(tcp_data->RCV_WND);
            break;
        }
        chilog(WARNING, "buffer size: %i", tcp_data->RCV_WND);
        // send the responding packet
        chitcpd_send_tcp_packet(si, entry, return_packet);
        deep_free_packet(return_packet);
        deep_free_packet(packet);
        return;
    }
}