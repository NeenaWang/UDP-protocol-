#include "gbn.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <arpa/inet.h>
#include <stdbool.h>

#ifndef bool
#define bool _Bool
#define true 1
#define false 0
#endif

state_t s = {.current_state = CLOSED};
unsigned int window_size;
unsigned int ssthresh;
volatile sig_atomic_t timeout_flag;
struct sockaddr_in server_addr;

void gbn_init()
{
    s.current_state = CLOSED;
}

int gbn_client_connectconnect(int sockfd, const char *server_ip, int server_port)
{
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0)
    {
        perror("inet_pton failed");
        return -1;
    }
    return 0;
}

// void timeout_handler(int sig)
// {
//     timeout_flag = 1;
// }

volatile sig_atomic_t e_flag = false;

void timeout_handler(int signum)
{
    printf("Call timeout handler\n");
    e_flag = true;
}

uint16_t checksum(uint16_t *buf, int nwords)
{
    uint32_t sum;

    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

int gbn_socket(int domain, int type, int protocol)
{

    /*----- Randomizing the seed. This is used by the rand() function -----*/

    /* TODO: Your code here. */

    srand((unsigned)time(0));
    int sockfd = socket(domain, type, protocol);
    if (sockfd < 0)
    {
        perror("Error creating socket");
        return -1;
    }
    return sockfd;
}

// know which port and address to receive
int gbn_bind(int sockfd, const struct sockaddr *server, socklen_t socklen)
{

    /* TODO: Your code here. */
    if (bind(sockfd, server, socklen) == -1)
    {
        perror("Error binding socket to address");
        return -1;
    }
    return 0; 
}

int gbn_listen(int sockfd, int backlog)
{

    /* TODO: Your code here. */
    // not using this backlog parameter
    // return(-1);
    printf("Server is ready to receive on port %d.\n", 8081);
    return 0;
}

// client side (send SYN-> receive SYNACK)
int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen)
{

    /* TODO: Your code here. */
    s.current_state = CLOSED;

    gbnhdr syn_packet = {.type = SYN, .seqnum = 0, .checksum = 0};

    syn_packet.checksum = checksum((uint16_t *)&syn_packet, sizeof(gbnhdr) / 2);

    printf("Sending SYN packet..wow\n");
    s.current_state = SYN_SENT;
    if (sendto(sockfd, &syn_packet, sizeof(syn_packet), 0, server, socklen) < 0)
    {
        perror("sendto SYN");
        return -1;
    }

    // server send back SYNACK
    gbnhdr synack_packet;
    struct sockaddr from;
    socklen_t fromlen = sizeof(from);
    if (recvfrom(sockfd, &synack_packet, sizeof(synack_packet), 0, &from, &fromlen) < 0)
    {
        perror("recvfrom SYNACK");
        return -1;
    }

    // Check if the received packet is a SYNACK
    if (synack_packet.type == SYNACK)
    {
        printf("Received SYNACK, connection established.\n");
        s.current_state = ESTABLISHED;
        memcpy(&s.remote_addr, server, sizeof(struct sockaddr));
        s.remote_addr_len = socklen;
        return 0;
    }
    else
    {
        fprintf(stderr, "Expected SYNACK, received different packet type.\n");
        return -1;
    }
}

// server side (receive SYN->send SYNACK)

int gbn_accept(int sockfd, struct sockaddr *client, socklen_t *socklen)
{

    /* TODO: Your code here. */

    // return(-1);
    gbnhdr syn_pkt;
    if (recvfrom(sockfd, &syn_pkt, sizeof(syn_pkt), 0, client, socklen) < 0)
    {
        perror("Error receiving SYN packet");
        return -1;
    }

    // Check for SYN packet type
    if (syn_pkt.type != SYN)
    {
        fprintf(stderr, "Expected SYN, received different packet type.\n");
        return -1;
    }

    // Prepare and send SYNACK packet in response
    gbnhdr synack_pkt = {.type = SYNACK, .seqnum = 0, .checksum = 0};
    // Calculate checksum for SYNACK packet, similar to gbn_connect
    synack_pkt.checksum = checksum((uint16_t *)&synack_pkt, sizeof(gbnhdr) / 2);

    if (sendto(sockfd, &synack_pkt, sizeof(synack_pkt), 0, client, *socklen) < 0)
    {
        perror("Error sending SYNACK packet");
        return -1;
    }

    printf("the connection is good\n");
    // return 0;
    return sockfd;
}

ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags)
{

    /* TODO: Your code here. */
    if (s.current_state != ESTABLISHED)
    {
        printf("Connection not established.\n");
        return -1;
    }

    printf("FUNCTION: gbn_send() %d...\n", sockfd);
    size_t data_sent = 0;
    int attempts = 0;
    int acked_packets = 0;

    gbnhdr DATA_packet;
    gbnhdr ACK_packet;
    struct sockaddr_in client_sockaddr;
    socklen_t client_socklen = sizeof(client_sockaddr);

    while (data_sent < len && s.current_state == ESTABLISHED)
    {
        int i = 0;
        int packets_sent = 0;
        for (i = 0; i < s.window_size && (data_sent < len); i++)
        {
            // size_t remaining_data = len - data_sent;
            // size_t segment_size = remaining_data > DATALEN ? DATALEN : remaining_data;
            memset(DATA_packet.data, 0, DATALEN);
            memcpy(DATA_packet.data, buf + data_sent, DATALEN);

            DATA_packet.type = DATA;
            DATA_packet.seqnum = s.seq_num++;
            DATA_packet.checksum = 0; 
            DATA_packet.checksum = htons(checksum((uint16_t *)&DATA_packet, sizeof(DATA_packet) / 2));

            printf("Sending DATA packet with seqnum: %d\n", DATA_packet.seqnum + i);

            if (sendto(sockfd, &DATA_packet, sizeof(gbnhdr), 0, (struct sockaddr *)&s.remote_addr, s.remote_addr_len) < 0)
            {
                perror("sendto");
                return -1;
            }

            data_sent += DATALEN;
            packets_sent++;
        }

        int acks_received = 0;
        while (acks_received < packets_sent)
        {
            alarm(TIMEOUT); 
            gbnhdr ack_packet;
            struct sockaddr from;
            socklen_t fromlen = sizeof(from);

            if (maybe_recvfrom(sockfd, &ack_packet, sizeof(gbnhdr), 0, &from, &fromlen) < 0 && errno != EINTR)
            {
                perror("Error receiving ACK");
                return -1;
            }
            if (e_flag)
            {
                printf("Timeout occurred, decreasing window size. Current window size: %d\n", window_size);
                e_flag = false; 
                window_size = (window_size / 2) > 1 ? (window_size / 2) : 1;
                data_sent -= DATALEN * packets_sent;
                s.seq_num -= packets_sent;
                break;
            }

            else if (ack_packet.type == DATAACK && ack_packet.seqnum == (s.seq_num - packets_sent + acks_received) % 256)
            {
                acks_received++;
                printf("ACK received for packet %d, increasing acks_received to %d\n", ack_packet.seqnum, acks_received);
            }
        }
        if (acks_received == packets_sent)
        {
            printf("All packets in the window acknowledged, increasing window size. New window size: %d\n", window_size + 1);
            // when all data get ACK means the windowsize can be larger to increase effiency
            window_size = (window_size + 1) < MAX_WINDOW_SIZE ? (window_size + 1) : MAX_WINDOW_SIZE; 
        }
    }
    alarm(0); 
    printf("Transmission completed. Total sent bytes: %zu\n", data_sent);
    return data_sent; 
}


ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags)
{

    /* TODO: Your code here. */
    printf("FUNCTION: gbn_recv() %d...\n", sockfd);

    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    gbnhdr recv_packet, ack_packet;
    ssize_t packet_len = 0;

    memset(&ack_packet, 0, sizeof(ack_packet));
    ack_packet.type = DATAACK;

    while (true)
    {
        memset(&recv_packet, 0, sizeof(recv_packet));
        packet_len = recvfrom(sockfd, &recv_packet, sizeof(recv_packet), flags, (struct sockaddr *)&from, &fromlen);

        if (packet_len < 0){
            if (errno == EINTR){
                perror("Error receiving packet");
                continue; 
            }
        }

        recv_packet.checksum = ntohs(recv_packet.checksum); 
        uint16_t computed_checksum = checksum((uint16_t *)&recv_packet, sizeof(recv_packet) / 2 - sizeof(recv_packet.checksum) / 2);
        if (recv_packet.type == DATA && recv_packet.seqnum == s.expected_seqnum)
        {
            printf("Received DATA packet: seqnum=%d\n", recv_packet.seqnum);
            memcpy(buf, recv_packet.data, DATALEN);

            // Send ACK for this packet
            ack_packet.seqnum = recv_packet.seqnum; 
            ack_packet.checksum = 0;
            ack_packet.checksum = htons(checksum((uint16_t *)&ack_packet, sizeof(ack_packet) / 2 - sizeof(ack_packet.checksum) / 2));

            if (sendto(sockfd, &ack_packet, sizeof(ack_packet), 0, (struct sockaddr *)&from, fromlen) < 0)
            {
                perror("Error sending ACK");
            }
            else
            {
                printf("Sent ACK for seqnum %d\n", ack_packet.seqnum);
            }

            // for next packet update seqnum 
            s.expected_seqnum++;
            break;
        }
        // else if (recv_packet.type == FIN)
        // {
        //     // Handle FIN packet
        //     printf("Received FIN packet\n");
        //     s.current_state = FIN_RCVD;
        //     continue;
        // }
    }

    return DATALEN;
}

int gbn_close(int sockfd)
{
    if (sockfd >= 0)
    {
        // Close the socket
        if (close(sockfd) < 0)
        {
            perror("Error closing socket");
            return -1;
        }
        // Reset the state
        s.current_state = CLOSED;
        printf("Connection closed.\n");
    }
    return 0;
}

ssize_t maybe_recvfrom(int s, char *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen)
{

    /*----- Packet not lost -----*/
    if (rand() > LOSS_PROB * RAND_MAX)
    {

        /*----- Receiving the packet -----*/
        int retval = recvfrom(s, buf, len, flags, from, fromlen);

        /*----- Packet corrupted -----*/
        if (rand() < CORR_PROB * RAND_MAX)
        {
            /*----- Selecting a random byte inside the packet -----*/
            int index = (int)((len - 1) * rand() / (RAND_MAX + 1.0));

            /*----- Inverting a bit -----*/
            char c = buf[index];
            if (c & 0x01)
                c &= 0xFE;
            else
                c |= 0x01;
            buf[index] = c;
        }

        return retval;
    }
    /*----- Packet lost -----*/
    return (len); /* Simulate a success */
}

ssize_t maybe_sendto(int s, const void *buf, size_t len, int flags,
                     const struct sockaddr *to, socklen_t tolen)
{

    char *buffer = malloc(len);
    memcpy(buffer, buf, len);

    /*----- Packet not lost -----*/
    if (rand() > LOSS_PROB * RAND_MAX)
    {
        /*----- Packet corrupted -----*/
        if (rand() < CORR_PROB * RAND_MAX)
        {

            /*----- Selecting a random byte inside the packet -----*/
            int index = (int)((len - 1) * rand() / (RAND_MAX + 1.0));

            /*----- Inverting a bit -----*/
            char c = buffer[index];
            if (c & 0x01)
                c &= 0xFE;
            else
                c |= 0x01;
            buffer[index] = c;
        }

        /*----- Sending the packet -----*/
        int retval = sendto(s, buffer, len, flags, to, tolen);
        free(buffer);
        return retval;
    }
    /*----- Packet lost -----*/
    else
        return (len); /* Simulate a success */
}
