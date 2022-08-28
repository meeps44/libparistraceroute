#ifndef LIBPT_SNIFFER_H
#define LIBPT_SNIFFER_H

/**
 * \file sniffer.h
 * \brief Header file : packet sniffer
 *
 * The current implementation is based on raw sockets, but we could envisage a
 * libpcap implementation too
 */

#include <stdbool.h> // bool
#include "packet.h"  // packet_t
#include "use.h"

// ERLEND //

// typedef struct hop
// {
// int returned_flowlabel;
// int hopnumber;
// address *hop_address; // Could be a list of address pointers
// } hop;

// typedef struct traceroute
// {
// // For easy route comparison - make a hash of the (source_ip, dest_ip, outgoing_flow_label)-tuple and add it
// // as a variable to the struct?
// // "outgoing_tcp_port": "443",
// // "flow_label": "1048575",
// // "timestamp": "2022-05-07 15:50:47.559550",
// // "source": "2a03:b0c0:1:d0::b45:6001",
// // "source_asn": "14061",
// // "destination": "2600:9000:20a5:f800:10:15f0:8cc0:93a1",
// // "destination_asn": "16509",
// // "path_id": "c0f8ed8a7c1f3d725bd89de7ed7eced0b9dcc67b",
// uint16_t outgoing_tcp_port;
// char *timestamp;
// address source_ip;
// uint32_t source_asn;
// address destination_ip;
// uint32_t destination_asn;
// // uint8_t path_id[SHA_DIGEST_LENGTH]; // Need to include OpenSSL lib to get SHA_DIGEST_LENGTH definition
// hop *hops[35]; // maximum hop length is 35. any hops longer than that do not get included.
// // Could also be a list of *hop-pointers
// }
// traceroute;

// typedef struct ipv6_address
// {
// uint16_t address_short[8];
// } address;

// typedef struct my_icmp6_header
// {
// uint8_t type;
// uint8_t code;
// uint16_t checksum;
// uint32_t opt;
// } icmp6_header;

// typedef struct my_ipv6_header
// {
// uint8_t version : 4;
// uint32_t flow_label : 20;
// uint8_t traffic_class;
// uint16_t payload_length;
// uint8_t next_header;
// uint8_t hop_limit;
// address source;
// address destination;
// } ipv6_header;

// void parse_packet(const packet_t *p);
// ipv6_header *parse_ipv6(const uint8_t *first_byte);
// icmp6_header *parse_icmp6(const uint8_t *icmp_first_byte);
// void parse_tcp(const uint8_t *p);

// END ERLEND //

/**
 * \struct sniffer_t
 * \brief Structure representing a packet sniffer. The sniffer calls
 *    a function whenever a packet is sniffed. For instance
 *    sniffer->recv_param may point to a queue_t instance and
 *    sniffer->recv_callback may be used to feed this queue whenever
 *    a packet is sniffed.
 */

typedef struct
{
#ifdef USE_IPV4
    int icmpv4_sockfd; /**< Raw socket for sniffing ICMPv4 packets */
#endif
#ifdef USE_IPV6
    int icmpv6_sockfd; /**< Raw socket for sniffing ICMPv6 packets */
#endif
    void *recv_param;                                          /**< This pointer is passed whenever recv_callback is called */
    bool (*recv_callback)(packet_t *packet, void *recv_param); /**< Callback for received packets */
} sniffer_t;

/**
 * \brief Creates a new sniffer.
 * \param callback This function is called whenever a packet is sniffed.
 * \return Pointer to a sniffer_t structure representing a packet sniffer
 */

sniffer_t *sniffer_create(void *recv_param, bool (*recv_callback)(packet_t *, void *));

/**
 * \brief Free a sniffer_t structure.
 * \param sniffer Points to a sniffer_t instance.
 */

void sniffer_free(sniffer_t *sniffer);

#ifdef USE_IPV4
/**
 * \brief Return the file descriptor related to the ICMPv4 raw socket
 *    managed by the sniffer.
 * \param sniffer Points to a sniffer_t instance.
 * \return The corresponding socket file descriptor.
 */

int sniffer_get_icmpv4_sockfd(sniffer_t *sniffer);
#endif

#ifdef USE_IPV6
/**
 * \brief Return the file descriptor related to the ICMPv6 raw socket
 *    managed by the sniffer.
 * \param sniffer Points to a sniffer_t instance.
 * \return The corresponding socket file descriptor.
 */

int sniffer_get_icmpv6_sockfd(sniffer_t *sniffer);
#endif

/**
 * \brief Fetch a packet from the listening socket. The sniffer then
 *   call recv_callback and pass to this function this packet and
 *   eventual data stored in sniffer->recv_packet. If this callback
 *   returns false, a message is printed.
 * \param sniffer Points to a sniffer_t instance.
 * \param protocol_id The family of the packet to fetch (IPPROTO_ICMP, IPPROTO_ICMPV6)
 */

void sniffer_process_packets(sniffer_t *sniffer, uint8_t protocol_id);

#endif // LIBPT_SNIFFER_H
