#include "use.h"
#include "config.h"
#include "ext.h" // erlend
#include <stdbool.h>

#include <stdlib.h>     // malloc
#include <stdio.h>      // perror
#include <string.h>     // memcpy, memset
#include <unistd.h>     // fnctl
#include <fcntl.h>      // fnctl
#include <sys/socket.h> // socket, bind,
#include <sys/types.h>  // socket, bind
#include <arpa/inet.h>
#include <netinet/in.h> // IPPROTO_ICMP, IPPROTO_ICMPV6

#ifdef USE_IPV6
#include <netinet/ip6.h> // ip6_hdr
#endif

#include "sniffer.h"

#define BUFLEN 4096

// Solaris/Sun
// http://livre.g6.asso.fr/index.php/L%27exemple_%C2%AB_mini-ping_%C2%BB_revisit%C3%A9
#ifdef sun                // Solaris
#define _XOPEN_SOURCE 500 // correct recvmsg/sendmsg/msg/CMSG_xx syntax
#define __EXTENSIONS__
#ifndef CMSG_SPACE // Solaris <= 9
#define CMSG_SPACE(l) ((size_t)_CMSG_HDR_ALIGN(sizeof(struct cmsghdr) + (l)))
#define CMSG_LEN(l) ((size_t)_CMSG_DATA_ALIGN(sizeof(struct cmsghdr)) + (l))
#endif
#endif

// Some implementation does not respects RFC3542
// http://livre.g6.asso.fr/index.php/L'implémentation
#ifndef IPV6_RECVHOPLIMIT
#define IPV6_RECVHOPLIMIT IPV6_HOPLIMIT
#endif
#ifndef IPV6_RECVPKTINFO
#define IPV6_RECVPKTINFO IPV6_PKTINFO
#endif

/**
 * \brief Initialize an ICMPv4 raw socket in a sniffer_t instance
 * \param sniffer A pointer to a sniffer_t instance
 * \param port The listening port
 * \return true iif successful
 */
#ifdef USE_IPV4
static bool create_icmpv4_socket(sniffer_t *sniffer, uint16_t port)
{
    struct sockaddr_in saddr;

    // Create a raw socket (man 7 ip) listening ICMPv4 packets
    if ((sniffer->icmpv4_sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1)
    {
        perror("create_icmpv4_socket: error while creating socket");
        goto ERR_SOCKET;
    }

    // Make the socket non-blocking
    if (fcntl(sniffer->icmpv4_sockfd, F_SETFD, O_NONBLOCK) == -1)
    {
        goto ERR_FCNTL;
    }

    // Bind it to 0.0.0.0
    memset(&saddr, 0, sizeof(struct sockaddr_in));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY;
    saddr.sin_port = htons(port);

    if (bind(sniffer->icmpv4_sockfd, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in)) == -1)
    {
        perror("create_icmpv4_socket: error while binding the socket");
        goto ERR_BIND;
    }

    return true;

ERR_BIND:
ERR_FCNTL:
    close(sniffer->icmpv4_sockfd);
ERR_SOCKET:
    return false;
}
#endif

/**
 * \brief Initialize an ICMPv6 raw socket in a sniffer_t instance
 * \param sniffer A pointer to a sniffer_t instance
 * \param port The listening port
 * \return true iif successful
 */
#ifdef USE_IPV6
static bool create_icmpv6_socket(sniffer_t *sniffer, uint16_t port)
{
    struct in6_addr anyaddr = IN6ADDR_ANY_INIT;
    struct sockaddr_in6 saddr;
    int on = 1;

    // Create a raw socket (man 7 ip) listening ICMPv6 packets
    if ((sniffer->icmpv6_sockfd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) == -1)
    {
        perror("create_icmpv6_socket: error while creating socket");
        goto ERR_SOCKET;
    }

    // Make the socket non-blocking
    if (fcntl(sniffer->icmpv6_sockfd, F_SETFD, O_NONBLOCK) == -1)
    {
        goto ERR_FCNTL;
    }

    // IPV6 socket options we actually need this for reconstruction of an IPv6 Packet lateron
    // - dst_ip + arriving interface
    // - TCL
    // - Hoplimit
    // http://h71000.www7.hp.com/doc/731final/tcprn/v53_relnotes_025.html
    // http://livre.g6.asso.fr/index.php?title=L%27impl%C3%A9mentation&oldid=2961

    if ((setsockopt(sniffer->icmpv6_sockfd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) == -1)     // struct in6_pktinfo
        || (setsockopt(sniffer->icmpv6_sockfd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on, sizeof(on)) == -1) // int
        || (setsockopt(sniffer->icmpv6_sockfd, IPPROTO_IPV6, IPV6_RECVRTHDR, &on, sizeof(on)) == -1)    // struct ip6_rthdr
        || (setsockopt(sniffer->icmpv6_sockfd, IPPROTO_IPV6, IPV6_RECVHOPOPTS, &on, sizeof(on)) == -1)  // struct ip6_hbh
        || (setsockopt(sniffer->icmpv6_sockfd, IPPROTO_IPV6, IPV6_RECVDSTOPTS, &on, sizeof(on)) == -1)  // struct ip6_dest
        || (setsockopt(sniffer->icmpv6_sockfd, IPPROTO_IPV6, IPV6_RECVTCLASS, &on, sizeof(on)) == -1)   // int
    )
    {
        perror("create_icmpv6_socket: error in setsockopt");
        goto ERR_SETSOCKOPT;
    }

    memset(&saddr, 0, sizeof(struct sockaddr_in6));
    // Bind to ::1
    saddr.sin6_family = AF_INET6;
    saddr.sin6_addr = anyaddr;
    saddr.sin6_port = htons(port);

    if (bind(sniffer->icmpv6_sockfd, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in6)) == -1)
    {
        perror("create_icmpv6_socket: error while binding the socket");
        goto ERR_BIND;
    }

    return true;

ERR_BIND:
ERR_SETSOCKOPT:
ERR_FCNTL:
    close(sniffer->icmpv6_sockfd);
ERR_SOCKET:
    return false;
}
#endif

sniffer_t *sniffer_create(void *recv_param, bool (*recv_callback)(packet_t *, void *))
{
    sniffer_t *sniffer;

    // TODO: We currently only listen for ICMP thanks to raw sockets which
    // requires root privileges
    // Can we set port to 0 to capture all packets wheter ICMP, UDP or TCP?
    if (!(sniffer = malloc(sizeof(sniffer_t))))
        goto ERR_MALLOC;
#ifdef USE_IPV4
    if (!create_icmpv4_socket(sniffer, 0))
        goto ERR_CREATE_ICMPV4_SOCKET;
#endif
#ifdef USE_IPV6
    if (!create_icmpv6_socket(sniffer, 0))
        goto ERR_CREATE_ICMPV6_SOCKET;
#endif
    sniffer->recv_param = recv_param;
    sniffer->recv_callback = recv_callback;
    return sniffer;
#ifdef USE_IPV6
ERR_CREATE_ICMPV6_SOCKET:
#ifdef USE_IPV4
    close(sniffer->icmpv4_sockfd);
#endif
#endif
#ifdef USE_IPV4
ERR_CREATE_ICMPV4_SOCKET:
#endif
    free(sniffer);
ERR_MALLOC:
    return NULL;
}

void sniffer_free(sniffer_t *sniffer)
{
    if (sniffer)
    {
#ifdef USE_IPV4
        close(sniffer->icmpv4_sockfd);
#endif
#ifdef USE_IPV6
        close(sniffer->icmpv6_sockfd);
#endif
        free(sniffer);
    }
}

#ifdef USE_IPV4
int sniffer_get_icmpv4_sockfd(sniffer_t *sniffer)
{
    return sniffer->icmpv4_sockfd;
}
#endif

#ifdef USE_IPV6
int sniffer_get_icmpv6_sockfd(sniffer_t *sniffer)
{
    return sniffer->icmpv6_sockfd;
}

/**
 * \brief Rebuild the missing parts of an IPv6 header.
 * \param ip6_header The IPv6 header we want to complete.
 * \param msghdr
 * \param from
 * \param num_bytes The size in bytes of the IPv6 header
 * \return true iif successful
 */

static bool rebuild_ipv6_header(
    struct ip6_hdr *ip6_header,
    struct msghdr *msg,
    const struct sockaddr_in6 *from,
    ssize_t num_bytes)
{
    bool ret = true;
    struct cmsghdr *cmsg;
    struct in6_pktinfo *pktinfo;
    uint32_t tcl;

    // Now we can rebuild the IPv6 layer
    // ip_version (hardcoded), traffic class (updated later), flow label (hardcoded)
    ip6_header->ip6_ctlun.ip6_un1.ip6_un1_flow = htonl(0x60000000);

    // length
    ip6_header->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(num_bytes);

    // src_ip
    memcpy(&ip6_header->ip6_src, &(from->sin6_addr), sizeof(struct in6_addr));

    // protocol
    ip6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt = IPPROTO_ICMPV6;

    // Fetch ancillary data (e.g last parts of the IPv6 header)
    for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg))
    {
        if (cmsg->cmsg_level == IPPROTO_IPV6)
        {
            switch (cmsg->cmsg_type)
            {
            // Possible values: /usr/include/linux/in6.h
            case IPV6_PKTINFO: // dst_ip
                pktinfo = (struct in6_pktinfo *)CMSG_DATA(cmsg);
                memcpy(&(ip6_header->ip6_dst), &(pktinfo->ipi6_addr), sizeof(struct in6_addr));
                break;
            case IPV6_HOPLIMIT: // ttl
                ip6_header->ip6_ctlun.ip6_un1.ip6_un1_hlim = *(uint8_t *)CMSG_DATA(cmsg);
                break;
            case IPV6_RTHDR:
                break; // TODO handle this case properly, see RFC 2292
            case IPV6_HOPOPTS:
                break; // TODO handle this case properly, see RFC 2292
            case IPV6_DSTOPTS:
                break;        // TODO handle this case properly, see RFC 2292
            case IPV6_TCLASS: // traffic class
                tcl = *(uint8_t *)CMSG_DATA(cmsg);
                *((uint32_t *)&(ip6_header->ip6_ctlun.ip6_un1.ip6_un1_flow)) |= htonl(tcl << 8);
                break;
            default:
                // This should never occur
                fprintf(stderr, "Unhandled cmsg of type %d\n", cmsg->cmsg_type);
                ret = false;
                break;
            }
        }
        else
        {
            // This should never occur
            fprintf(stderr, "Ignoring msg (level = %d)\n", cmsg->cmsg_level);
            ret = false;
        }
    }

    return ret;
}

/**
 * \brief Fetch an IPv6/ICMPv6 packet from an IPv6 socket
 * \param ipv6_sockfd An IPv6 socket which is sniffing an ICMPv6 packet
 * \param bytes A preallocated buffer in which we write the full IPv6 packet.
 * \param len The size of the preallocated buffer
 * \param flags
 */

static ssize_t recv_icmpv6(int ipv6_sockfd, void *bytes, size_t len, int flags)
{
    ssize_t num_bytes;
    char cmsg_buf[BUFLEN];
    struct sockaddr_in6 from;
    struct ip6_hdr *ip6_header = (struct ip6_hdr *)bytes;

    struct iovec iov = {
        .iov_base = ((uint8_t *)bytes) + sizeof(struct ip6_hdr),
        .iov_len = len - sizeof(struct ip6_hdr)};

    struct msghdr msg = {
        .msg_name = &from,                  // socket address
        .msg_namelen = sizeof(from),        // sizeof socket
        .msg_iov = &iov,                    // buffer (scather/gather array)
        .msg_iovlen = 1,                    // number of msg_iov elements
        .msg_control = cmsg_buf,            // ancillary data
        .msg_controllen = sizeof(cmsg_buf), // sizeof ancillary data
        .msg_flags = flags                  // flags related to recv messages
    };

    // We do not need memset since we will explicitely set each bit of
    // the IPv6 header. Uncomment to debug.
    // memset(bytes, 0, sizeof(struct ip6_hdr));

    // Fetch the bytes nested in the IPv6 packet (in the case of traceroute,
    // we fetch ICMPv6/UDP/payload layers).
    if ((num_bytes = recvmsg(ipv6_sockfd, &msg, flags)) == -1)
    {
        fprintf(stderr, "recv_ipv6_header: Can't fetch data\n");
        goto ERR_RECVMSG;
    }

    if (msg.msg_flags & MSG_TRUNC)
    {
        fprintf(stderr, "recv_ipv6_header: data truncated\n");
        goto ERR_MSG_TRUNC;
    }

    if (msg.msg_flags & MSG_CTRUNC)
    {
        fprintf(stderr, "recv_ipv6_header: ancillary data truncated\n");
        goto ERR_MSG_CTRUNK;
    }

    if (!rebuild_ipv6_header(ip6_header, &msg, &from, num_bytes))
    {
        fprintf(stderr, "recv_ipv6_header: error in rebuild_ipv6_header\n");
        goto ERR_REBUILD_IPV6_HEADER;
    }

    return num_bytes + sizeof(struct ip6_hdr);
ERR_REBUILD_IPV6_HEADER:
ERR_MSG_CTRUNK:
ERR_MSG_TRUNC:
ERR_RECVMSG:
    return 0;
}

#endif // USE_IPV6

// ERLEND //
// enum IPV6_HEADER_OPTS
// {
// NH_NNH = 59,      // No next header
// NH_HBH_OPTS = 0,  // Hop-by-Hop Options
// NH_DST_OPTS = 60, // Destination Options
// NH_RH = 43,       // Routing Header
// NH_FH = 44,       // Fragment Header
// NH_AH = 51,       // Authentication Header
// NH_ESPH = 50,     // Encapsulation Security Payload Header
// NH_MH = 135,      // Mobility Header
// NH_TCP = 6,
// NH_UDP = 17,
// NH_ICMPv6 = 58,
// };

// // Type codes: https://datatracker.ietf.org/doc/html/rfc4443
// enum ICMP_TYPES
// {
// ICMP_ECHO_REQUEST = 128,
// ICMP_ECHO_REPLY = 129,
// ICMP_DESTINATION_UNREACHABLE = 1,
// ICMP_PACKET_TOO_BIG = 2,
// ICMP_TIME_EXCEEDED = 3,
// ICMP_PARAMETER_PROBLEM = 4,
// };

// icmp6_header *parse_icmp6(const uint8_t *icmp_first_byte)
// {
// puts("Entering parse_icmp6");
// icmp6_header *h = calloc(1, sizeof(icmp6_header));
// ipv6_header *inner_ipv6;
// h->type = *icmp_first_byte;
// h->code = *(icmp_first_byte + 1);
// h->checksum = ((uint16_t) * (icmp_first_byte + 2) << 8) | *(icmp_first_byte + 3);
// // Depending on the type there will be a value between bytes 5-9 as well, however
// // as it is not used in our project it will not be parsed at this time.

// switch (h->type)
// {
// case ICMP_TIME_EXCEEDED:
// inner_ipv6 = parse_ipv6(icmp_first_byte + 8);
// printf("Returned flow label:\t%x\n", inner_ipv6->flow_label);
// break;
// default:
// puts("DEBUG:\ticmp_parse default");
// printf("ICMP type:\t%x\n", h->type);
// break;
// }

// return h;
// }

// ipv6_header *parse_ipv6(const uint8_t *first_byte)
// {
// ipv6_header *h = calloc(1, sizeof(ipv6_header));

// // Fill IPv6 struct
// h->version = (*first_byte >> 4);
// h->traffic_class = ((uint16_t)(*first_byte & 0x0F) << 8) | (*(first_byte + 1) >> 4);
// h->flow_label = ((uint32_t)(*(first_byte + 1) & 0x0F) << 16) | ((uint32_t) * (first_byte + 2) << 8) | *(first_byte + 3);
// h->payload_length = (((uint16_t) * (first_byte + 4)) << 8) | *(first_byte + 5);
// h->next_header = *(first_byte + 6);
// h->hop_limit = *(first_byte + 7);

// // Set source and destination
// printf("Source:\t\n");
// for (int i = 0, k = 0; i < 8; i++, k += 2)
// {
// h->source.address_short[i] = (((uint16_t) * (first_byte + 8 + k)) << 8) | *(first_byte + 8 + k + 1);
// printf("%x ", h->source.address_short[i]);
// }
// puts("");
// printf("Destination:\t\n");
// for (int i = 0, k = 0; i < 8; i++, k += 2)
// {
// h->destination.address_short[i] = (((uint16_t) * (first_byte + 24 + k)) << 8) | *(first_byte + 24 + k + 1);
// printf("%x ", h->destination.address_short[i]);
// }
// puts("");

// printf("Version:\t%d\n", h->version);
// printf("Traffic class:\t%x\n", h->traffic_class);
// printf("Flow label:\t%x\n", h->flow_label);
// printf("Payload length:\t%x\n", h->payload_length);
// printf("Next header:\t%x\n", h->next_header);
// printf("Hop limit:\t%x\n", h->hop_limit);
// return h;
// }

// void parse_packet(const packet_t *p)
// {
// packet_fprintf(stdout, p);
// puts("");
// // uint8_t eh_length;
// uint8_t *first_byte = packet_get_bytes(p);
// int hl = 40; // Initial value = IPv6 Header Length

// if ((*first_byte >> 4) == 6) // If IPv6
// {
// ipv6_header *ip6h = parse_ipv6(first_byte);
// // icmp6_header *icmp6h; // Necessary due to https://ittutoria.net/question/a-label-can-only-be-part-of-a-statement-and-a-declaration-is-not-a-statement/
// puts("Returned from parse_ipv6");
// printf("ip6h next_header:\t%x\n", ip6h->next_header);

// switch (ip6h->next_header)
// {
// case NH_ICMPv6:
// // icmp6_header *icmp6h = parse_icmp6(first_byte + hl);
// puts("Calling parse_icmp6");
// parse_icmp6(first_byte + hl);

// // If parse_icmp6 returns a valid payload: parse inner ipv6
// // and potentially, also inner tcp.
// // What we want is the inner IPv6 flow-label.
// break;
// case NH_HBH_OPTS: // Hop-by-Hop Options
// // uint8_t new_next_header = *(first_byte + hl);
// // eh_length = *(first_byte + hl + 1); // The extension header length is always in the second octet of the EH.
// // chl += (eh_length + 8);
// break;
// case NH_DST_OPTS: // Destination Options
// break;
// case NH_RH: // Routing Header
// break;
// case NH_FH: // Fragment Header
// break;
// case NH_AH: // Authentication Header
// break;
// case NH_ESPH: // Encapsulation Security Payload Header
// break;
// case NH_MH: // Mobility Header
// break;
// default:
// puts("DEBUG:\tipv6_parse_default");
// break;
// };
// }
// }

// address *createAddress(void)
// {
// address *a;
// if (a = calloc(1, sizeof(address)))
// {
// perror("Error");
// exit(1);
// }

// return a;
// }

// traceroute *createTraceroute(void)
// {
// traceroute *t;
// if (t = calloc(1, sizeof(traceroute)) == NULL)
// {
// perror("Error");
// exit(1);
// }

// return t;
// }

// hop *createHop(void)
// {
// hop *h;

// if (h = calloc(1, sizeof(hop)) == NULL)
// {
// perror("Error");
// exit(1);
// }

// return h;
// }

// /**
// * @brief Appends hop-object to the next available spot in the
// * hops-array. Returns -1 if the array is full.
// *
// * @param h
// * @param t
// * @return int
// */
// int appendHop(hop *h, traceroute *t)
// {
// int i;

// for (i = 0; i < 35; i++)
// {
// if (t->hops[i] == NULL)
// {
// printf("Available spot found at index:\t%d\n", i);
// t->hops[i] = h;
// return 0;
// }
// }

// return -1;
// }
// END ERLEND //

int first_run = true;
traceroute *t;
void sniffer_process_packets(sniffer_t *sniffer, uint8_t protocol_id)
{
    uint8_t recv_bytes[BUFLEN];
    ssize_t num_bytes = 0;
    packet_t *packet;

    switch (protocol_id)
    {
#ifdef USE_IPV4
    case IPPROTO_ICMP:
        num_bytes = recv(sniffer->icmpv4_sockfd, recv_bytes, BUFLEN, 0);
        break;
#endif
#ifdef USE_IPV6
    case IPPROTO_ICMPV6:
        num_bytes = recv_icmpv6(sniffer->icmpv6_sockfd, recv_bytes, BUFLEN, 0);
        break;
#endif
    }

    if (num_bytes >= 4)
    {
        // We have to make some modifications on the datagram
        // received because the raw format varies between
        // OSes:
        //  - Linux: the whole packet is in network endianess
        //  - NetBSD: the packet is in network endianess except
        //  IP total length and frag ofs(?) are in host-endian
        //  - FreeBSD: same as NetBSD?
        //  - Apple: same as NetBSD?
        //  Bug? On NetBSD, the IP length seems incorrect
#if defined __APPLE__ || __NetBSD__ || __FreeBSD__
        // uint16_t ip_len = read16(recv_bytes, 2);
        // writebe16(recv_bytes, 2, ip_len);
        printf("sniffer_process_packets: something unclear here\n");
#endif
        if (sniffer->recv_callback != NULL)
        {
            packet = packet_create_from_bytes(recv_bytes, num_bytes);
            const uint8_t *first_byte = packet_get_bytes(packet);

            // BEGIN ERLEND //
            // fprintf(stderr, "DEBUG: Calling parse_packet()\n");
            // parse_packet(packet);
            ipv6_header *outer_ipv6 = parse_ipv6(first_byte);
            ipv6_header *inner_ipv6 = get_inner_ipv6_header(packet);
            uint32_t returned_flowlabel = inner_ipv6->flow_label;
            // fprintf(stderr, "DEBUG: Returned from parse_packet()\n");
            // packet_dump(packet);

            hop *h;
            if (first_run)
            {
                /* Init asn-lookup */
                // asnLookupInit("/home/erlend/dev/routeviews-rv6-20220411-1200.pfx2as.txt");
                asnLookupInit("/root/routeviews/routeviews-rv6-pfx2as.txt");

                t = createTraceroute();
                set_traceroute(t);
                t->timestamp = create_timestamp();
                /* Set source ip */
                inet_pton(AF_INET6, get_host_ip(), &t->source_ip);
                /* Set source ASN */
                strcpy(t->source_asn, asnLookup(&t->source_ip));
                /* Set destination ip */
                t->destination_ip = inner_ipv6->destination;
                /* Set destination ASN */
                strcpy(t->destination_asn, asnLookup(&t->destination_ip));
                /* Set hop count */
                t->hop_count = 0;
                first_run = false;
            }

            h = createHop();
            h->hopnumber = t->hop_count + 1;
            h->hop_address = outer_ipv6->source;
            h->returned_flowlabel = returned_flowlabel;
            if (appendHop(h, t) == -1)
            {
                fprintf(stderr, "Failed to append hop: Hop array is full\n");
            }
            // END ERLEND //

            if (!(sniffer->recv_callback(packet, sniffer->recv_param)))
            {
                fprintf(stderr, "Error in sniffer's callback\n");
            }
        }
    }
}
