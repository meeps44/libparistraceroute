#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/file.h> // flock()
#include <unistd.h>   // getHostname()
#include <errno.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <arpa/inet.h>

#include "ext.h"
#include "patricia.h"
// #include "hashmap.h"
// #include "packet.h" // included in ext.h

#define DEBUG_ON 1

// uint16_t outgoing_tcp_port;
// char *timestamp;
// address *source_ip;
// uint32_t source_asn;
// address *destination_ip;
// uint32_t destination_asn;
// uint8_t path_id[SHA_DIGEST_LENGTH];
// uint8_t hop_count;
// hop *hops[HOP_MAX]; // maximum hop length is 35. any hops longer than that do not get included.

// static const char *TRACEROUTE_FORMAT_IN = "\n%[^,], %d, %d";
// static const char *TRACEROUTE_FORMAT_OUT = "%s, %d, %d\n";
// static const char *TRACEROUTE_FORMAT_IN = "\n%d,%[^,], %[], %d, %[], %d, %[^,], %d, %[]";
// static const char *TRACEROUTE_FORMAT_OUT = "%d, %s, %[], %d, %[], %d, %[^,], %d, %[]\n";

traceroute *t;

void set_traceroute(traceroute *tr)
{
    t = tr;
}

traceroute *get_traceroute(void)
{
    return t;
}

icmp6_header *parse_icmp6(const uint8_t *icmp_first_byte)
{
    puts("Entering parse_icmp6");
    icmp6_header *h = calloc(1, sizeof(icmp6_header));
    ipv6_header *inner_ipv6;
    h->type = *icmp_first_byte;
    h->code = *(icmp_first_byte + 1);
    h->checksum = ((uint16_t) * (icmp_first_byte + 2) << 8) | *(icmp_first_byte + 3);
    // Depending on the type there will be a value between bytes 5-9 as well, however
    // as it is not used in our project it will not be parsed at this time.

    switch (h->type)
    {
    case ICMP_TIME_EXCEEDED:
        inner_ipv6 = parse_ipv6(icmp_first_byte + 8);
        printf("Returned flow label:\t%x\n", inner_ipv6->flow_label);
        break;
    default:
        puts("DEBUG:\ticmp_parse default");
        printf("ICMP type:\t%x\n", h->type);
        break;
    }

    return h;
}

ipv6_header *parse_ipv6(const uint8_t *first_byte)
{
    ipv6_header *h = calloc(1, sizeof(ipv6_header));

    // Fill IPv6 struct
    h->version = (*first_byte >> 4);
    h->traffic_class = ((uint16_t)(*first_byte & 0x0F) << 8) | (*(first_byte + 1) >> 4);
    h->flow_label = ((uint32_t)(*(first_byte + 1) & 0x0F) << 16) | ((uint32_t) * (first_byte + 2) << 8) | *(first_byte + 3);
    h->payload_length = (((uint16_t) * (first_byte + 4)) << 8) | *(first_byte + 5);
    h->next_header = *(first_byte + 6);
    h->hop_limit = *(first_byte + 7);

    // Set source and destination
    printf("Source:\t\n");
    for (int i = 0, k = 0; i < 8; i++, k += 2)
    {
        h->source.__in6_u.__u6_addr16[i] = (((uint16_t) * (first_byte + 8 + k)) << 8) | *(first_byte + 8 + k + 1);
        printf("%x ", h->source.__in6_u.__u6_addr16[i]);
    }
    puts("");
    printf("Destination:\t\n");
    for (int i = 0, k = 0; i < 8; i++, k += 2)
    {
        h->destination.__in6_u.__u6_addr16[i] = (((uint16_t) * (first_byte + 24 + k)) << 8) | *(first_byte + 24 + k + 1);
        printf("%x ", h->destination.__in6_u.__u6_addr16[i]);
    }
    puts("");

    printf("Version:\t%d\n", h->version);
    printf("Traffic class:\t%x\n", h->traffic_class);
    printf("Flow label:\t%x\n", h->flow_label);
    printf("Payload length:\t%x\n", h->payload_length);
    printf("Next header:\t%x\n", h->next_header);
    printf("Hop limit:\t%x\n", h->hop_limit);
    return h;
}

void parse_packet(const packet_t *p)
{
    packet_fprintf(stdout, p);
    puts("");
    // uint8_t eh_length;
    uint8_t *first_byte = packet_get_bytes(p);
    int hl = 40; // Initial value = IPv6 Header Length

    if ((*first_byte >> 4) == 6) // If IPv6
    {
        ipv6_header *ip6h = parse_ipv6(first_byte);
        // icmp6_header *icmp6h; // Necessary due to https://ittutoria.net/question/a-label-can-only-be-part-of-a-statement-and-a-declaration-is-not-a-statement/
        puts("Returned from parse_ipv6");
        printf("ip6h next_header:\t%x\n", ip6h->next_header);

        switch (ip6h->next_header)
        {
        case NH_ICMPv6:
            // icmp6_header *icmp6h = parse_icmp6(first_byte + hl);
            puts("Calling parse_icmp6");
            parse_icmp6(first_byte + hl);

            // If parse_icmp6 returns a valid payload: parse inner ipv6
            // and potentially, also inner tcp.
            // What we want is the inner IPv6 flow-label.
            break;
        case NH_HBH_OPTS: // Hop-by-Hop Options
            // uint8_t new_next_header = *(first_byte + hl);
            // eh_length = *(first_byte + hl + 1); // The extension header length is always in the second octet of the EH.
            // chl += (eh_length + 8);
            break;
        case NH_DST_OPTS: // Destination Options
            break;
        case NH_RH: // Routing Header
            break;
        case NH_FH: // Fragment Header
            break;
        case NH_AH: // Authentication Header
            break;
        case NH_ESPH: // Encapsulation Security Payload Header
            break;
        case NH_MH: // Mobility Header
            break;
        default:
            puts("DEBUG:\tipv6_parse_default");
            break;
        };
    }
}

address *createAddress()
{
    address *a;
    if ((a = calloc(1, sizeof(address))) == NULL)
    {
        perror("Error");
        exit(1);
    }

    return a;
}

traceroute *createTraceroute()
{
    traceroute *t;
    if ((t = calloc(1, sizeof(traceroute))) == NULL)
    {
        perror("createTraceroute: calloc error");
        exit(1);
    }

    return t;
}

hop *createHop()
{
    hop *h;
    if ((h = calloc(1, sizeof(hop))) == NULL)
    {
        perror("Error");
        exit(1);
    }

    return h;
}

void sPrintHash(uint8_t *digest, char *s)
{
    const int MAX = 41;
    int i, length = 0;
    for (i = 0; i < SHA_DIGEST_LENGTH; i++)
    {
        length += snprintf(s + length, MAX - length, "%02x", digest[i]);
    }
}

void printHash(uint8_t *digest)
{
    int i;
    for (i = 0; i < SHA_DIGEST_LENGTH; i++)
    {
        printf("%02x", digest[i]);
    }
    puts("");
}

uint8_t *hashPath(address arr[], int arraySize)
{
    unsigned char *obuf = malloc(sizeof(uint8_t) * 20);
    SHA_CTX shactx;

    SHA1_Init(&shactx);
    for (int i = 0; i < arraySize; i++)
    {
        SHA1_Update(&shactx, &arr[i], sizeof(address));
    }
    SHA1_Final(obuf, &shactx); // digest now contains the 20-byte SHA-1 hash

    return obuf;
}

// TODO: Rewrite to use patricia-tree.
int asnLookup(address *ipv6_address)
{
    int ASN;
    FILE *fp;
    char input_buffer[1024], open_string_buffer[1024];
    int num;
    int i = 1;

    sprintf(open_string_buffer, "python3 main.py %d", atoi(addressToString(ipv6_address)));

#if DEBUG_ON == 1
    printf("DEBUG:\tvalue of open_string_buffer:\t%s\n", open_string_buffer);
#endif

    fp = popen(open_string_buffer, "r");
    if (fp == NULL)
    {
        perror("Failed to create file pointer\n");
        fprintf(stderr, "Errno:\t%s\n", strerror(errno));
        exit(1);
    }

    while (fgets(input_buffer, sizeof(input_buffer), fp) != NULL)
    {
        printf("Read line:\t%d\n", i++);
        num = atoi(input_buffer);
        printf("Num = %d\n", num);
    }
    pclose(fp);
    return ASN;
}

// address *parseIPv6(packet_t packet);

// void printParsedPacket(parsed_packet *p);

// int getFlowLabel(parsed_packet *p);

int printHop(hop *h)
{
    char hop_addr[100];

    printf("Returned flow label:\t%u\n", h->returned_flowlabel);
    printf("Hop number:\t%d\n", h->hopnumber);
    printf("Destination address:\t%s\n", inet_ntop(AF_INET6, h->hop_address, hop_addr, sizeof(struct in6_addr)));
    return 0;
}

int printTraceroute(traceroute *t)
{
    /*
    uint16_t outgoing_tcp_port;
    char *timestamp;
    address source_ip;
    uint32_t source_asn;
    address destination_ip;
    uint32_t destination_asn;
    uint8_t path_id[SHA_DIGEST_LENGTH];
    hop *hops[35]; // maximum hop length is 35. any hops longer than that do not get included.
    */
    char src_addr[100];
    char dst_addr[100];

    printf("Outgoing tcp port:\t%d\n", t->outgoing_tcp_port);
    printf("Timestamp:\t%d\n", t->outgoing_tcp_port);
    printf("Source address:\t%s\n", inet_ntop(AF_INET6, t->source_ip, src_addr, sizeof(struct in6_addr)));
    printf("Source ASN:\t%d\n", t->source_asn);
    printf("Destination address:\t%s\n", inet_ntop(AF_INET6, t->destination_ip, dst_addr, sizeof(struct in6_addr)));
    printf("Destination ASN:\t%d\n", t->destination_asn);
    printf("Path ID:\t%x\n", t->path_id);
    printf("Hop count:\t%x\n", t->hop_count);
    for (int i = 0; i < t->hop_count; i++)
    {
        printHop(t->hops[i]);
    }

    return 0;
}

/* TODO: Implement tracerouteToJSON*/
char *tracerouteToJSON(traceroute *t)
{
    return 0;
}

char *createFileName(struct tm *now) // (Might not be needed)
{
    // TODO: Implement malloc guards (check malloc return value for errors)
    char *fileName = malloc(sizeof(char) * 100);
    char *hostname = malloc(sizeof(char) * 30);
    char *timestamp = malloc(sizeof(char) * 50);
    gethostname(hostname, 30);

    // Output timestamp in format "YYYY-MM-DD-hh_mm_ss : "
    sprintf(timestamp, "-%04d-%02d-%02d-%02d_%02d_%02d",
            now->tm_year + 1900, now->tm_mon + 1, now->tm_mday,
            now->tm_hour, now->tm_min, now->tm_sec);

    strcat(hostname, timestamp);

    return fileName;
}

struct tm *getCurrentTime()
{
    time_t t = time(NULL);
    struct tm *now = gmtime(&t);

    return now;
}

int appendAddress(address *a, traceroute *t, uint8_t hopnumber, uint32_t returned_flowlabel)
{
    traceroute *tmp = t;
    int i;

    for (i = 0; i < 35; i++)
    {
        if (tmp->hops[i] == NULL)
        {
            printf("appendAddress:\tAvailable spot found at index:\t%d\n", i);
            hop *h = malloc(sizeof(hop));
            h->hop_address = a;
            h->hopnumber = hopnumber;
            h->returned_flowlabel = returned_flowlabel;
            tmp->hops[i] = h;
            return 0;
        }
    }

    return -1;
}

int appendHop(hop *h, traceroute *t)
{
    int i;

    for (i = 0; i < 35; i++)
    {
        if (t->hops[i] == NULL)
        {
            printf("appendHop:\tAvailable spot found at index:\t%d\n", i);
            t->hops[i] = h;
            return 0;
        }
    }

    return -1;
}

int serialize_csv(char *fileName, traceroute *t)
{
    FILE *file;
    if ((file = fopen(fileName, "a+")) == 0)
    {
        fprintf(stderr, "Error opening file:\t%s\nErrno:\t%s\n", fileName, strerror(errno));
        return -1;
    }

    /* Busy-waiting while file is locked */
    while (flock(fileno(file), LOCK_EX | LOCK_NB) == -1)
    {
        if (errno == EWOULDBLOCK)
        {
            fprintf(stderr, "Error: file is locked\n");
        }
        else
        {
            // error
            perror("Error ");
        }
    }

    // /* Write to file */
    // fwrite(t, sizeof(traceroute), 1, file);
    static const char *HOP_FORMAT_OUT = "%d, %d, %s ";
    static const char *TR_FORMAT_OUT = "%d, %s, %s, %d, %s, %d, %s, %d, ";

    char src_addr[100];
    char dst_addr[100];
    char hop_addr[100];

    /* Convert address to string before writing to file. */
    inet_ntop(AF_INET6, t->source_ip, src_addr, sizeof(struct in6_addr));
    inet_ntop(AF_INET6, t->destination_ip, dst_addr, sizeof(struct in6_addr));
    /* Write to file */
    fprintf(file, TR_FORMAT_OUT,
            t->outgoing_tcp_port,
            t->timestamp,
            src_addr,
            t->source_asn,
            dst_addr,
            t->destination_asn,
            t->path_id,
            t->hop_count);
    for (int i = 0; i < t->hop_count; i++)
    {
        /* Convert address to string before writing to file */
        inet_ntop(AF_INET6, t->hops[i]->hop_address, hop_addr, sizeof(struct in6_addr));
        /* Write to file */
        fprintf(file, HOP_FORMAT_OUT,
                t->hops[i]->returned_flowlabel,
                t->hops[i]->hopnumber,
                hop_addr);
    }
    fprintf(file, "\n");

    flock(fileno(fileName), LOCK_UN); // unlock file
    fclose(file);
    return 0;
}

int deserialize_csv(char *fileName, traceroute *t, long offset)
{
    FILE *file;
    if ((file = fopen(fileName, "r")) == 0)
    {
        perror("Error ");
        return 1;
    }

    fseek(file, offset, SEEK_SET);
    // fread(t, sizeof(traceroute), 1, file);
    static const char *TR_TEST_FORMAT_IN = "\n%d, %[^,], %d:%d, %d, %d:%d, %d, %[^,], %d";
    static const char *HOP_FORMAT_IN = " %d, %d, %d:%d";
    fscanf(file, TR_TEST_FORMAT_IN);

    // scanf returns EOF (which is -1) on end of file
    while (fscanf(file, TR_TEST_FORMAT_IN,
                  t->outgoing_tcp_port,
                  t->timestamp,
                  t->source_ip,
                  t->source_asn,
                  t->destination_ip,
                  t->destination_asn,
                  t->path_id,
                  t->hop_count) != EOF)
    {
    }

    fclose(file);
    return 0;
}

int serialize_bytes(char *fileName, traceroute *t)
{
    FILE *file;
    if ((file = fopen(fileName, "a+")) == 0)
    {
        fprintf(stderr, "Error opening file:\t%s\nErrno:\t%s\n", fileName, strerror(errno));
        return -1;
    }

    /* Busy-waiting while file is locked */
    while (flock(fileno(file), LOCK_EX | LOCK_NB) == -1)
    {
        if (errno == EWOULDBLOCK)
        {
            fprintf(stderr, "Error: file is locked\n");
        }
        else
        {
            // error
            perror("Error ");
        }
    }

    /* Write to file */
    fwrite(t, sizeof(traceroute), 1, file);

    flock(fileno(fileName), LOCK_UN); // unlock file
    fclose(file);
    return 0;
}

int deserialize_bytes(char *fileName, traceroute *t, long offset)
{
    FILE *file;
    if ((file = fopen(fileName, "r")) == 0)
    {
        perror("Error ");
        return 1;
    }

    fseek(file, offset, SEEK_SET);
    fread(t, sizeof(traceroute), 1, file);

    fclose(file);
    return 0;
}

// Patricia functions below

patricia_tree_t *tree;
const uint8_t v4_mapped_prefix[12] = {0, 0, 0, 0,
                                      0, 0, 0, 0,
                                      0, 0, 0xff, 0xff};

inline static prefix_t *make_prefix()
{
    prefix_t *rval = (prefix_t *)malloc(sizeof(prefix_t));
    rval->ref_count = 1;
    return rval;
}

inline static bool set_prefix(prefix_t *subnet, int family, inx_addr *addr, unsigned int width)
{
    if (!(family == AF_INET || family == AF_INET6))
        return false;

    if (family == AF_INET && width > 32)
        return false;

    if (family == AF_INET6 && width > 128)
        return false;

    if (family == AF_INET)
    {
        memcpy(&subnet->add.sin6, v4_mapped_prefix, sizeof(v4_mapped_prefix));
        memcpy(&subnet->add.sin6.s6_addr[12], addr, sizeof(struct in_addr));
    }

    else if (family == AF_INET6)
        memcpy(&subnet->add.sin6, addr, sizeof(subnet->add.sin6));

    subnet->family = AF_INET6;
    subnet->bitlen = (family == AF_INET ? width + 96 : width);

    return true;
}

inline static bool parse_cidr(const char *cidr, int *family, inx_addr *subnet, unsigned short *mask)
{
    char buffer[40];
    const char *addr_str = 0;
    const char *mask_str = 0;
    char *endptr;

    if (!cidr)
        return false;

    const char *slash = strchr(cidr, '/');

    if (slash)
    {
        int len = slash - cidr < 40 ? slash - cidr : 39;
        memcpy(buffer, cidr, len);
        buffer[len] = '\0';
        addr_str = buffer;
        mask_str = slash + 1;
    }
    else
    {
        addr_str = cidr;
        mask_str = 0;
    }

    *family = AF_INET;

    if (inet_pton(*family, addr_str, subnet) != 1)
    {
        *family = AF_INET6;

        if (inet_pton(*family, addr_str, subnet) != 1)
            return false;
    }

    if (mask_str)
    {
        errno = 0;
        *mask = strtol(mask_str, &endptr, 10);

        if (endptr == mask_str || errno != 0)
            return false;

        if (*family == AF_INET && *mask > 32)
            return false;
        else if (*mask > 128)
            return false;
    }
    else
    {
        if (*family == AF_INET)
            *mask = 32;
        else
            *mask = 128;
    }

    return true;
}

void patricia_init(bool arg_binary_lookup_mode)
{
    tree = New_Patricia(128);
}

int insert(int family, inx_addr subnet, unsigned short mask, int data)
{
    prefix_t *sn = make_prefix();

    if (!sn)
    {
        perror("Memory allocation failed\n");
        return 0;
    }

    bool res = set_prefix(sn, family, &subnet, mask);

    if (!res)
    {
        Deref_Prefix(sn);
        perror("invalid subnet/prefix\n");
        return 0;
    }

    patricia_node_t *node = patricia_lookup(tree, sn);
    fprintf(stderr, "Got new node, addr: %p\n", node);
    Deref_Prefix(sn);

    if (!node)
    {
        perror("patricia_lookup failed.\n");
        return 0;
    }

    // if (!data)
    // data = NULL;

    // node->data = (void *)&data;
    node->data = calloc(1, sizeof(int));
    memcpy(node->data, &data, sizeof(int));
    printf("Insert: Node addr:\t%p\n", node->data);
    printf("Insert: Node data:\t%d\n", *(int *)node->data);

    return 1;
}

int lookup_addr(int family, inx_addr addr)
{
    prefix_t *subnet = make_prefix();

    if (!subnet)
    {
        perror("invalid subnet/prefix");
        return 0;
    }

    int mask = family == AF_INET ? 32 : 128;
    bool res = set_prefix(subnet, family, &addr, mask);

    if (!res)
    {
        Deref_Prefix(subnet);
        perror("out of memory");
        return 0;
    }

    patricia_node_t *node = patricia_search_best(tree, subnet);
    Deref_Prefix(subnet);

    if (!node)
        return 0;

    printf("Node bitlen:\t%d\n", node->prefix->bitlen);
    printf("Node data:\t%d\n", *(int *)node->data);
    int data = *(int *)node->data;

    return data;
}