#include <openssl/sha.h>
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
#include "patricia_wrapper.h"
// #include "hashmap.h"
// #include "packet.h" // included in ext.h

#define DEBUG_ON

struct in6_addr *dest_addr;
struct in6_addr *create_destination(void)
{
    if ((dest_addr = calloc(1, sizeof(struct in6_addr))) == NULL)
    {
        perror("create_destination: calloc error");
        exit(1);
    }
    return dest_addr;
}

struct in6_addr *get_destination(void)
{
    return dest_addr;
}

// traceroute *const t;
traceroute *t = NULL;
traceroute *createTraceroute()
{
    if ((t = calloc(1, sizeof(traceroute))) == NULL)
    {
        perror("createTraceroute: calloc error");
        exit(1);
    }

    return t;
}

int init_traceroute(char *src_ip, char *dst_ip)
{
    if (t == NULL)
        return -1;

    /* Set timestamp */
    t->timestamp = create_timestamp();

    /* Set source ip */
    // fprintf(stderr, "get_host_ip: %s\n", get_host_ip());
    // fprintf(stderr, "get_host_ip: %s\n", get_host_ip());
    // inet_pton(AF_INET6, get_host_ip(), &t->source_ip);
    // fprintf(stderr, "ext.c (init_traceroute): Setting src IP\n");
    inet_pton(AF_INET6, src_ip, &t->source_ip);
    // inet_ntop(AF_INET6, &t->source_ip, foo, INET6_ADDRSTRLEN);
    // fprintf(stderr, "ext.c (init_traceroute): Set src IP done\n");

    /* Set source ASN */
    // fprintf(stderr, "ext.c (init_traceroute): Starting asnLookup\n");
    char *asnlookup_result = asnLookup(&t->source_ip);
    if (asnlookup_result != NULL)
    {
        memcpy(t->source_asn, asnlookup_result, strlen(asnlookup_result) + 1);
    }
    else
    {
        strcpy(t->source_asn, "NULL");
    }
    // fprintf(stderr, "ext.c (init_traceroute): Finished asnLookup\n");

    /* Set destination ip */
    // t->destination_ip = inner_ipv6->destination;
    // inet_ntop(AF_INET6, &t->destination_ip, foo, INET6_ADDRSTRLEN);
    // fprintf(stderr, "ext.c (init_traceroute): Setting dst IP\n");
    inet_pton(AF_INET6, dst_ip, &t->destination_ip);
    // inet_ntop(AF_INET6, &t->destination_ip, foo, INET6_ADDRSTRLEN);
    // fprintf(stderr, "ext.c (init_traceroute): Set dst IP done\n");

    /* Set destination ASN */
    // fprintf(stderr, "ext.c (init_traceroute): Starting asnLookup\n");
    asnlookup_result = asnLookup(&t->destination_ip);
    if (asnlookup_result != NULL)
    {
        memcpy(t->destination_asn, asnlookup_result, strlen(asnlookup_result) + 1);
    }
    else
    {
        strcpy(t->destination_asn, "NULL");
    }
    // fprintf(stderr, "ext.c (init_traceroute): Finished asnLookup\n");

    /* Set hop count */
    t->hop_count = 0;

    return 0;
}

traceroute *get_traceroute(void)
{
    return t;
}

// void set_traceroute(traceroute *tr)
//{
// t = tr;
//}

struct in6_addr *convert_address_string(char *ipv6_address_string)
{

    struct in6_addr *i6 = malloc(sizeof(struct in6_addr));
    char *dst = malloc(sizeof(char) * 48);
    dst = get_host_ip();
    int pton_result;

    if ((pton_result = inet_pton(AF_INET6, dst, i6)) != 1)
    {
        fprintf(stderr, "Error: convert_address_string failed to convert \
        string %s to struct in6_addr\n",
                ipv6_address_string);
        return NULL;
    }

    return i6;
}

char *get_host_ip()
{
    char *dst = malloc(sizeof(char) * 40);
    // struct in6_addr *i6 = malloc(sizeof(struct in6_addr));

    FILE *f;
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    char *filename = "/proc/net/if_inet6";
    int current_token = 0;

    /* IPv6 scope value in hexadecimal representation.
    A scope value of "00" indicates global scope.
    Ref.: https://tldp.org/HOWTO/Linux+IPv6-HOWTO/ch11s04.html */
    char scope_value[50];

    f = fopen(filename, "r");
    if (f == NULL)
    {
        fprintf(stderr, "get_host_ip: Failed to open %s", filename);
        exit(EXIT_FAILURE);
    }

    while ((read = getline(&line, &len, f)) != -1)
    {
        current_token++;

        /* Get the first token */
        char *token = strtok(line, " ");
        char *address = token;

        /* Walk through other tokens */
        while (token != NULL)
        {
            if (current_token == 4)
            {
                strcpy(scope_value, token);
            }
            token = strtok(NULL, " ");
            current_token++;
        }

        if (strcmp(scope_value, "00") == 0)
        {
            for (int i = 0, k = 0; k < strlen(address); i += 5, k += 4)
            {
                memcpy((dst + i), (address + k), 4);
                if (k + 4 < strlen(address))
                    *(dst + i + 4) = 58;
            }

            dst[40] = '\0';

            // int pton_result;
            // if ((pton_result = inet_pton(AF_INET6, dst, i6)) == 1)
            //{
            // printf("Converted successfully from string to struct in6_addr\n");
            //}
            fclose(f);
            // if (line)
            // free(line);
            // printf("get_host_ip: The global IPv6-address is:\t%s\n", dst);
            return dst;
        }
        current_token = 0;
    }

    perror("Global IPv6-address not found\n");
    fclose(f);
    // if (line)
    // free(line);

    return NULL;
}

ipv6_header *get_inner_ipv6_header(const uint8_t *first_byte)
{
    int IPV6_HEADER_LENGTH = 40;  // Initial value = IPv6 Header Length
    int ICMPV6_HEADER_LENGTH = 8; // Initial value = IPv6 Header Length
    icmp6_header *icmp6;
    ipv6_header *inner_ipv6;

    if ((*first_byte >> 4) == 6) // If IPv6
    {
        ipv6_header *ip6h = parse_ipv6(first_byte);
        // icmp6_header *icmp6h; // Necessary due to https://ittutoria.net/question/a-label-can-only-be-part-of-a-statement-and-a-declaration-is-not-a-statement/
#ifdef EXT_DEBUG
        puts("parse_packet: Returned from parse_ipv6");
        printf("parse_packet: ip6h next_header:\t%x\n", ip6h->next_header);
#endif

        switch (ip6h->next_header)
        {
        case NH_ICMPv6:
            icmp6 = parse_icmp6(first_byte + IPV6_HEADER_LENGTH);
            switch (icmp6->type)
            {
            case ICMP_TIME_EXCEEDED:
                inner_ipv6 = parse_ipv6(first_byte + IPV6_HEADER_LENGTH + ICMPV6_HEADER_LENGTH);
                return inner_ipv6;
            default:
                // fprintf(stderr, "get_inner_ipv6_header: Error: ICMP type is not ICMP_TIME_EXCEEDED.
                //  ICMP type is:\t%x\n", icmp6->type);
                return NULL;
            }
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
            // fprintf(stderr, "get_inner_ipv6_header:\tError: reached ipv6_parse_default
            // in switch statement. IPv6 Next Header is not ICMPv6");
            return NULL;
        };
    }
    // fprintf(stderr, "get_inner_ipv6_header: Error: packet is not an IPv6-packet.");
    return NULL;
}

icmp6_header *parse_icmp6(const uint8_t *icmp_first_byte)
{
    icmp6_header *h = calloc(1, sizeof(icmp6_header));
    h->type = *icmp_first_byte;
    h->code = *(icmp_first_byte + 1);
    h->checksum = ((uint16_t) * (icmp_first_byte + 2) << 8) | *(icmp_first_byte + 3);
    // Depending on the type there can be a value between bytes 5-9 as well,
    // though this value is not used in our project.
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

    /* Set source */
    memcpy(h->source.__in6_u.__u6_addr8, (first_byte + 8), 16);
    // char src_ip_tmp[17];
    // memcpy(src_ip_tmp, h->source.__in6_u.__u6_addr8, 16);
    // src_ip_tmp[16] = '\0';

    /* Set destination */
    memcpy(h->destination.__in6_u.__u6_addr8, (first_byte + 24), 16);
    // char dst_ip_tmp[17];
    // memcpy(dst_ip_tmp, h->destination.__in6_u.__u6_addr8, 16);
    // dst_ip_tmp[16] = '\0';
#ifdef EXT_DEBUG
    char presentation_buffer[INET6_ADDRSTRLEN];
    printf("parse_ipv6: Destination IP:\n%s\n", inet_ntop(AF_INET6, &h->destination, presentation_buffer, 48));
    printf("Version:\t%d\n", h->version);
    printf("Traffic class:\t%x\n", h->traffic_class);
    printf("Flow label:\t%x\n", h->flow_label);
    printf("Payload length:\t%x\n", h->payload_length);
    printf("Next header:\t%x\n", h->next_header);
    printf("Hop limit:\t%x\n", h->hop_limit);
#endif
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
        switch (ip6h->next_header)
        {
        case NH_ICMPv6:
            parse_icmp6(first_byte + hl);
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
            fprintf(stderr, "parse_packet:\treached ipv6_parse_default in switch statement");
            break;
        };
    }
}

struct in6_addr *createAddress()
{
    struct in6_addr *a;
    if ((a = calloc(1, sizeof(struct in6_addr))) == NULL)
    {
        perror("Error");
        exit(1);
    }

    return a;
}

hop *createHop()
{
    hop *h;
    if ((h = calloc(1, sizeof(hop))) == NULL)
    {
        perror("createHop: calloc error");
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

uint8_t *hashPath(struct in6_addr arr[], int arraySize)
{
    unsigned char *obuf = malloc(sizeof(uint8_t) * 20);
    SHA_CTX shactx;

    SHA1_Init(&shactx);
    for (int i = 0; i < arraySize; i++)
    {
        SHA1_Update(&shactx, &arr[i], sizeof(struct in6_addr));
    }
    SHA1_Final(obuf, &shactx); // digest now contains the 20-byte SHA-1 hash

    return obuf;
}

int asnLookupInit(char *filename)
{
    patricia_init(false);
    FILE *f;
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    char *token = NULL;
    char *address;
    int mask = 0;
    char *asn;
    struct in6_addr *my_addr = calloc(1, sizeof(struct in6_addr));

    f = fopen(filename, "r");
    if (f == NULL)
    {
        perror("asnLookupInit: Error opening file");
        exit(EXIT_FAILURE);
    }

    while ((read = getline(&line, &len, f)) != -1)
    {
        // printf("Retrieved line of length %zu:\n", read);
        // printf("%s", line);
        token = strtok(line, " ");
        int nmb = 1;
        while (token)
        {
            switch (nmb)
            {
            case 1:
                address = token;
                // printf("address: %s\n", address);
                inet_pton(AF_INET6, address, my_addr);
                break;
            case 2:
                mask = atoi(token);
                // printf("mask: %d\n", mask);
                break;
            case 3:
                nmb = 1;
                asn = malloc(sizeof(char) * 200);
                strcpy(asn, token);

                /* Strip trailing newline */
                asn[strcspn(asn, "\n")] = 0;

                //  printf("asn: %s\n", asn);
                //  Insert into patricia-tree
                //  insert(AF_INET6, (struct in6_addr) * my_addr, mask, asn);
                insert(AF_INET6, *my_addr, mask, asn);
                break;
            default:
                puts("Error: default");
                break;
            }
            nmb++;
            token = strtok(NULL, " ");
        }
    }

    fclose(f);
    // if (line)
    // free(line);
    return 0;
}

char *asnLookup(struct in6_addr *ipv6_address)
{
    // char *ASN;
    //  struct in6_addr i6;
    //   unsigned char *example_address2 = "1900:2100::2a2d";
    //   inet_pton(AF_INET6, ipv6_address, &i6);
    // puts("ext.c: Entering asnlookup");
    char *lookup_result = lookup_addr(AF_INET6, *ipv6_address);
    // puts("ext.c: Finished asnlookup");
    // printf("Lookup result:\t%s\n", lookup_result);
    return lookup_result;
}

const char *printAddress(struct in6_addr *i6)
{
    char *addr_buffer = malloc(sizeof(char) * INET6_ADDRSTRLEN);
    return inet_ntop(AF_INET6, i6, addr_buffer, INET6_ADDRSTRLEN);
}

int printHop(hop *h)
{
    char hop_addr[INET6_ADDRSTRLEN];

    if (h == NULL)
        return -1;

    fprintf(stderr, "Returned flow label:\t%u\n", h->returned_flowlabel);
    fprintf(stderr, "Hop number:\t%d\n", h->hopnumber);
    fprintf(stderr, "Hop address:\t%s\n", inet_ntop(AF_INET6, &h->hop_address, hop_addr, INET6_ADDRSTRLEN));
    fprintf(stderr, "Hop ASN:\t%d\n", h->hop_asn);
    return 0;
}

int printTraceroute(traceroute *t)
{
    char src_addr[100];
    char dst_addr[100];

    if (t == NULL)
        return -1;

    printf("Outgoing tcp port:\t%d\n", t->outgoing_tcp_port);
    printf("Timestamp:\t%d\n", t->outgoing_tcp_port);
    printf("Source address:\t%s\n", inet_ntop(AF_INET6, &t->source_ip, src_addr, sizeof(struct in6_addr)));
    printf("Source ASN:\t%s\n", t->source_asn);
    printf("Destination address:\t%s\n", inet_ntop(AF_INET6, &t->destination_ip, dst_addr, sizeof(struct in6_addr)));
    printf("Destination ASN:\t%s\n", t->destination_asn);
    printf("Path ID:\t%s\n", t->path_id);
    printf("Hop count:\t%x\n", t->hop_count);
    for (int i = 0; i < t->hop_count; i++)
    {
        printHop(&t->hops[i]);
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
    sprintf(timestamp, "-%04d-%02d-%02dT%02d:%02d:%02d",
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

char *create_timestamp()
{
    char *timestamp = calloc(1, sizeof(char) * 50);
    struct tm *now = getCurrentTime();
    // Output timestamp in format "YYYY-MM-DD-hh_mm_ss : "
    sprintf(timestamp, "%04d-%02d-%02dT%02d:%02d:%02d",
            now->tm_year + 1900, now->tm_mon + 1, now->tm_mday,
            now->tm_hour, now->tm_min, now->tm_sec);

    return timestamp;
}

int appendHop(hop *h, traceroute *t)
{
    if (t->hop_count >= 35)
    {
        return -1;
    }
    t->hops[t->hop_count] = *h;
    t->hop_count++;
    return 0;
}

int serialize_csv(char *fileName, traceroute *t)
{
    FILE *file;
    // printf("serialize_csv: opening file %s for writing\n", fileName);
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
    static const char *HOP_FORMAT_OUT = "%d, %d, %s, %s, ";
    static const char *HOP_FORMAT_LAST = "%d, %d, %s, %s";
    static const char *TR_FORMAT_OUT = "%d, %d, %s, %s, %s, %s, %s, %s, %d, ";

    char src_addr[INET6_ADDRSTRLEN + 1];
    char dst_addr[INET6_ADDRSTRLEN + 1];
    char hop_addr[INET6_ADDRSTRLEN + 1];

    /* Convert src address to string before writing to file. */
    inet_ntop(AF_INET6, &t->source_ip, src_addr, sizeof(src_addr));
    memcpy(&src_addr[46], "\0", 1);
    // printf("serialize_csv: converted source ip: %s", src_addr);

    /* Convert destination address to string before writing to file. */
    inet_ntop(AF_INET6, &t->destination_ip, dst_addr, sizeof(dst_addr));
    memcpy(&dst_addr[46], "\0", 1);
    // printf("serialize_csv: converted destination ip: %s", dst_addr);
    /* Write to file */
    // puts("serialize_csv: Writing traceroute to file");
    fprintf(file, TR_FORMAT_OUT,
            t->outgoing_flow_label,
            t->outgoing_tcp_port,
            t->timestamp,
            src_addr,
            t->source_asn,
            dst_addr,
            t->destination_asn,
            t->path_id,
            t->hop_count);
    // puts("serialize_csv: wrote traceroute:");
    // printf(TR_FORMAT_OUT,
    // t->outgoing_flow_label,
    // t->outgoing_tcp_port,
    // t->timestamp,
    // src_addr,
    // t->source_asn,
    // dst_addr,
    // t->destination_asn,
    // t->path_id,
    // t->hop_count);
    // puts("serialize_csv: Done writing traceroute to file. Writing hops...");
    for (int i = 0; i < t->hop_count; i++)
    {
        /* Convert address to string before writing to file */
        inet_ntop(AF_INET6, &t->hops[i].hop_address, hop_addr, sizeof(hop_addr));
        memcpy(&hop_addr[46], "\0", 1);
        if (i < t->hop_count - 1)
        {
            /* Write to file */
            fprintf(file, HOP_FORMAT_OUT,
                    t->hops[i].hopnumber,
                    t->hops[i].returned_flowlabel,
                    hop_addr,
                    t->hops[i].hop_asn);
            /* Write to stdout */
            // printf(HOP_FORMAT_OUT,
            // t->hops[i].hopnumber,
            // t->hops[i].returned_flowlabel,
            // hop_addr,
            // t->hops[i].hop_asn);
        }
        else
        {
            /* Write to file */
            fprintf(file, HOP_FORMAT_LAST,
                    t->hops[i].hopnumber,
                    t->hops[i].returned_flowlabel,
                    hop_addr,
                    t->hops[i].hop_asn);
            /* Write to stdout */
            // printf(HOP_FORMAT_LAST,
            // t->hops[i].hopnumber,
            // t->hops[i].returned_flowlabel,
            // hop_addr,
            // t->hops[i].hop_asn);
        }
    }
    // puts("serialize_csv: Done writing hops to file");
    fprintf(file, "\n");
    // puts("serialize_csv: Finished writing traceroute to file");

    flock(fileno(file), LOCK_UN); // unlock file
    fclose(file);
    return 0;
}

// int deserialize_csv(char *fileName, traceroute *t, long offset)
//{
// FILE *file;
// if ((file = fopen(fileName, "r")) == 0)
//{
// perror("Error ");
// return 1;
//}

// fseek(file, offset, SEEK_SET);
//// fread(t, sizeof(traceroute), 1, file);
// static const char *TR_TEST_FORMAT_IN = "\n%d, %[^,], %d:%d, %d, %d:%d, %d, %[^,], %d";
// static const char *HOP_FORMAT_IN = " %d, %d, %d:%d";
// fscanf(file, TR_TEST_FORMAT_IN);

//// scanf returns EOF (which is -1) on end of file
// while (fscanf(file, TR_TEST_FORMAT_IN,
// t->outgoing_tcp_port,
// t->timestamp,
// t->source_ip,
// t->source_asn,
// t->destination_ip,
// t->destination_asn,
// t->path_id,
// t->hop_count) != EOF)
//{
//}

// fclose(file);
// return 0;
//}

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

    flock(fileno(file), LOCK_UN); // unlock file
    fclose(file);
    return 0;
}

// int deserialize_bytes(char *fileName, traceroute *t, long offset)
//{
// FILE *file;
// if ((file = fopen(fileName, "r")) == 0)
//{
// perror("Error ");
// return 1;
//}

// fseek(file, offset, SEEK_SET);
// fread(t, sizeof(traceroute), 1, file);

// fclose(file);
// return 0;
//}
