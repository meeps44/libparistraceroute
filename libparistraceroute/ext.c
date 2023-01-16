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

// #define EXT_DEBUG

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

int init_traceroute(long start_time, char *src_ip, char *dst_ip)
{
    if (t == NULL)
        return -1;

    /* Set timestamp */
    // t->timestamp = create_timestamp();
    t->start_time = start_time;

    /* Set source ip */
    inet_pton(AF_INET6, src_ip, &t->source_ip);

    /* Set source ASN */
    char *asnlookup_result = asnLookup(&t->source_ip);
    if (asnlookup_result != NULL)
    {
        memcpy(t->source_asn, asnlookup_result, strlen(asnlookup_result) + 1);
    }
    else
    {
        strcpy(t->source_asn, "NULL");
    }
    /* Set destination ip */
    inet_pton(AF_INET6, dst_ip, &t->destination_ip);
    /* Set destination ASN */
    asnlookup_result = asnLookup(&t->destination_ip);
    if (asnlookup_result != NULL)
    {
        memcpy(t->destination_asn, asnlookup_result, strlen(asnlookup_result) + 1);
    }
    else
    {
        strcpy(t->destination_asn, "NULL");
    }

    /* Set hop count */
    t->hop_count = 0;

    return 0;
}

traceroute *get_traceroute(void)
{
    return t;
}

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
            fclose(f);
            return dst;
        }
        current_token = 0;
    }

    perror("Global IPv6-address not found\n");
    fclose(f);
    return NULL;
}

ipv6_header *get_inner_ipv6_header(uint8_t *first_byte)
{
    const int IPV6_HEADER_LENGTH = 40;
    const int ICMPV6_HEADER_LENGTH = 8;
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

        uint8_t nh = ip6h->next_header;
        uint8_t *nh_first_byte = first_byte + IPV6_HEADER_LENGTH;
        uint8_t h_len = 0;

        bool quit = false;
        while (!quit)
        {
            switch (nh)
            {
            case NH_ICMPv6:
                icmp6 = parse_icmp6(first_byte + IPV6_HEADER_LENGTH);
                switch (icmp6->type)
                {
                case ICMP_TIME_EXCEEDED:
                    inner_ipv6 = parse_ipv6(first_byte + IPV6_HEADER_LENGTH + ICMPV6_HEADER_LENGTH);
                    return inner_ipv6;
                case ICMP_DESTINATION_UNREACHABLE:
                    if (icmp6->code == 4)
                    {
                        inner_ipv6 = parse_ipv6(first_byte + IPV6_HEADER_LENGTH + ICMPV6_HEADER_LENGTH);
                        return inner_ipv6;
                    }
                    else
                    {
                        return NULL;
                    }
                default:
#ifdef EXT_DEBUG
                    fprintf(stderr, "get_inner_ipv6_header: Error: ICMP type is not ICMP_TIME_EXCEEDED. \
                  ICMP type is:\t%x\n",
                            icmp6->type);
#endif
                    return NULL;
                }
            case NH_HBH_OPTS: // Hop-by-Hop Options
                // Length of the Hop-by-Hop Options header in 8-octet units, not including the first 8 octets.
                nh = *nh_first_byte;
                h_len = 8 + *(nh_first_byte + 1); // The extension header length is always in the second octet of the EH.
                nh_first_byte += h_len;
                break;
            case NH_DST_OPTS: // Destination Options
                nh = *nh_first_byte;
                // 8-bit unsigned integer.  Length of the Destination Options header in 8-octet units, not including the first 8 octets.
                h_len = 8 + *(nh_first_byte + 1); // The extension header length is always in the second octet of the EH.
                nh_first_byte += h_len;
                break;
            case NH_RH: // Routing Header
                //  8-bit unsigned integer.  Length of the Routing header in 8-octet units, not including the first 8 octets.
                nh = *nh_first_byte;
                h_len = 8 + *(nh_first_byte + 1); // The extension header length is always in the second octet of the EH.
                nh_first_byte += h_len;
                break;
            case NH_FH: // Fragment Header
                // Should never occur, ICMPv6 limits its message body size, per rfc4443:
                // "The ICMP payload is as much of invoking packet as possible without
                // the ICMPv6 packet exceeding the minimum IPv6 MTU."
                return NULL;
            case NH_AH: // Authentication Header
                nh = *nh_first_byte;
                // Payload Length:
                // This 8-bit field specifies the length of AH in 32-bit words (4-byte units), minus "2".  Thus, for example, if an integrity algorithm
                // yields a 96-bit authentication value, this length field will be "4" (3 32-bit word fixed fields plus 3 32-bit words for the ICV, minus 2).
                // For IPv6, the total length of the header must be a multiple of 8-octet units. Padding is added if necessary.
                h_len = 8 + (*(nh_first_byte + 1) * 4); // multiply by 4 to convert from 32-bit words to 8-bit bytes.
                nh_first_byte += h_len;
                break;
            case NH_ESPH: // Encapsulation Security Payload Header
                return NULL;
            default:
#ifdef EXT_DEBUG
                fprintf(stderr, "get_inner_ipv6_header:\tError: reached ipv6_parse_default \
                in switch statement. IPv6 Next Header is not ICMPv6");
#endif
                return NULL;
            };
        }
    }
#ifdef EXT_DEBUG
    fprintf(stderr, "get_inner_ipv6_header: Error: packet is not an IPv6-packet.");
#endif
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

    /* Fill IPv6 struct */
    h->version = (*first_byte >> 4);
    h->traffic_class = ((uint16_t)(*first_byte & 0x0F) << 8) | (*(first_byte + 1) >> 4);
    h->flow_label = ((uint32_t)(*(first_byte + 1) & 0x0F) << 16) | ((uint32_t) * (first_byte + 2) << 8) | *(first_byte + 3);
    h->payload_length = (((uint16_t) * (first_byte + 4)) << 8) | *(first_byte + 5);
    h->next_header = *(first_byte + 6);
    h->hop_limit = *(first_byte + 7);

    /* Set source */
    memcpy(h->source.__in6_u.__u6_addr8, (first_byte + 8), 16);

    /* Set destination */
    memcpy(h->destination.__in6_u.__u6_addr8, (first_byte + 24), 16);
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

uint8_t *hashPathTuple(addr_tuple arr[], int arraySize)
{
    unsigned char *obuf = malloc(sizeof(uint8_t) * 20);
    SHA_CTX shactx;

    SHA1_Init(&shactx);
    for (int i = 0; i < arraySize; i++)
    {
        SHA1_Update(&shactx, &arr[i].hop_address, sizeof(struct in6_addr));
        SHA1_Update(&shactx, &arr[i].hopnumber, sizeof(uint8_t));
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
        token = strtok(line, " ");
        int nmb = 1;
        while (token)
        {
            switch (nmb)
            {
            case 1:
                address = token;
                inet_pton(AF_INET6, address, my_addr);
                break;
            case 2:
                mask = atoi(token);
                break;
            case 3:
                nmb = 1;
                asn = malloc(sizeof(char) * 200);
                strcpy(asn, token);

                /* Strip trailing newline */
                asn[strcspn(asn, "\n")] = 0;
                /*  Insert into patricia-tree */
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
    if (line)
    {
        free(line);
    }
    return 0;
}

char *asnLookup(struct in6_addr *ipv6_address)
{
    char *lookup_result = lookup_addr(AF_INET6, *ipv6_address);
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

    printf("Returned flow label:\t%u\n", h->returned_flowlabel);
    printf("Hop number:\t%d\n", h->hopnumber);
    printf("Hop address:\t%s\n", inet_ntop(AF_INET6, &h->hop_address, hop_addr, INET6_ADDRSTRLEN));
    printf("Hop ASN:\t%s\n", h->hop_asn);
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

char *createFileName(struct tm *now) // (Might not be needed)
{
    char *fileName = malloc(sizeof(char) * 100);
    if (fileName == NULL)
    {
        perror("createFileName memory allocation error");
        exit(1);
    }
    char *hostname = malloc(sizeof(char) * 30);
    if (hostname == NULL)
    {
        perror("createFileName memory allocation error");
        exit(1);
    }
    char *timestamp = malloc(sizeof(char) * 50);
    if (timestamp == NULL)
    {
        perror("createFileName memory allocation error");
        exit(1);
    }
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

    /* Output format definitions */
    static const char *STRING_FORMAT_OUT = "%s ";
    static const char *NUMBER_FORMAT_OUT = "%d ";
    static const char *STRING_FORMAT_LAST = "%s, ";
    static const char *STRING_FORMAT_LAST_COLUMN = "%s";
    static const char *NUMBER_FORMAT_LAST = "%d, ";
    static const char *TR_FORMAT_OUT = "%d, %d, %s, %s, %s, %s, %s, %s, %d, ";

    char src_addr[INET6_ADDRSTRLEN + 1];
    char dst_addr[INET6_ADDRSTRLEN + 1];
    char hop_addr[INET6_ADDRSTRLEN + 1];

    /* Convert src address to string before writing to file. */
    inet_ntop(AF_INET6, &t->source_ip, src_addr, sizeof(src_addr));
    memcpy(&src_addr[46], "\0", 1);

    /* Convert destination address to string before writing to file. */
    inet_ntop(AF_INET6, &t->destination_ip, dst_addr, sizeof(dst_addr));
    memcpy(&dst_addr[46], "\0", 1);

    /* Write to file */
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

    /* Write hop addresses */
    for (int i = 0; i < t->hop_count; i++)
    {
        /* Convert address to string before writing to file */
        inet_ntop(AF_INET6, &t->hops[i].hop_address, hop_addr, sizeof(hop_addr));
        memcpy(&hop_addr[46], "\0", 1);
        if (i < t->hop_count - 1)
        {
            /* Write to file */
            fprintf(file, STRING_FORMAT_OUT, hop_addr);
        }
        else
        {
            /* Write to file */
            fprintf(file, STRING_FORMAT_LAST, hop_addr);
        }
    }

    /* Write hop numbers */
    for (int i = 0; i < t->hop_count; i++)
    {
        if (i < t->hop_count - 1)
        {
            /* Write to file */
            fprintf(file, NUMBER_FORMAT_OUT, t->hops[i].hopnumber);
        }
        else
        {
            /* Write to file */
            fprintf(file, NUMBER_FORMAT_LAST, t->hops[i].hopnumber);
        }
    }

    /* Write returned flow labels*/
    for (int i = 0; i < t->hop_count; i++)
    {
        if (i < t->hop_count - 1)
        {
            /* Write to file */
            fprintf(file, NUMBER_FORMAT_OUT, t->hops[i].returned_flowlabel);
        }
        else
        {
            /* Write to file */
            fprintf(file, NUMBER_FORMAT_LAST, t->hops[i].returned_flowlabel);
        }
    }

    /* Write hop ASN */
    for (int i = 0; i < t->hop_count; i++)
    {
        if (i < t->hop_count - 1)
        {
            /* Write to file */
            fprintf(file, STRING_FORMAT_OUT, t->hops[i].hop_asn);
        }
        else
        {
            /* Write to file */
            fprintf(file, STRING_FORMAT_LAST_COLUMN, t->hops[i].hop_asn);
        }
    }

    fprintf(file, "\n");
    flock(fileno(file), LOCK_UN); // unlock file
    fclose(file);
    return 0;
}

char *inet_addr_to_string(struct in6_addr *addr)
{
    const size_t BUFFERSIZE = INET6_ADDRSTRLEN + 3;
    char *addr_str = malloc(sizeof(char) * BUFFERSIZE);

    /* Insert opening string quotation mark */
    addr_str[0] = '\"';

    /* Convert address to string */
    inet_ntop(AF_INET6, addr, (addr_str + 1), INET6_ADDRSTRLEN);
    fprintf(stderr, "Debug: inet_addr_to_string addr_str: %s\n", addr_str);
    // inet_ntop(AF_INET6, addr, (addr_str + 1), BUFFERSIZE);

    /* Insert closing string quotation mark */
    addr_str[strlen(addr_str)] = '\"';

    /* Remove final whitespace */
    addr_str[strlen(addr_str) + 1] = '\0';

    return addr_str;
}

sqlite3 *db_open_and_init(char *filename)
{
    sqlite3 *db;
    int result_code;
    result_code = sqlite3_open(filename, &db);
    if (result_code)
    {
        fprintf(stderr, "Can't open database %s\n", sqlite3_errmsg(db));
        exit(EXIT_FAILURE);
    }
    else
    {
        fprintf(stderr, "Database opened successfully\n");
    }

    /*
        From the documentation:
        "This function registers an internal busy handler that keeps attempting to acquire a busy lock until the total specified time has passed.
        Because this function registers an internal busy handler, any current busy handler is removed.
        The timeout value can be explicitly removed by setting a timeout value of zero."
    */
    /* Set busy timeout */
    sqlite3_busy_timeout(db, 120000); // 120 seconds

    /* Create traceoute_data table */
    db_create_table(db);

    return db;
}

int db_create_table(sqlite3 *db)
{
    char *error_message;
    int result_code;
    char *sql;

    /* Create table */
    sql = "CREATE TABLE IF NOT EXISTS TRACEROUTE_DATA("
          "START_TIME                INT      NOT NULL,"
          "SOURCE_TCP_PORT           INT      NOT NULL,"
          "SOURCE_FLOW_LABEL         INT      NOT NULL,"
          "SOURCE_IP                 TEXT     NOT NULL,"
          "SOURCE_ASN                TEXT     NOT NULL,"
          "DESTINATION_IP            TEXT     NOT NULL,"
          "DESTINATION_ASN           TEXT     NOT NULL,"
          "PATH_HASH                 TEXT     NOT NULL,"
          "HOP_COUNT                 INT      NOT NULL,"
          "HOP_IP_ADDRESSES          TEXT     NOT NULL,"
          "HOP_NUMBERS               TEXT     NOT NULL,"
          "HOP_RETURNED_FLOW_LABELS  TEXT     NOT NULL,"
          "HOP_ASNS                  TEXT     NOT NULL);";
    fprintf(stderr, "Creating DB table\n");
    if ((result_code = sqlite3_exec(db, sql, &db_callback, NULL, &error_message)) != SQLITE_OK)
    {
        fprintf(stderr, "Debug: Create DB table error: %s\n", error_message);
        return result_code;
    }
    else
    {
        fprintf(stderr, "Debug: DB table created successfully\n");
    }

    return result_code;
}

int db_callback(void *unused, int column_count, char **data, char **columns)
{
    int i;
    for (i = 0; i < column_count; i++)
    {
        // For each column in the row, print its data
        printf("%s = %s\n", columns[i], data[i] ? data[i] : "NULL");
    }
    printf("\n");
    return 0;
}

void db_close(sqlite3 *db)
{
    /*
    int result_code;
    result_code = sqlite3_close(db);

    if (result_code != SQLITE_OK)
    {
        fprintf(stderr, "Debug: DB connection failed to close successfully\n");
    }
    else
    {
        fprintf(stderr, "Debug: DB connection closed successfully\n");
    }

    fprintf(stderr, "Debug: db_close all done!\nresult_code: %d\n", result_code);
    return result_code;
    */
    sqlite3_close(db);
}

int db_insert(sqlite3 *db, traceroute *t, char *src_ip_in, char *dst_ip_in)
{
    char *error_message;
    int result_code;
    char sql[4096];
    size_t s_len;

    char src_ip[INET6_ADDRSTRLEN + 2];
    char dst_ip[INET6_ADDRSTRLEN + 2];
    src_ip[0] = '\"';
    dst_ip[0] = '\"';
    strcpy((src_ip + 1), src_ip_in);
    strcpy((dst_ip + 1), dst_ip_in);
    s_len = strlen(src_ip);
    src_ip[s_len] = '\"';
    src_ip[s_len + 1] = '\0';
    s_len = strlen(dst_ip);
    dst_ip[s_len] = '\"';
    dst_ip[s_len + 1] = '\0';
    /*
    // char *src_ip = inet_addr_to_string(&t->source_ip);
    // char *dst_ip = inet_addr_to_string(&t->destination_ip);
    src_ip[0] = '\"';
    dst_ip[0] = '\"';
    inet_ntop(AF_INET6, &t->source_ip, (src_ip + 1), INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &t->destination_ip, (dst_ip + 1), INET6_ADDRSTRLEN);
    src_ip[strlen(src_ip)] = '\"';
    // src_ip[strlen(src_ip) + 1] = '\0';
    dst_ip[strlen(dst_ip)] = '\"';
    // dst_ip[strlen(dst_ip) + 1] = '\0';
    */
    char *hiats = hop_ip_addresses_to_string(t);
    char *hnts = hop_numbers_to_string(t);
    char *hrfts = hop_returned_flowlabels_to_string(t);
    char *hats = hop_asns_to_string(t);
    char *hash = path_id_to_string(t->path_id);

    fprintf(stderr, "Debug: db_insert strings:\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n",
            src_ip, dst_ip, hiats, hnts, hrfts, hats, hash);
    fprintf(stderr,
            "INSERT INTO TRACEROUTE_DATA (START_TIME,\
    SOURCE_TCP_PORT,\
    SOURCE_FLOW_LABEL,\
    SOURCE_IP,\
    SOURCE_ASN,\
    DESTINATION_IP,\
    DESTINATION_ASN,\
    PATH_HASH,\
    HOP_COUNT,\
    HOP_IP_ADDRESSES,\
    HOP_NUMBERS,\
    HOP_RETURNED_FLOW_LABELS,\
    HOP_ASNS) \
    VALUES (%ld,%d,%d,%s,%s,%s,%s,%s,%d,%s,%s,%s,%s);",
            t->start_time,
            t->outgoing_tcp_port,
            t->outgoing_flow_label,
            src_ip,
            t->source_asn,
            dst_ip,
            t->destination_asn,
            hash,
            t->hop_count,
            hiats,
            hnts,
            hrfts,
            hats);

    sprintf(sql,
            "INSERT INTO TRACEROUTE_DATA (START_TIME,\
    SOURCE_TCP_PORT,\
    SOURCE_FLOW_LABEL,\
    SOURCE_IP,\
    SOURCE_ASN,\
    DESTINATION_IP,\
    DESTINATION_ASN,\
    PATH_HASH,\
    HOP_COUNT,\
    HOP_IP_ADDRESSES,\
    HOP_NUMBERS,\
    HOP_RETURNED_FLOW_LABELS,\
    HOP_ASNS) \
    VALUES (%ld,%d,%d,%s,%s,%s,%s,%s,%d,%s,%s,%s,%s);",
            t->start_time,
            t->outgoing_tcp_port,
            t->outgoing_flow_label,
            src_ip,
            t->source_asn,
            dst_ip,
            t->destination_asn,
            hash,
            t->hop_count,
            hiats,
            hnts,
            hrfts,
            hats);
    /* Insert into table */
    if ((result_code = sqlite3_exec(db, sql, &db_callback, NULL, &error_message)) != SQLITE_OK)
    {
        // free(src_ip);
        // free(dst_ip);
        free(hiats);
        free(hnts);
        free(hrfts);
        free(hats);
        free(hash);
        fprintf(stderr, "Debug: DB insert failed: %s\n", error_message);
        return result_code;
    }
    // free(src_ip);
    // free(dst_ip);
    free(hiats);
    free(hnts);
    free(hrfts);
    free(hats);
    free(hash);

    fprintf(stderr, "Debug: DB insert completed successfully\n");
    return result_code;
}

char *path_id_to_string(char *path_id)
{
    const int BUFFERSIZE = 23;
    char *s_buffer = malloc(sizeof(char) * BUFFERSIZE);
    s_buffer[0] = '\"';
    memcpy((s_buffer + 1), path_id, 20);
    s_buffer[BUFFERSIZE - 2] = '\"';
    s_buffer[BUFFERSIZE - 1] = '\0';
    return s_buffer;
}

char *hop_ip_addresses_to_string(traceroute *t)
{
    char *s_buffer = malloc(sizeof(char) * 4096);
    char hop_addr[INET6_ADDRSTRLEN];

    /* Insert opening string quotation mark */
    strncat(s_buffer, "\"", 2);

    for (int i = 0; i < t->hop_count; i++)
    {
        /* Convert address to string */
        inet_ntop(AF_INET6, &t->hops[i].hop_address, hop_addr, sizeof(hop_addr));
        /* Add to large string buffer */
        strncat(s_buffer, hop_addr, INET6_ADDRSTRLEN);
        strncat(s_buffer, " ", 2);
    }

    /* Replace final whitespace with closing string quotation mark */
    s_buffer[strlen(s_buffer) - 1] = '\"';

    /* Remove final whitespace */
    // s_buffer[strlen(s_buffer) - 1] = '\0';
    return s_buffer;
}

char *hop_numbers_to_string(traceroute *t)
{
    char *s_buffer = malloc(sizeof(char) * 4096);
    char i_buffer[100];

    /* Insert opening string quotation mark */
    strncat(s_buffer, "\"", 2);
    for (int i = 0; i < t->hop_count; i++)
    {
        /* Convert hop number to string */
        sprintf(i_buffer, "%d", t->hops[i].hopnumber);
        /* Concat hop number with string buffer */
        strncat(s_buffer, i_buffer, 2048);
        strncat(s_buffer, " ", 2);
    }

    /* Replace final whitespace with closing string quotation mark */
    s_buffer[strlen(s_buffer) - 1] = '\"';
    return s_buffer;
}

char *hop_returned_flowlabels_to_string(traceroute *t)
{
    char *s_buffer = malloc(sizeof(char) * 4096);
    char i_buffer[100];

    /* Insert opening string quotation mark */
    strncat(s_buffer, "\"", 2);
    for (int i = 0; i < t->hop_count; i++)
    {
        /* Convert hop number to string */
        sprintf(i_buffer, "%d", t->hops[i].returned_flowlabel);
        /* Concat hop number with string buffer */
        strncat(s_buffer, i_buffer, 2048);
        strncat(s_buffer, " ", 2);
    }

    /* Insert closing string quotation mark */
    // strncat(s_buffer, "\"", 2);

    /* Replace final whitespace with closing string quotation mark */
    s_buffer[strlen(s_buffer) - 1] = '\"';
    return s_buffer;
}

char *hop_asns_to_string(traceroute *t)
{
    char *s_buffer = malloc(sizeof(char) * 4096);

    /* Insert opening string quotation mark */
    strncat(s_buffer, "\"", 2);
    for (int i = 0; i < t->hop_count; i++)
    {
        strncat(s_buffer, t->hops[i].hop_asn, 2048);
        strncat(s_buffer, " ", 2);
    }

    /* Replace final whitespace with closing string quotation mark */
    s_buffer[strlen(s_buffer) - 1] = '\"';
    return s_buffer;
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

    flock(fileno(file), LOCK_UN); // unlock file
    fclose(file);
    return 0;
}
