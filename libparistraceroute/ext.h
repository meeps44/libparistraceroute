#ifndef EXT_H
#define EXT_H
#include <stdint.h>
#include <openssl/sha.h> // SHA1
#include <netinet/in.h>  //in6_addr
#include <sqlite3.h>
#include "packet.h"

#define HOP_MAX 35

enum IPV6_HEADER_OPTS
{
    NH_NNH = 59,      // No next header
    NH_HBH_OPTS = 0,  // Hop-by-Hop Options
    NH_DST_OPTS = 60, // Destination Options
    NH_RH = 43,       // Routing Header
    NH_FH = 44,       // Fragment Header
    NH_AH = 51,       // Authentication Header
    NH_ESPH = 50,     // Encapsulation Security Payload Header
    NH_MH = 135,      // Mobility Header
    NH_TCP = 6,
    NH_UDP = 17,
    NH_ICMPv6 = 58,
};

// Type codes: https://datatracker.ietf.org/doc/html/rfc4443
enum ICMP_TYPES
{
    ICMP_ECHO_REQUEST = 128,
    ICMP_ECHO_REPLY = 129,
    ICMP_DESTINATION_UNREACHABLE = 1,
    ICMP_PACKET_TOO_BIG = 2,
    ICMP_TIME_EXCEEDED = 3,
    ICMP_PARAMETER_PROBLEM = 4,
};

typedef struct icmp6_header_s
{
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t opt;
} icmp6_header;

typedef struct ipv6_header_s
{
    uint8_t version : 4;
    uint32_t flow_label : 20;
    uint8_t traffic_class;
    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit;
    struct in6_addr source;
    struct in6_addr destination;
} ipv6_header;

typedef struct addr_tuple_s
{
    u_int8_t hopnumber;
    struct in6_addr hop_address; // uint32_t __u6_addr32[4], uint8_t	__u6_addr8[16], uint16_t __u6_addr16[8]
} addr_tuple;

/**
 * @brief Inits ASN-lookup by loading asn2prefix and creating patricia-tree
 *
 * @param filename
 * @return int
 */
int asnLookupInit(char *filename);

/**
 * @brief Parses an ICMPv6-packet and creates a newly allocated ICMPv6-header object.
 *
 * @param icmp_first_byte
 * @return icmp6_header* The ICMPv6-header object.
 */
icmp6_header *parse_icmp6(const uint8_t *icmp_first_byte);

/**
 * @brief Parses an IPv6-packet and creates a newly allocated IPv6-header object.
 *
 * @param first_byte
 * @return ipv6_header* The IPv6-header.
 */
ipv6_header *parse_ipv6(const uint8_t *first_byte);

typedef struct hop
{
    uint8_t hopnumber;
    uint32_t returned_flowlabel;
    char hop_asn[200];
    struct in6_addr hop_address; // uint32_t __u6_addr32[4], uint8_t	__u6_addr8[16], uint16_t __u6_addr16[8]
} hop;

typedef struct traceroute
{
    long start_time;
    uint16_t outgoing_tcp_port;
    int outgoing_flow_label;
    char *timestamp;
    struct in6_addr source_ip;
    char source_asn[200];
    struct in6_addr destination_ip;
    char destination_asn[200];
    char path_id[SHA_DIGEST_LENGTH + 1]; // +1 for terminating null-character
    uint8_t hop_count;
    hop hops[HOP_MAX]; // maximum hop length is 35. any hops longer than that do not get included.
} traceroute;

/**
 * @brief Get the global traceroute object
 *
 * @return traceroute* Pointer to the heap-allocated traceroute object.
 */
traceroute *get_traceroute(void);

/**
 * @brief Set the global traceroute object.
 *
 * @param t
 */
void set_traceroute(traceroute *tr);

/**
 * @brief Create an address object initialized to zero
 *
 * @return address* Pointer to the new address object
 */
struct in6_addr *createAddress(void);

/**
 * @brief Create a Traceroute object initialized to zero
 *
 * @return traceroute*
 */
traceroute *createTraceroute(void);

/**
 * @brief Initialize a traceroute object
 *
 * @return int 0 if successful, -1 on error.
 */
int init_traceroute(long start_time, char *src_ip, char *dst_ip);

/**
 * @brief Create a Hop object initalized to zero
 *
 * @return hop*
 */
hop *createHop(void);

/**
 * @brief Prints a hash digest to a unsigned char buffer.
 * The buffer should be at least size 41 or greater.
 * NB! For successful memcmp() between two buffers, the buffer size needs to
 *  be exactly size 41.
 *
 * @param digest The hash digest in the form of an array of unsigned
 * characters of size SHA_DIGEST_LENGTH.
 * @param s The destination buffer.
 */
void sPrintHash(uint8_t *digest, char *s);

/**
 * @brief Prints a hash digest to STDOUT.
 *
 * @param digest The hash digest in the form of an array of unsigned
 * characters of size SHA_DIGEST_LENGTH.
 */
void printHash(uint8_t digest[]);

/**
 * @brief Creates a hash of all the hops in a path and returns the resulting
 * digest.
 * We define a path as an ordered, indexed set of hops to a destination.
 *
 * @param l Ordered list of address pointers that combined comprise a path.
 * @return uint8_t* List containing the newly created 20-char long SHA1 digest.
 *
 * NB! Code must be linked with libopenSSL in order for this to work.
 * Linkage example: gcc sha1-in-c.c -lcrypto
 */
uint8_t *hashPath(struct in6_addr arr[], int arraySize);

/**
 * @brief Performs ASN-lookup of a given IPv6-address.
 *
 * @param ipv6_address The IPv6-address on which to lookup.
 * @return int The AS number associated with this address.
 */
char *asnLookup(struct in6_addr *ipv6_address);

/**
 * @brief Get the Flow Label value of a parsed_packet.
 *
 * @param p
 * @return int
 */
int getFlowLabel(struct in6_addr *a);

/**
 * @brief Loads a traceroute object at OFFSET <offset> in FILE <filename>
 * into memory at location <t>.
 *
 * @param fileName The file to read from.
 * @param t Pointer to the destination traceroute object.
 * @param offset Offset within the file. Must be a multiple of
 * sizeof(traceroute).
 *
 * @return int 1 if successful, 0 if error.
 */
int readTracerouteFromFile(char *filename, traceroute *t, long offset);

/**
 * @brief Write a traceroute object to file in binary format.
 * Uses file locking to avoid race conditions
 *
 * @param t
 */
int writeTracerouteToFile(traceroute *t, char *filename);

/**
 * @brief Prints each individual field of a traceroute object to STDOUT.
 *
 * @param t
 */
int printTraceroute(traceroute *t);

/**
 * @brief Prints each individual field of a hop object to STDOUT
 *
 * @param h
 * @return int
 */
int printHop(hop *h);

/**
 * @brief Gets the current time (GMT)
 *
 * @return A struct representation of the current time in GMT
 */
struct tm *getCurrentTime(void);

/**
 * @brief Appends hop-object to the next available spot in the
 * hops-array. Returns -1 if the array is full.
 *
 * @param h
 * @param t
 * @return int
 */
int appendHop(hop *h, traceroute *t);

/**
 * @brief Loads a .pt-file into memory and converts its content into an
 * array (or linked-list, or hashmap) of Traceroute-objects.
 *
 * @param filename
 * @return int 0 on success, -1 on error
 */
int ptFileToTraceroute(char *filename);

/**
 * @brief Compares two traceroute paths and returns the hop-number (index)
 * where they diverged. If the paths did not diverge (they are equal), return 0.
 *
 * @param t1
 * @param t2
 * @return int
 */
int compareIndexedPaths(traceroute *t1, traceroute *t2);

/**
 * @brief Compares two traceroute paths.
 *
 * @param t
 * @return 1 if equal, 0 if not equal, -1 on error.
 */
int comparePaths(traceroute *t1, traceroute *t2);

/**
 * @brief Compares all paths to [source], [destination] in file1 against
 * all paths with the same [source], [destination] pair in file2 and
 * returns the hop-number (index) where they diverged. If the paths did not
 * diverge (they are equal), print EQUAL.
 *
 * @param file1
 * @param file2
 * @return *char[] Array of strings in the format:
 * Paths [source], [destination] in [file1], [file2] were EQUAL
 * Paths [source], [destination] in [file1], [file2] were NOT EQUAL. Diverged
 * at: [hopnumber].
 */
char **fCompareIndexedPaths(char *file1, char *file2);

/**
 * @brief Compares all paths to [source], [destination] in file1 against
 * all paths with the same [source], [destination] pair in file2.
 *
 * @param file1
 * @param file2
 * @return *char[] Array of strings in the format:
 * Paths [source], [destination] in [file1], [file2] were EQUAL
 * Paths [source], [destination] in [file1], [file2] were NOT EQUAL
 */
char **fComparePaths(char *file1, char *file2);

/**
 * @brief Creates a filename in the form HOSTNAME-CURRENT_TIME.
 * The filename length is limited to 100 characters.
 *
 * @return Pointer to the filename.
 */
char *createFileName(struct tm *now); // (Might not be needed)

/**
 * @brief Compares two hops and checks if they are equal. (Function
 * might not be needed).
 *
 * @param h1
 * @param h2
 * @return int 1 if equal, 0 if not equal.
 */
int compareHops(hop *h1, hop *h2);

/**
 * @brief Compares two address objects and checks if they are equal.
 *
 * @param a1 Pointer to the first address object.
 * @param a2 Pointer to the second address object.
 * @return int 1 if equal, 0 if not equal.
 */
int compareAddresses(struct in6_addr *a1, struct in6_addr *a2);

/**
 * @brief Writes all traceroute objects in tr_array to filename.
 *
 * @param filename
 * @param tr_arr
 * @param arraySize
 * @return int
 */
int writeTracerouteArrayToFile(char *filename, traceroute *tr_arr[], int arraySize);

/**
 * @brief Reads arraySize number of traceroute objects from filename into
 * array tr_arr.
 *
 * @param filename
 * @param tr_arr
 * @param arraySize
 * @return int
 */
int readTracerouteArrayFromFile(char *filename, traceroute *tr_arr[], int arraySize);

/**
 * @brief Serializes a traceroute object and writes it to file in CSV-format.
 *
 * @param fileName
 * @param t
 * @return int
 */
int serialize_csv(char *fileName, traceroute *t);

/**
 * @brief Serializes a traceroute object and writes it to file as a
 * raw sequence of bytes.
 *
 * @param fileName
 * @param t
 * @return int
 */
int serialize_bytes(char *fileName, traceroute *t);

/**
 * @brief Creates a timestamp of the current time represented
 * as a string.
 *
 * @return String representation of the current time in UTC-format.
 */
char *create_timestamp();

/**
 * @brief Get the global IPv6-address of the local host. Address is
 * extracted from file /proc/net/if_inet6.
 *
 * @return String representation of global host IPv6 in
 * xx:xx:xx:xx:xx:xx-format.
 */
char *get_host_ip();

/**
 * @brief Converts a string representation of an IPv6-address to a
 * struct in6_addr.
 *
 * @param ipv6_address_string The string to be converted.
 * @return struct in6_addr* The resultant struct. Returns NULL on failure.
 */
struct in6_addr *convert_address_string(char *ipv6_address_string);

/**
 * @brief
 *
 * @param t Pointer to the traceroute object.
 * @param i6 Pointer to the IPv6-address to be hashed.
 * @return int
 */

/**
 * @brief Get the inner ipv6 header object
 *
 * @param p The raw IPv6 packet.
 * @return ipv6_header* Pointer to the inner IPv6-header.
 */
ipv6_header *get_inner_ipv6_header(uint8_t *first_byte);

/**
 * @brief Create destination, Create a newly allocated struct in6_addr.
 *
 * @return struct in6_addr*
 */
struct in6_addr *create_destination(void);

/**
 * @brief Get a pointer to the global destination object.
 *
 * @return struct in6_addr*
 */
struct in6_addr *get_destination(void);

/**
 * @brief Converts a struct in6_addr to a printable string.
 *
 * @param i6 A pointer to a struct in6_addr.
 * @return char* A pointer to the newly malloced string containing
 * the presentation form of the IPv6-address.
 * On success, inet_ntop() returns a non-null pointer to dst.  NULL is returned if there was an error, with errno set to indicate the error.
 */
const char *printAddress(struct in6_addr *i6);

/**
 * @brief Creates a hash of all the address_tuples in a path and returns the resulting
 * digest.
 *
 * @param arr Ordered list of address pointers that combined comprise a path.
 * @param arraySize Size of the addr_tuple array.
 * @return  Pointer to the newly created SHA1 digest.
 *
 * NB! Code must be linked with libopenSSL in order for this to work.
 * Linkage example: gcc sha1-in-c.c -lcrypto
 */
uint8_t *hashPathTuple(addr_tuple arr[], int arraySize);

char *inet_addr_to_string(struct in6_addr *addr);

sqlite3 *db_open_and_init(char *filename);

int db_create_table(sqlite3 *db);

int db_callback(void *unused, int column_count, char **data, char **columns);

int db_insert(sqlite3 *db, traceroute *t);

char *hop_ip_addresses_to_string(traceroute *t);

char *hop_numbers_to_string(traceroute *t);

char *hop_returned_flowlabels_to_string(traceroute *t);

char *hop_asns_to_string(traceroute *t);

char *path_id_to_string(char *path_id);

int db_close(sqlite3 *db);

int serialize_bytes(char *fileName, traceroute *t);

#endif
