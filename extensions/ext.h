#include <openssl/sha.h> /* SHA1 */

typedef struct ipv6_address  {
    uint16_t address_short[8];
} address;

typedef struct hop
{
    int returned_flowlabel;
    int hopnumber;
    address *hop_address; // Could be a list of address pointers
} hop;

typedef struct traceroute
{
    // For easy route comparison - make a hash of the (source_ip, dest_ip, outgoing_flow_label)-tuple and add it
    // as a variable to the struct?
    /*
            "outgoing_tcp_port": "443",
        "flow_label": "1048575",
        "timestamp": "2022-05-07 15:50:47.559550",
        "source": "2a03:b0c0:1:d0::b45:6001",
        "source_asn": "14061",
        "destination": "2600:9000:20a5:f800:10:15f0:8cc0:93a1",
        "destination_asn": "16509",
        "path_id": "c0f8ed8a7c1f3d725bd89de7ed7eced0b9dcc67b",
    */
    uint16_t outgoing_tcp_port;
    char *timestamp;
    address source_ip;
    uint32_t source_asn;
    address destination_ip;
    uint32_t destination_asn;
    uint8_t path_id[SHA_DIGEST_LENGTH];
    hop *hops[35]; // maximum hop length is 35. any hops longer than that do not get included.
    // Could also be a list of *hop-pointers

} traceroute;


/**
 * @brief Create an address object initialized to zero
 * 
 * @return address* Pointer to the new address object
 */
address *createAddress(void);


/**
 * @brief Create a Traceroute object initialized to zero
 * 
 * @return traceroute* 
 */
traceroute *createTraceroute(void);

/**
 * @brief Create a Hop object initalized to zero
 * 
 * @return hop* 
 */
hop *createHop(void);

/**
 * @brief Hashes a list of addresses (aka a path).
 * 
 * @param l 
 * @return uint8_t* A pointer to a string containing a 20-char SHA1 digest.
 * 
 * NB! Code must be linked with libopenSSL in order for this to work.
 * Linkage example: gcc sha1-in-c.c -lcrypto
 */
uint8_t *hashPath(address *l[]);

/**
 * @brief Performs ASN-lookup of a given IPv6-address.
 * 
 * @param ipv6_address The IPv6-address on which to lookup.
 * @return int The AS number associated with this address
 */
int asnLookup(address ipv6_address);

/**
 * @brief Parses a raw IPv6-packet and saves the result to a parsed_packet struct.
 *
 * @param packet
 * @return parsed_packet*
 */
parsed_packet *parseIPv6(packet_t packet);

/**
 * @brief Prints each individual field of a parsed_packet to STDOUT.
 *
 * @param p
 */
void printParsedPacket(parsed_packet *p);

/**
 * @brief Get the Flow Label value of a parsed_packet.
 *
 * @param p
 * @return int
 */
int getFlowLabel(parsed_packet *p);

/**
 * @brief Write a traceroute object to file in binary format.
 * Uses file locking to avoid race conditions
 *
 * @param t
 */
void fWriteTraceroute(traceroute *t, char *filename);

/**
 * @brief Prints each individual field of a traceroute object to STDOUT.
 *
 * @param t
 */
void printTraceroute(traceroute *t);

/**
 * @brief Convert a traceroute object to JSON.
 *
 * @param t
 * @return char*
 */
char *tracerouteToJSON(traceroute *t);

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
 * @brief Appends an address-object to the next available spot in the
 * hops-array. Returns -1 if the array is full, 0 if executed correctly.
 * 
 * @param a 
 * @param t 
 * @return int Returns -1 if the array is full, 0 if executed correctly with no
 * errors.
 */
int appendAddress(address *a, traceroute *t, int hopnumber, int returned_flowlabel);
