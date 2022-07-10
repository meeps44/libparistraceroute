typedef struct parsed_packet {

} parsed_packet;

typedef struct address {
    int a, b, c, d;
} address;

/**
 * @brief Contains data about each hop excluding the hopnumber and address
 * 
 */
typedef struct hop_metadata {
    int returned_flowlabel;
} hop_metadata;

typedef struct hop {
    hop_metadata md;
    int hopnumber;
    address a;
} hop;

typedef struct traceroute {
    // For easy route comparison - make a hash of the (source_ip, dest_ip, outgoing_flow_label)-tuple and add it 
    // as a variable to the struct?

    char *path_hash;
    hop hops[35]; // maximum hop length is 35. any hops longer than that do not get included. 
    // this could also be a list of *hop-pointers. maybe a better idea?

} traceroute;

/**
 * @brief Performs ASN-lookup of a given IPv6-address.
 * 
 * @param routeViewsFilePath The RouteViews file from which we will get ASN-data.
 * @return int 
 */
int asnLookup(char *routeViewsFilePath, address ipv6_address);

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
void fWriteTraceroute(traceroute *t, char *fileName);

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