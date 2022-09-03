#include "patricia.h"
#include <netinet/in.h> //in6_addr

inline static prefix_t *make_prefix();

inline static bool set_prefix(prefix_t *subnet, int family, struct in6_addr *addr, unsigned int width);

inline static bool parse_cidr(const char *cidr, int *family, struct in6_addr *subnet, unsigned short *mask);

void patricia_init(bool arg_binary_lookup_mode);

int insert(int family, struct in6_addr subnet, unsigned short mask, char *data);

char *lookup_addr(int family, struct in6_addr addr);