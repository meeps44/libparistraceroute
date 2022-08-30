#include "patricia.h"

inline static prefix_t *make_prefix();

inline static bool set_prefix(prefix_t *subnet, int family, inx_addr *addr, unsigned int width);

inline static bool parse_cidr(const char *cidr, int *family, inx_addr *subnet, unsigned short *mask);

void patricia_init(bool arg_binary_lookup_mode);

int insert(int family, inx_addr subnet, unsigned short mask, int data);

int lookup_addr(int family, inx_addr addr);