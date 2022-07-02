#include <stdio.h>
#include <stdlib.h>
#include <sys/file.h> // flock()
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include "ext.h"

int asnLookup(char *routeViewsFilePath, address ipv6_address)
{
    int ASN;

    return ASN;
}

parsed_packet *parseIPv6(packet_t packet);

void printParsedPacket(parsed_packet *p);

int getFlowLabel(parsed_packet *p);

void fWriteTraceroute(traceroute *t, char *fileName)
{
    FILE *f;
    char *filedir = "/home/erlend/C-programming/library-test/write_test.txt";
    size_t numb_elements = 1;
    int my_int = 42;
    address my_struct = {
        .a = 52,
        .b = 1,
        .c = 96,
        .d = 8765
    };
    char my_str[50] = "Hello from process 1!\n";

    // opens a file for reading and appending
    if ((f = fopen(filedir, "a+")) == NULL)
    {
        fprintf(stderr, "Error opening file\n");
        printf("Oh dear, something went wrong ! %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (flock(fileno(f), LOCK_EX) == -1) // exclusive lock - only 1 file may operate on it at a time
    {
        fprintf(stderr, "Error locking file\n");
        printf("Oh dear, something went wrong ! %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    fwrite(&my_struct, sizeof(int), sizeof(my_struct)/sizeof(int), f);
    // fwrite(my_str, sizeof(char), sizeof(my_str), f);

    flock(fileno(f), LOCK_UN); // unlock file
    fclose(f);
}

void printTraceroute(traceroute *t);

char *tracerouteToJSON(traceroute *t);