#include <stdio.h>
#include <stdlib.h>
#include <sys/file.h> // flock()
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include "ext.h"
#include <openssl/sha.h> // SHA1
#include <time.h>
#include <stdbool.h>

int hashPath(parsed_packet *p)
{
    // Creates a hash of all the hops in a path and returns the result
    // We define a path as an ordered, indexed set of hops to a destination.

    // The data to be hashed
    char data[] = "Hello, world!";
    size_t length = strlen(data);

    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(data, length, hash);
    // hash now contains the 20-byte SHA-1 hash
}

int asnLookup(char *routeViewsFile, address ipv6_address)
{
    int ASN;
    FILE *fp;
    char input_buffer[1024];
    int num;
    int i = 1;

    fp = popen("python3 main.py", "r");
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

parsed_packet *parseIPv6(packet_t packet);

void printParsedPacket(parsed_packet *p);

int getFlowLabel(parsed_packet *p);

void fWriteTraceroute(traceroute *t, char *fileName)
{
    FILE *f;
    char *filename = "/home/erlend/C-programming/library-test/write_test.txt";
    size_t numb_elements = 1;
    int my_int = 42;
    address my_struct = {
        .a = 52,
        .b = 1,
        .c = 96,
        .d = 8765};
    char my_str[50] = "Hello from process 1!\n";

    // opens a file for reading and appending
    if ((f = fopen(filename, "a+")) == NULL)
    {
        fprintf(stderr, "Error opening file:\t%s\nErrno:\t%s\n", filename, strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (flock(fileno(f), LOCK_EX) == -1) // exclusive lock - only 1 file may operate on it at a time
    {
        fprintf(stderr, "Error locking file:\t%s\nErrno:\t%s\n", filename, strerror(errno));
        exit(EXIT_FAILURE);
    }

    fwrite(&my_struct, sizeof(int), sizeof(my_struct) / sizeof(int), f);
    // fwrite(my_str, sizeof(char), sizeof(my_str), f);

    flock(fileno(f), LOCK_UN); // unlock file
    fclose(f);
}

void printTraceroute(traceroute *t);

char *tracerouteToJSON(traceroute *t);

char *getFileName(struct tm *currentTime)
{
    char *fileName;

    return fileName;
}

struct tm *getCurrentTime(void)
{
    // time_t t = time(NULL);
    // struct tm tm = *localtime(&t);
    // printf("now: %d-%02d-%02d %02d:%02d:%02d\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

    time_t t = time(NULL);
    struct tm *now = gmtime(&t);
    // Output timestamp in format "YYYY-MM-DD hh:mm:ss : "
    printf("%04d-%02d-%02d %02d:%02d:%02d : ",
           now->tm_year + 1900, now->tm_mon + 1, now->tm_mday,
           now->tm_hour, now->tm_min, now->tm_sec);

    return now;
}