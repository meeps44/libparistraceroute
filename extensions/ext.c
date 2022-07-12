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

#define DEBUG_ON 1

address *createAddress(void)
{
    address *a;
    if (a = calloc(1, sizeof(address)))
    {
        perror("Error");
        exit(1);
    }

    return a;
}

traceroute *createTraceroute(void)
{
    traceroute *t;
    if (t = calloc(1, sizeof(traceroute)) == NULL)
    {
        perror("Error");
        exit(1);
    }

    return t;
}

hop *createHop(void)
{
    hop *h;
    
    if (h = calloc(1, sizeof(hop)) == NULL) // if error
    {
        perror("Error");
        exit(1);
    }

    return h;
}

uint8_t *hashPath(address *l[])
{
    // Creates a hash of all the hops in a path and returns the result
    // We define a path as an ordered, indexed set of hops to a destination.

    // The data to be hashed
    SHA_CTX shactx;
    // uint8_t digest[SHA_DIGEST_LENGTH];
    uint8_t *digest = calloc(SHA_DIGEST_LENGTH, sizeof(uint8_t));

    SHA1_Init(&shactx);
    SHA1_Update(&shactx, l, sizeof(traceroute));
    SHA1_Final(digest, &shactx); // digest now contains the 20-byte SHA-1 hash
    
    return digest;
}

int asnLookup(address ipv6_address)
{
    int ASN;
    FILE *fp;
    char input_buffer[1024], open_string_buffer[1024];
    int num;
    int i = 1;

    sprintf(open_string_buffer, "python3 main.py %d", ipv6_address);

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

parsed_packet *parseIPv6(packet_t packet);

void printParsedPacket(parsed_packet *p);

int getFlowLabel(parsed_packet *p);

// 
// 
/**
 * @brief Loads a traceroute object into memory, parses it and prints out
 * its information
 * 
 * @param fileName 
 */
traceroute *fReadTraceroute(char *filename)
{
    FILE *f;
    traceroute *t = calloc(1, sizeof(traceroute));

    if ((f = fopen(filename, "r")) == NULL)
    {
        fprintf(stderr, "Error opening file:\t%s\nErrno:\t%s\n", filename, strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* Seek to the beginning of the file */
    fseek(f, 0, SEEK_SET);

    /* Read and display data */
    fread(t, sizeof(traceroute), 1, f);
    fclose(f);

    return t;
}

void fWriteTraceroute(traceroute *t, char *filename)
{
    FILE *f;
    // char *filename = "/home/erlend/C-programming/library-test/write_test.txt";
    size_t numb_elements = 1;
    int my_int = 42;
    // address my_struct = {
        // .a = 52,
        // .b = 1,
        // .c = 96,
        // .d = 8765};
    // char my_str[50] = "Hello from process 1!\n";

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

    fwrite(&t, sizeof(traceroute), 1, f);
    //fwrite(&my_struct, sizeof(int), sizeof(my_struct) / sizeof(int), f);
    // fwrite(my_str, sizeof(char), sizeof(my_str), f);

    flock(fileno(f), LOCK_UN); // unlock file
    fclose(f);
}

void printTraceroute(traceroute *t);

char *tracerouteToJSON(traceroute *t);

//char *createFileName(struct tm *currentTime) // (Might not be needed)
//{
    //char *fileName;

    //return fileName;
//}

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

int appendAddress(address *a, traceroute *t, int hopnumber, int returned_flowlabel)
{
    traceroute *tmp = t;
    int i;

    for (i = 0; i < 35; i++)
    {
        if (tmp->hops[i] == NULL)
        {
            printf("Available spot found at index:\t%d\n", i);
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
            printf("Available spot found at index:\t%d\n", i);
            t->hops[i] = h;
            return 0;
        }
    }

    return -1;
}