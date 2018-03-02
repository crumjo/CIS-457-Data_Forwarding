/**
 * Calculates the internet checksum, assumes buf has been
 * padded with zeros to a 16 bit boundary. Code is from 
 * Computer Networks fifth edition.
 * 
 * @param *buf the data to calculate.
 * @param count the size of buf in 16 bit units.
 * @return unsigned short the calculated checksum.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include "router_utility.c"


#ifndef router_utility_h
#define router_utility_h



unsigned short cksum (unsigned short *buf, int count);
unsigned char* ttl (unsigned char* icmp_buf);
int lookup(char *filename, char *ip, char *iface);
unsigned char* icmp_error(uint8_t type, uint8_t code, uint16_t cksum, unsigned char* iphdr, unsigned char* error_msg);

#endif
