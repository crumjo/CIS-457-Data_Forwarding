/**
 * Router uilities to generate a checksum, add the time to live, 
 * lookup addresses in the forwarding table, and generate
 * ICMP error messages.
 */

#include <stdio.h>
#include <unistd.h>
#include "router_utility.h"

#define ICMP_CODE_NET = (uint8_t) 0
#define ICMP_CODE_HOST = (uint8_t) 1
#define ICMP_TYPE_TIME = (uint8_t) 11
#define ICMP_TYPE_UNREACHABLE = (uint8_t) 3


/**
 * Calculates the internet checksum, assumes buf has been
 * padded with zeros to a 16 bit boundary. Code is from 
 * Computer Networks fifth edition.
 * 
 * @param *buf the data to calculate.
 * @param count the size of buf in 16 bit units.
 * @return unsigned short the calculated checksum.
 */
unsigned short cksum (unsigned short *buf, int count)
{
    register unsigned long sum = 0;

    while (count--)
    {
        sum += *buf++;
        if (sum & 0xFFFF0000)
        {
            /* Wrap around after carry. */
            sum &= 0xFFFF;
            sum++;
        }
    }
    return ~(sum & 0xFFFF);
}


/**
 * Time to live method that updates the time to live
 * and sends the appropriate error message if the time
 * to live is zero or less.
 * 
 * @param icmp_buf the icmp message to add TTL to.
 * @return unsigned char * the updated icmp message.
 */
unsigned char* ttl (unsigned char *icmp_buf)
{
	/* Copy iphdr and 64 bits of data for error message. */
	unsigned char data[84];
	memcpy (&data, icmp_buf, sizeof(data));	
	
    /* Pull ttl from icmp_buf, 9th byte of ip header. */
    uint8_t ttl;
    memcpy(&ttl, icmp_buf+14+9, sizeof(uint8_t));

    ttl--;

	/* Check if the packet timed out and then drop. */
    if (ttl <= 0)
    {
        //Time out. ICMP timeout reply, drop packet. -1 implies timeout
        //icmp_error
        //return buf with updated ttl
		unsigned char csum[16];
		memcpy (&csum, icmp_buf + 14 + 20 + 16, sizeof(uint16_t));
		create_icmp_err (ICMP_TYPE_TIME, ICMP_CODE_NET, csum, data, icmp_buf);
        return icmp_buf;
    }
    else
    {
        //update checksum
        unsigned short check[2];
        memcpy (check, icmp_buf+14+10, sizeof(uint16_t));
        uint16_t new_checksum = htons(cksum(check,2));

        memcpy(icmp_buf+14+10, &new_checksum, sizeof(uint16_t));

        return icmp_buf;
    }
}


/**
 * Looks up a routing table to return interface associated
 * with an IP address.
 * 
 * @param filename the name of the routing table.
 * @param ip the ip address to look up.
 * @param iface the interface for the given ip.
 * @return int a 1 if the ip is found in the routing table, -1 otherwise.
 */
int lookup(char *filename, char *ip, char *iface)
{

    FILE *in_file = fopen( filename, "r" );
    if (in_file == NULL) {
        fprintf(stderr, "File open failed.");
        fclose(in_file);
        exit(1);
    }

    /* Get the size of the file. */
    fseek (in_file, 0, SEEK_END);
    int size = ftell (in_file);
    fseek (in_file, 0, SEEK_SET);

    int lines = size / 22;
    // printf ("Lines: %d\n\n", lines);

    char tmp[2], line[128];
    int bits;

    for (int i = 0; i < lines; i++)
    {
        if (i != (lines - 1))
        {
            fread(line, sizeof(char), 22, in_file);
            memcpy(tmp, &line[9], 2);
            bits = atoi(tmp);
            char tmp_ip[16], comp_ip[16];
            memcpy (comp_ip, ip, (bits / 4));
            memcpy (tmp_ip, &line, (bits / 4));
            // printf("Passed IP: %s\n", comp_ip);
            // printf("File IP: %s\n", tmp_ip);

            if (strcmp (comp_ip, tmp_ip) == 0)
            {
                memcpy (iface, &line[14], 7);
                //printf("Interface: %s\n", iface);
                return 1;
            }
        }
        /* Last line. */
        else
        {
            //printf("Here\n\n");
            int pos = ftell (in_file);

            fread(line, sizeof(char), (size - pos), in_file);
            memcpy(tmp, &line[9], 2);
            bits = atoi(tmp);
            char tmp_ip[5], comp_ip[5];
            
            for (int i = 0; i < 4; i++)
            {
                comp_ip[i] = ip[i];
            }
            comp_ip[4] = '\0';
            

            //printf("%s\n", line);
            if (strcmp("r1-table.txt", filename) == 0)
            {
                strcpy(tmp_ip, "10.3");
            }
            else
            {
                strcpy(tmp_ip, "10.1");
            }
            // printf ("IP from param: %s\n", ip);
            // printf("Passed IP: %s\n", comp_ip);
            // printf("File IP: %s\n", tmp_ip);

            if (strcmp (comp_ip, tmp_ip) == 0)
            {
                char other_route[16];
                memcpy (other_route, &line[12], 8);
                memcpy (iface, &line[21], 7);
                printf("Other router IP: %s \t Interface: %s\n", other_route, iface);
                return 1;
            }
            
        }
    }

    fclose (in_file);
    return -1;; 
}


/**
 * Creates an icmp error message.
 * @param type the type of icmp message.
 * @param code host or network unreachable.
 * @param cksum the internet checksum.
 * @param iphdr the ip header and first 64 bits of data.
 * @param new_msg pointer to a new allocated icmp error message.
 */
void create_icmp_err (uint8_t type, uint8_t code, uint16_t cksum, unsigned char *iphdr, unsigned char *new_msg)
{
	uint32_t zeros = 0x0000;

	/* Set the type. */
	memcpy (new_msg, type, sizeof(uint8_t));
	memcpy (new_msg + sizeof(uint8_t), code, sizeof(uint8_t));
	memcpy (new_msg + 2 * sizeof(uint8_t), cksum, sizeof(uint16_t));
	memcpy (new_msg + 4 * sizeof(uint8_t), zeros, sizeof(uint32_t));
	memcpy (new_msg + 8 * sizeof(uint8_t), iphdr, sizeof(iphdr));

}
