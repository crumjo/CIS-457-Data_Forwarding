#include <stdio.h>
#include <unistd.h>

/**
 * Type: Time Exceeded = 11			Destination Unreachable = 3
 * Code: Network Unreachable = 0	Host Unreachable = 1	
 */

int create_icmp_err (uint8_t type, uint8_t code, uint16_t cksum, unsigned char *iphdr, unsigned char *new_msg)
{
	uint32_t zeros = 0x0000;

	/* Set the type. */
	memcpy (new_msg, type, sizeof(uint8_t));
	memcpy (new_msg + sizeof(uint8_T), code, sizeof(uint8_t));
	memcpy (new_msg + 2 * sizeof(uint8_t), cksum, sizeof(uint16_t));
	memcpy (new_msg + 4 * sizeof(uint8_t), zeros, sizeof(uint32_t));
	memcpy (new_msg + 8 * sizeof(uint8_t), iphdr, sizeof(iphdr));
}
