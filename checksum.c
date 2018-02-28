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
#include "checksum.h"


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