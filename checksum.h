/**
 * Calculates the internet checksum, assumes buf has been
 * padded with zeros to a 16 bit boundary. Code is from 
 * Computer Networks fifth edition.
 * 
 * @param *buf the data to calculate.
 * @param count the size of buf in 16 bit units.
 * @return unsigned short the calculated checksum.
 */

#ifndef checksum_h
#define checksum_h

unsigned short cksum (unsigned short *buf, int count);

#endif