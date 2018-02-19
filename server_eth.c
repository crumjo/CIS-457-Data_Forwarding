#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>


int main (int argc, char **argv)
{
	/** 
 	* ET_P_ALL = All packet protocols. 
 	* SOCK_RAW = access to header.
    */
	int sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	/* sockaddr_ll = mac address or network interface. */
	struct sockaddr_ll addr, listenaddr;
	
	listenaddr.sll_family = AF_PACKET;
	listenaddr.sll_protocol = htons(ETH_P_ALL);
	
	/* ifindex = interface index (ethernet, virtual, etc) */
	listenaddr.sll_ifindex = if_nametoindex("h1-eth0"); //Mininet interface
	
	/* Listen to packets on h1-eth0 interface only. */
	bind(sockfd, (struct sockaddr *) &listenaddr, sizeof(listenaddr));

	while (1)
	{
		int len = sizeof(addr);
		char buf[5000];
		int n = recvfrom (sockfd, buf, 5000, 0, (struct sockaddr *) &addr, &len);

		if (addr.sll_pkttype != PACKET_OUTGOING)
		{
			printf("Got a packet.\n");
			struct ether_header eh;
			
			/* Copy address of buf[0] to address of eh. */
			memcpy(&eh, &buf[0], 14);
		
			int p_type = ntohs(eh.ether_type);			
				
			if (p_type == 0x800)
			{
				printf("IPV4 packet.\n");
				struct iphdr ih;

				memcpy(&ih, &buf[14], 20);
				
				struct in_addr ih_src;
				ih_src.s_addr = ih.saddr;

				struct in_addr ih_dst;
				ih_dst.s_addr = ih.daddr;	
	
				printf("IP Source: \t\t %s\n", inet_ntoa(ih_src));
				printf("IP Destination: \t %s\n", inet_ntoa(ih_dst));
			}

			/* ether_ntoa takes address and makes it ASCII printable. */
			printf("Destination: \t\t %s\n", ether_ntoa((struct ether_addr *) &eh.ether_dhost));
			
			printf("Source: \t\t %s\n", ether_ntoa((struct ether_addr *) &eh.ether_shost));

			printf("Type: \t\t\t %x\n\n", p_type);
		}
	}
	return 0;
}
