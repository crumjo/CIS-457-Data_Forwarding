#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <netpacket/packet.h> 
#include <sys/socket.h> 
#include <sys/types.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <net/if.h>

struct reply
{
    struct ether_header eh;
    struct ether_arp ea;
};

struct icmp_reply
{
    struct ether_header eh;
    struct iphdr ip;
    struct icmphdr x; 
};

void build_reply(struct reply* r, struct ether_header *eh, struct ether_arp *arp_frame, uint8_t dmac[6])
{
    r->ea.ea_hdr.ar_hrd=htons(ARPHRD_ETHER);
    r->ea.ea_hdr.ar_pro=htons(ETH_P_IP);
    r->ea.ea_hdr.ar_hln=ETHER_ADDR_LEN;
    r->ea.ea_hdr.ar_pln=sizeof(in_addr_t);
    r->ea.ea_hdr.ar_op=htons(ARPOP_REPLY);
    memcpy(&r->ea.arp_tha, &arp_frame->arp_sha, 6);/////
    memcpy(&r->ea.arp_tpa, &arp_frame->arp_spa, 4);
    memcpy(&r->ea.arp_sha, &arp_frame->arp_tha, 6);
    memcpy(&r->ea.arp_spa, &arp_frame->arp_tpa, 4);
    
    memcpy(&r->eh, eh, sizeof(struct ether_header));
}

void get_dst_ip(struct ifaddrs *ifaddr, struct ifaddrs *tmp, uint8_t arp_tpa[4], int socket, uint8_t dmac[6])
{
    struct ifreq ifr;
    for (tmp = ifaddr; tmp; tmp = tmp->ifa_next) {
        if (tmp->ifa_addr->sa_family==AF_INET) {
            struct sockaddr_in* sa = (struct sockaddr_in *) tmp->ifa_addr;
            char *addr = inet_ntoa(sa->sin_addr);
            char arp_addr[50];
            sprintf(arp_addr, "%u.%u.%u.%u", arp_tpa[0], arp_tpa[1],
                                             arp_tpa[2], arp_tpa[3]);
            
            if (strcmp(addr, arp_addr) == 0)
            {  
                ifr.ifr_addr.sa_family = AF_INET;
                memset(&ifr, 0x00, sizeof(ifr));

                strcpy(ifr.ifr_name, tmp->ifa_name);
                ioctl(socket, SIOCGIFHWADDR, &ifr);
                for( int i = 0; i < 6; i++ )
                {
                    printf("%u ", (unsigned char)ifr.ifr_hwaddr.sa_data[i]);
                }
                printf("\n");
            }
        }
    }
}

int main()
{
    //get list of interface addresses. This is a linked list. Next
    //pointer is in ifa_next, interface name is in ifa_name, address is
    //in ifa_addr. You will have multiple entries in the list with the
    //same name, if the same interface has multiple addresses. This is
    //common since most interfaces will have a MAC, IPv4, and IPv6
    //address. You can use the names to match up which IPv4 address goes
    //with which MAC address.
    struct ifaddrs *ifaddr, *tmp;
    if (getifaddrs(&ifaddr) == -1)
    {
        perror("getifaddrs");
        return 1;
    }

    fd_set sockets;
    FD_ZERO(&sockets);

    //have the list, loop over the list
    for (tmp = ifaddr; tmp != NULL; tmp = tmp -> ifa_next)
    {
        int packet_socket;

        //Check if this is a packet address, there will be one per
        //interface.  There are IPv4 and IPv6 as well, but we don't care
        //about those for the purpose of enumerating interfaces. We can
        //use the AF_INET addresses in this list for example to get a list
        //of our own IP addresses
        if (tmp -> ifa_addr -> sa_family == AF_PACKET)
        {
            printf("Creating Socket on interface %s\n", tmp -> ifa_name);
            //create a packet socket
            //AF_PACKET makes it a packet socket
            //SOCK_RAW makes it so we get the entire packet
            //could also use SOCK_DGRAM to cut off link layer header
            //ETH_P_ALL indicates we want all (upper layer) protocols
            //we could specify just a specific one
            packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
            if (packet_socket < 0)
            {
                perror("socket");
                return 2;
            }
            
            if (bind(packet_socket, tmp -> ifa_addr, sizeof(struct sockaddr_ll)) == -1)
            {
                perror("bind");
            }

            FD_SET(packet_socket, &sockets);
        }
    }
    printf ("Ready to recieve now\n");
    while (1)
    {
        char buf[1500];
        struct sockaddr_ll recvaddr;
        socklen_t recvaddrlen = sizeof(struct sockaddr_ll);
        fd_set tmp_set = sockets;

        struct timeval tv;
		tv.tv_sec = 1;
    	tv.tv_usec = 0;
		select(FD_SETSIZE+1, &tmp_set, NULL, NULL, &tv);
        //we can use recv, since the addresses are in the packet, but we
        //use recvfrom because it gives us an easy way to determine if
        //this packet is incoming or outgoing (when using ETH_P_ALL, we
        //see packets in both directions. Only outgoing can be seen when
        //using a packet socket with some specific protocol)

        for (int i=0;i<FD_SETSIZE;i++)
		{
			if (FD_ISSET(i, &tmp_set))
			{
				recvfrom(i, buf, 1500, 0, (struct sockaddr*)&recvaddr, &recvaddrlen);
                
                if(recvaddr.sll_pkttype == PACKET_OUTGOING)
                    continue;

                struct ether_header* eh = (struct ether_header*)malloc(sizeof(struct ether_header));
                struct ether_arp* arp_frame = (struct ether_arp*) (buf+14);
                /* Copy address of buf[0] to address of eh. */
                if ((((buf[12]) << 8) + buf[13]) != ETH_P_ARP) 
                    continue;

                /* skip to the next frame if it's not an ARP REPLY */
                if (ntohs (arp_frame->arp_op) != ARPOP_REQUEST)
                    continue;

                memcpy(eh, &buf[0], 14);
                
                int p_type = ntohs(eh->ether_type);

                //Check if IPv4 header
                if (p_type == 0x0800)
                {
                    
                }
                
                /* Check if ARP header. */
                if (p_type == 0x0806)
                {
                    struct ether_addr src, dst;
                    memcpy(&dst, eh->ether_dhost, sizeof(dst));
                    memcpy(&src, eh->ether_shost, sizeof(src));

                    printf("> Got an ARP packet from %d\n", i);
                    printf(">Src : %s\n", ether_ntoa(&src));
                    printf(">Dst : %s\n", ether_ntoa(&dst));

                    uint8_t dmac[6];
                    struct reply *r = (struct reply*)malloc(sizeof(struct reply));
                    get_dst_ip(ifaddr, tmp, arp_frame->arp_tpa, i, dmac);
                    build_reply(r,eh,arp_frame, dmac);
                    
                    send(i, r, sizeof(struct reply), 0);

                    free(r);
                }

                free (eh);
			}
		}
    }
    //free the interface list when we don't need it anymore
    freeifaddrs(ifaddr);
    //exit
    return 0;
}
