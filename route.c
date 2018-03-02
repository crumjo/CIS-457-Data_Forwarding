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
#include <netinet/ip_icmp.h>

//custom arp_header, combine ether_header and ether_arp
struct arp_header
{
    struct ether_header eh;
    struct ether_arp ea;
};

//builds an arp reply
void build_reply(struct arp_header* r, struct ether_header *eh, struct ether_arp *arp_frame, uint8_t dmac[6])
{
    r->ea.ea_hdr.ar_hrd=htons(ARPHRD_ETHER);
    r->ea.ea_hdr.ar_pro=htons(ETH_P_IP);
    r->ea.ea_hdr.ar_hln=ETHER_ADDR_LEN;
    r->ea.ea_hdr.ar_pln=sizeof(in_addr_t);
    r->ea.ea_hdr.ar_op=htons(ARPOP_REPLY);
    //sets target ip and mac to original source for arp reply
    //sets source ip and mac to the routers ip and mac
    memcpy(&r->ea.arp_tha, &arp_frame->arp_sha, 6);
    memcpy(&r->ea.arp_tpa, &arp_frame->arp_spa, 4);
    memcpy(&r->ea.arp_sha, dmac, 6);
    memcpy(&r->ea.arp_spa, &arp_frame->arp_tpa, 4);
    memcpy(&r->eh, eh, sizeof(struct ether_header));
}
// builds arp request
void build_request(struct arp_header* r, struct ether_header *eh, struct ether_arp *arp_frame, uint8_t hop_ip[4])
{
    //sets options, arp_request
    r->ea.ea_hdr.ar_hrd=htons(ARPHRD_ETHER);
    r->ea.ea_hdr.ar_pro=htons(ETH_P_IP);
    r->ea.ea_hdr.ar_hln=ETHER_ADDR_LEN;
    r->ea.ea_hdr.ar_pln=sizeof(in_addr_t);
    r->ea.ea_hdr.ar_op=htons(ARPOP_REQUEST);

    //zero out target mac
    uint8_t tmp[6];
    for (int i = 0; i<6; i++) 
        tmp[i] = 0;
    //set source ip and mac to router ip and mac
    //sets target ip to the next hops ip (obtained from lookup/next hop function) and zeros target mac
    memcpy(&r->ea.arp_sha, &arp_frame->arp_sha, 6);
    memcpy(&r->ea.arp_spa, &arp_frame->arp_spa, 4);
    memcpy(&r->ea.arp_tha, tmp, 6);
    memcpy(&r->ea.arp_tpa, hop_ip, 4);
    //copy ether header in
    memcpy(&r->eh, eh, sizeof(struct ether_header));
    //sets ether type to ARP
    r->eh.ether_type = ntohs(2054);
}


void get_dst_mac(struct ifaddrs *ifaddr, struct ifaddrs *tmp, uint8_t arp_tpa[4], int socket, uint8_t dmac[6])
{
    struct ifreq ifr;
    for (tmp = ifaddr; tmp; tmp = tmp->ifa_next) {
        if (tmp->ifa_addr->sa_family==AF_INET) {
            struct sockaddr_in* sa = (struct sockaddr_in *) tmp->ifa_addr;
            char *addr = inet_ntoa(sa->sin_addr);
            char arp_addr[50];
            sprintf(arp_addr, "%u.%u.%u.%u", arp_tpa[0], arp_tpa[1],
                                             arp_tpa[2], arp_tpa[3]);
            //cycles through interfaces and checks against target ip
            if (strcmp(addr, arp_addr) == 0)
            {  
                ifr.ifr_addr.sa_family = AF_INET;
                memset(&ifr, 0x00, sizeof(ifr));
                //sets ifr values to proper levels to use on ioctl
                strcpy(ifr.ifr_name, tmp->ifa_name);
                ioctl(socket, SIOCGIFHWADDR, &ifr);
                //pulls hardware mac from socket using ioctl
                for( int i = 0; i < 6; i++ )
                {
                    //updates dmac to the destination mac. USED FOR APR REPLY
                    //printf("%u ", (unsigned char)ifr.ifr_hwaddr.sa_data[i]);
                    dmac[i] = (uint8_t)(unsigned char)ifr.ifr_hwaddr.sa_data[i];
                    //printf("%x ", dmac[i]);
                }
                //printf("\n");
            }
        }
    }
}

void get_src_mac(struct ifaddrs *ifaddr, struct ifaddrs *tmp, uint8_t if_ip[4], int socket, uint8_t if_mac[6])
{
    struct ifreq ifr;
    for (tmp = ifaddr; tmp; tmp = tmp->ifa_next) {
        if (tmp->ifa_addr->sa_family==AF_INET) {
            struct sockaddr_in* sa = (struct sockaddr_in *) tmp->ifa_addr;
            char *addr = inet_ntoa(sa->sin_addr);
            char arp_addr[50];
            sprintf(arp_addr, "%u.%u.%u.%u", if_ip[0], if_ip[1],
                                             if_ip[2], if_ip[3]);
            //compares interface address against the destination address
            if (strcmp(addr, arp_addr) == 0)
            {  
                ifr.ifr_addr.sa_family = AF_INET;
                memset(&ifr, 0x00, sizeof(ifr));
                //sets ifr for ioctl
                strcpy(ifr.ifr_name, tmp->ifa_name);
                ioctl(socket, SIOCGIFHWADDR, &ifr);
                for( int i = 0; i < 6; i++ )
                {
                    //sets the mac address to results from ioctl
                    if_mac[i] = (uint8_t)(unsigned char)ifr.ifr_hwaddr.sa_data[i];
                }
            }
        }
    }
}




void next_hop (char* table, char* buf, struct ifaddrs *tmp, struct ifaddrs *ifaddr, uint8_t hop_ip[4], struct ether_header* eh, struct ether_arp* arp_frame, char packet_iface[1023][15], int recvsocket)
{
    //passes in table associated with router, interface looping, the destination IP, and a list of interfaces matched with sockets
    unsigned char dest_ip[4];
    for (int i = 0; i < 4; i++)
    {
        //pull op ip into dest_ip
        uint8_t ip_tmp;
        memcpy (&ip_tmp, &buf[30+i], sizeof(uint8_t));
        memcpy (&dest_ip[i], &ip_tmp, sizeof(uint8_t));
    }
    //copy IP into string
    char lookup_ip[50];
    sprintf(lookup_ip, "%u.%u.%u.%u", dest_ip[0], dest_ip[1], dest_ip[2], dest_ip[3]);
    //printf("Dest IP: %s\n\n", lookup_ip);
    //allocate string for interface
    char* iface = (char*) malloc(sizeof(char)*15);
    //gets interface from lookup table
    int n = lookup(table, lookup_ip, iface);
    //if lookup fails send icmp_error msg
    if ( n < 0 )
    {
        uint16_t cksum = buf+14+10;
        unsigned char *iphd;
        memcpy (iphd, buf+14, sizeof(unsigned char)*20);
        buf = create_icmp_err(ICMP_DEST_UNREACH, 7, cksum,iphd, buf);
        send(recvsocket, &buf, sizeof(buf), 0);
    }
    else
    {
        printf("Interface: %s\n", iface);
        for (tmp = ifaddr; tmp != NULL; tmp = tmp -> ifa_next)
        {
            if (tmp -> ifa_addr -> sa_family == AF_INET)
            {   
                //loop through interfaces until reaching the next hop interface
                if (strcmp(iface, tmp->ifa_name) == 0)
                {
                    //Get IP address
                    struct sockaddr_in* sa = (struct sockaddr_in *) tmp->ifa_addr;
                    char *addr = inet_ntoa(sa->sin_addr);
                    //pull next ip address from interface
                    printf("Next Hop interface: %s\n", iface);
                    printf("Next IP: %s\n", addr);
                    
                    inet_pton(AF_INET, addr, hop_ip);
                    //build arp request from next ip to get dest mac
                    struct arp_header *r = (struct arp_header*)malloc(sizeof(struct arp_header));
                    build_request(r,eh,arp_frame, hop_ip);

                    printf("Sent an ARP request\n");

                    //send over the correct socket
                    int socket;
                    for (int i = 0; i < 1023; i++)
                    {
                        if (strcmp (packet_iface[i], tmp->ifa_name) == 0)
                        {
                            socket = i;
                        }
                    }
                    
                    send(socket, r, sizeof(struct arp_header), 0);
                } 
            }       
        }
    }
    
    free(iface);
}


int main(int argc, char** argv)
{
    if (argc<2)
    {
        printf("Missing routing table\n");
        exit(1);
    }
    //lookup("r1-table.txt", "10.1.1.1");

    //get list of interface addresses. This is a linked list. Next
    //pointer is in ifa_next, interface name is in ifa_name, address is
    //in ifa_addr. You will have multiple entries in the list with the
    //same name, if the same interface has multiple addresses. This is
    //common since most interfaces will have a MAC, IPv4, and IPv6
    //address. You can use the names to match up which IPv4 address goes
    //with which MAC address.
    struct ifaddrs *ifaddr, *tmp;
    char packet_iface[1023][15];
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
            //copy interface to entry in array equivalent to its socket. For sending out on same socket later
            strcpy (packet_iface[packet_socket], tmp->ifa_name);
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
                unsigned char* ireply = (unsigned char*)malloc(sizeof(unsigned char)*98);
                unsigned char* irequest = (unsigned char*)malloc(sizeof(unsigned char)*98);

                memcpy(eh, &buf[0], 14);
                
                int p_type = ntohs(eh->ether_type);
                //Check if IPv4 header
                if (p_type == 0x0800)
                {
                    printf("got an IPv4 packet!\n");
                    uint8_t *hop_ip = (uint8_t*)malloc(sizeof(uint8_t)*4);
                    //check if ICMP echo request, if so and not destination, calculate next hop
                    if (buf+14+20 == ICMP_ECHO)
                    {
                        next_hop(argv[1], buf, tmp, ifaddr, hop_ip, eh, arp_frame, packet_iface, i);
                    }
                    else if (buf+14+20 == ICMP_ECHOREPLY)
                    {
                        uint8_t tmp1 = ICMP_ECHOREPLY;
                        memcpy(ireply, &buf, 98);
                        memcpy(ireply+14+20, &tmp1, sizeof(uint8_t));
                        //iphdr swap

                        uint32_t tmp2;
                        memcpy(&tmp2,ireply+14+12, sizeof(uint32_t));
                        memcpy(ireply+14+12, ireply+14+16, sizeof(uint32_t));
                        memcpy(ireply+14+16, &tmp2, sizeof(uint32_t));
                        //ether header swap
                        uint8_t tmp3[6];
                        memcpy(&tmp3, ireply, sizeof(tmp3));
                        memcpy(ireply, ireply+5, sizeof(tmp3));
                        memcpy(ireply+5, &tmp3, sizeof(tmp3));

                        send (i, ireply, sizeof(unsigned char)*98, 0);
                    }
                    else
                    {
                        //icmp error message created from router_utility.c
                        //if not dest mac, send arp request to get destination
                    }
                }

                if (p_type == 0x0806)
                {
                    if (buf[21] == ARPOP_REQUEST)
                    {
                        printf("Got an arp request\n");
                        uint8_t dmac[6];
                        struct arp_header *r = (struct arp_header*)malloc(sizeof(struct arp_header));
                        get_dst_mac(ifaddr, tmp, arp_frame->arp_tpa, i, dmac);
                        build_reply(r,eh,arp_frame, dmac);
                        printf("Sent an arp reply\n");
                        send(i, r, sizeof(struct arp_header), 0);

                        free(r);
                    }
                    else if (buf[21] == ARPOP_REPLY)
                    {
                        printf("Got an arp reply\n");
                        //send ICMP request to next destination based on arp reply
                        memcpy(irequest, &buf, 98);
                        //change to ICMP echo
                        uint8_t tmp1 = ICMP_ECHO;
                        memcpy(irequest+14+20, &tmp1, sizeof(uint8_t));
                        //Flipping iphdr data back to ICMP request
                        uint32_t tmp2;
                        memcpy(&tmp2,irequest+14+16, sizeof(uint32_t));
                        memcpy(irequest+14+16, irequest+14+12, sizeof(uint32_t));
                        memcpy(irequest+14+12, &tmp2, sizeof(uint32_t));
                        //Flipping eth header back to ICMP request
                        uint8_t tmp3[6];
                        memcpy(&tmp3, irequest+5, sizeof(tmp3));
                        memcpy(irequest+5, irequest, sizeof(tmp3));
                        memcpy(irequest, &tmp3, sizeof(tmp3));
                        
                        //set to IPv4 header
                        uint16_t tmp4 = ntohs(2048);
                        memcpy (irequest+12, &tmp4, sizeof(uint16_t));

                        //change src mac address to router
                        //get interface mac
                        uint8_t if_mac[6];
                        uint8_t if_ip[4];
                        //hard code router ip
                        if (strcmp (argv[1], "r1-table.txt"))
                        {
                            if_ip[0] = htons(0x10);
                            if_ip[1] = htons(0x00);
                            if_ip[2] = htons(0x00);
                            if_ip[3] = htons(0x02);
                        }  
                        else
                        {
                            if_ip[0] = htons(0x10);
                            if_ip[1] = htons(0x00);
                            if_ip[2] = htons(0x00);
                            if_ip[3] = htons(0x01);
                        }
                        //get router mac address
                        get_src_mac (ifaddr, tmp, if_ip, i, if_mac);
                        // printf("Next Hop MAC: %x:%x:%x:%x:%x:%x\n", if_mac[0], if_mac[1], if_mac[2],
                        //                             if_mac[3], if_mac[4], if_mac[5]);
                        //copy mac into eth header
                        memcpy (irequest, &if_mac, sizeof(if_mac));
                        //send icmp request out
                        send (i, irequest, sizeof(unsigned char)*98, 0);
                    }
                    
                    
                }
                free(ireply);
                free (eh);
			}
		}
    }
    //free the interface list when we don't need it anymore
    freeifaddrs(ifaddr);
    //exit
    return 0;
}