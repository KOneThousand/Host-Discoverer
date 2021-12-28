//******************************************************
// Filename: HostDiscoverer.cpp
// Purpose:  Scan of local networks
// Author:   KOneThousand; 
// Date:     Dicember 27, 2021
//******************************************************

#include <iostream>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <cstring>
#include <netinet/ip_icmp.h>
#include <signal.h>
#include "Kping.hpp"

constexpr unsigned int PING_PKT_S      = 64;  // Define the Packet Constants ping packet size
constexpr unsigned int PORT_NO         = 0;   // Automatic port number
constexpr unsigned int PING_SLEEP_RATE = 10;  // timeout delay for receiving packets in microseconds

static unsigned int pingLoop = 1;

struct ping_pkt // Ping packet structure
{
    struct icmphdr hdr;
    char msg[PING_PKT_S-sizeof(struct icmphdr)];
};

unsigned short checksum(void *b, int len) // Calculating the Check Sum
{    
    unsigned short *buf = (unsigned short*)b;
    unsigned int sum = 0;
    unsigned short result;
  
    for (sum = 0; len > 1; len -= 2)
    {
        sum += *buf++;
    }  
    if (len == 1)
    {
        sum += *(unsigned char*)buf;
    }   
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;

    return result;
}
  
void intHandler(int var) // Interrupt handler
{
    pingLoop = 0;
}

char *dns_lookup(char *addr_host, struct sockaddr_in *addr_con) // Performs a DNS lookup 
{
    struct hostent *host_entity;
    char *ip = (char*)malloc(NI_MAXHOST*sizeof(char));
  
    if ((host_entity = gethostbyname(addr_host)) == NULL) // No ip found for hostname
    {
        return NULL;
    }
      
    // Filling up address structure
    strcpy(ip, inet_ntoa(*(struct in_addr *)host_entity->h_addr));
  
    (*addr_con).sin_family = host_entity->h_addrtype;
    (*addr_con).sin_port = htons (PORT_NO);
    (*addr_con).sin_addr.s_addr  = *(long*)host_entity->h_addr;
  
    return ip;
      
}
  
// Make a ping request
bool send_ping(char* ipToPing, int sockfd, struct ping_pkt &pckt, struct sockaddr_in const &r_addr)
{
    /* Setting up the ping process */
    char *ip_addr;
    struct sockaddr_in addr_con;
    unsigned int addrlen = sizeof(addr_con);
    char net_buf[NI_MAXHOST];
  
    ip_addr = dns_lookup(ipToPing, &addr_con);

    if(ip_addr == NULL)
    {
        return false;
    }
  
    signal(SIGINT, intHandler); // Catching interrupt

    unsigned int i, flag = 1, msg_received_count = 0;
    int msg_count = 0;
    
    if (pingLoop)
    {   
        flag = 1; // Flag is whether packet was sent or not
        bzero(&pckt, sizeof(pckt)); // Filling packet
        pckt.hdr.type = ICMP_ECHO;
        pckt.hdr.un.echo.id = getpid();
            
        for (i = 0; i < sizeof(pckt.msg)-1; i++)
        {
            pckt.msg[i] = i + '0';
        }    
        pckt.msg[i] = 0;
        pckt.hdr.un.echo.sequence = msg_count++;
        pckt.hdr.checksum = checksum(&pckt, sizeof(pckt));

        usleep(PING_SLEEP_RATE);

        /* Send packet */
        if (sendto(sockfd, &pckt, sizeof(pckt), 0, (struct sockaddr*)&addr_con, sizeof(*&addr_con)) <= 0)
        {
            flag = 0;
        }

        /* Receive packet */
        socklen_t addr_len = sizeof(r_addr);

        if (recvfrom(sockfd, &pckt, sizeof(pckt), 0, (struct sockaddr*)&r_addr, &addr_len) <= 0 && msg_count > 1) 
        {
            return false;
        }
        else
        {                    
            if(flag) // If packet was not sent, don't receive
            {
                if((pckt.hdr.type == 69 && pckt.hdr.code == 0)) 
                {
                    msg_received_count++;
                }
            }
        }

        if (msg_received_count == 1)
        {
            return true;
        }
    }

    return false;
}