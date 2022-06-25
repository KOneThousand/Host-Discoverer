//******************************************************
// Filename: HostDiscoverer.cpp
// Purpose:  Scan of local networks
// Author:   KOneThousand 
// Date:     June 21, 2022
//******************************************************

#include <iostream>
#include <string>
#include <vector>
#include <array>
#include <cmath>
#include <algorithm>
#include <bits/stdc++.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <cstring>
#include <netinet/ip_icmp.h>
#include <signal.h>

#include "Kping.hpp"

/* Text terminal color */
#define RST  "\x1B[0m"
#define BOLD_BLUE "\033[1;34m"
#define BLUE "\033[0;34m"
#define BOLD_GREEN "\033[1;32m"
#define BOLD_RED "\033[1;31m"

#define SET_BOLD_BLUE(x) BOLD_BLUE x RST
#define SET_BLUE(x) BLUE x RST
#define SET_BOLD_GREEN(x) BOLD_GREEN x RST
#define SET_BOLD_RED(x) BOLD_RED x RST

union IP {
   uint8_t bytes[4];
   uint32_t data;
};

const int ARRAY_CHUNKS_LEN = 4;

std::pair<std::string, std::string> separateIPfromCIDR(const std::string CIDR)
{
	std::string ipAddr, netmask;
	ipAddr.assign(CIDR, 0, CIDR.find('/')); // Strip out the ip address

	/* CALCULATE THE NETMASK FROM CIDR NOTATION */
	std::string CIDRMask;
	CIDRMask.assign(CIDR, (CIDR.find('/') + 1), 2); // Strip out the CIDR Netmask
	std::array<std::bitset<8>, 4> binNetmask;
	int nBlock = stoi(CIDRMask) / 8;
	for(int i = 0; i < nBlock; i++)
	{
		binNetmask[i] = 255; // Fill the chunk with 1's
	}
	if (nBlock < 4)
	{
		std::string temp = std::string(stoi(CIDRMask) % 8, '1'); // Add a number of 1's equal to CIDRMask % 8
		temp.resize(8, '0');
		binNetmask[nBlock] = std::bitset<8>(temp);
	}

	for(unsigned int i = 0; i < ARRAY_CHUNKS_LEN - 1; ++i)
	{
		std::string decimalTemp = std::to_string(binNetmask[i].to_ulong());
		netmask += (decimalTemp + '.');
	}
	netmask += std::to_string(binNetmask[3].to_ulong());

	return std::make_pair(ipAddr, netmask); // Return the ip address and the netmask in CISCO notation
}

std::array<int, 4> getChunks(const std::string &chunksToDivide) // Fill an array with the numbers between the points
{
	std::array<std::string, 4> str_Chunks;
	std::stringstream check(chunksToDivide);
	std::string temp;
	for(int i = 0; (getline(check, temp, '.')); i++) // Until the are tokens
		str_Chunks[i] = temp;

	std::array<int, 4> int_Chunks;
	for (unsigned int i = 0; i < ARRAY_CHUNKS_LEN; ++i)
		int_Chunks[i] = stoi(str_Chunks[i]);

	return int_Chunks;
}

std::string firstIpAddrRange(const std::string& ipAddr, const std::string& netmask) // calculate the first ip address of the network
{ 
	std::string firstIpAddr;

	std::array<int, 4> int_ipAddrChunks, int_netmaskChunks;
	int_ipAddrChunks  = getChunks(ipAddr);
	int_netmaskChunks = getChunks(netmask);
	for(unsigned int i = 0; i < ARRAY_CHUNKS_LEN; ++i)
	{	
		unsigned int tempCalc = int_ipAddrChunks[i] & int_netmaskChunks[i]; // bitwise AND operation
		if (i < 3)
		{
			firstIpAddr += std::to_string(tempCalc) + ".";
		}
		else
		{
			firstIpAddr += std::to_string(tempCalc + 1); // remove broadcast ip address
		}	
	}

	return firstIpAddr;
}

std::string lastIpAddrRange(const std::string& firstIpAddr, const std::string& netmask) // calculate the last ip address of the network
{
	std::string lastIpAddr;

	std::array<int, 4> int_firstIpAddrChunks, int_netmaskChunks;
	int_firstIpAddrChunks = getChunks(firstIpAddr);
	int_netmaskChunks     = getChunks(netmask);
	for(unsigned int i = 0; i < ARRAY_CHUNKS_LEN; ++i)
	{	
		std::bitset<8> binNetmaskChunk (int_netmaskChunks[i]); // Convert the netmask chunk from decimal to binary
		std::string oppBinNetmaskChunk = binNetmaskChunk.flip().to_string(); // Calculate the opposite of the binary netmask chunk
		int oppDecimalNetmaskChunk = std::bitset<8>(std::bitset<8>(oppBinNetmaskChunk)).to_ulong(); // Convert the opposite of the 
																									// netmask chunk from binary to decimal
		
		unsigned int tempCalc = oppDecimalNetmaskChunk | int_firstIpAddrChunks[i]; // bitwise OR operation
		if (i < 3)
		{
			lastIpAddr += std::to_string(tempCalc) + ".";
		}
		else
		{
			lastIpAddr += std::to_string(tempCalc - 1); // Remove broadcast ip address 
		}
	}

	return lastIpAddr;
}

std::string mergeChunks(const int fstChunk, const int sndChunk, const int trdChunk, const int fthChunk) // merge the given chunks into a unique string				
{ 
	std::string currentIpAddr = std::to_string(fstChunk) + "." + std::to_string(sndChunk) + "." +
								std::to_string(trdChunk) + "." + std::to_string(fthChunk);
	return currentIpAddr; 	
}

constexpr unsigned int PING_PKT_S   = 64;  // Define the Packet Constants ping packet size
constexpr unsigned int RECV_TIMEOUT = 10;  // Timeout delay for receiving packets in secs

struct ping_pkt // Ping packet structure
{
    struct icmphdr hdr;
    char msg[PING_PKT_S-sizeof(struct icmphdr)];
};	

void foundHost(const std::array<int, 4> &currentIpAddrChunks, std::vector<std::string> &upHosts, const int sockfd) // ping the given ip address
{
	std::string currentIpAddr = mergeChunks(currentIpAddrChunks[0], currentIpAddrChunks[1],
		 									currentIpAddrChunks[2], currentIpAddrChunks[3]); // compose the given chunks into a string

	/* Make a ping reqeust part */
    struct ping_pkt pckt;
    struct sockaddr_in r_addr;
    struct timeval tv_out; 
    tv_out.tv_usec = RECV_TIMEOUT;

    unsigned int ttl_val = 64;  
    // Set socket options at ip to TTL and value to 64, change to what you want by setting ttl_val
    if (setsockopt(sockfd, SOL_IP, IP_TTL, &ttl_val, sizeof(ttl_val)) != 0)
    {
        return;
    }

    // Setting timeout of recv setting
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv_out, sizeof(tv_out));
	
	if (send_ping((char*)currentIpAddr.data(), sockfd, pckt, r_addr)) // if the send_ping function is able to ping the host
	{
		upHosts.push_back(currentIpAddr);
	}
}

constexpr unsigned int LAST_ARRAY_ELEMENT = 3;  

void scan(const std::string& firstIpAddr, const std::string& lastIpAddr) // iterate through the all range and ping every single ip address
{
	std::array<int, 4> firstIpAddrChunks, lastIpAddrChunks, currentIpAddrChunks;
	std::vector<std::string> upHosts;

	firstIpAddrChunks = getChunks(firstIpAddr);
	lastIpAddrChunks  = getChunks(lastIpAddr);

	IP tempIp;
	IP lastIp;
	int index = LAST_ARRAY_ELEMENT;
	for(unsigned int i = 0; i < 4; ++i) // assign to lastIP values in the opposite order 
	{
		lastIp.bytes[i] = lastIpAddrChunks[index];
		--index;
	}

	index = LAST_ARRAY_ELEMENT;
	for(unsigned int i = 0; i < 4; ++i) // assign to tempIP values in the opposite order
	{
		tempIp.bytes[i] = firstIpAddrChunks[index];
		--index;
	}

	int sockfd;
	if (getuid())
        sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    else
        sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if(sockfd == -1)
        return;

	while (tempIp.data != lastIp.data) // ping all ip addresses of the range
	{
		index = LAST_ARRAY_ELEMENT;
		for(unsigned int i = 0; i < 4; ++i)
		{
			currentIpAddrChunks[i] = tempIp.bytes[index];
			--index;
		}
		foundHost(currentIpAddrChunks, upHosts, sockfd);
		++tempIp.data;
	}	

	if(!upHosts.empty()) // if at least an up host is found 
	{
		for(unsigned int i = 0; i < upHosts.size(); ++i)
			std::cout << SET_BOLD_GREEN(<< upHosts[i] << " is up!\n");
	}
	else
		std::cout << SET_BOLD_RED("No up host!\n");
}

void printUsage()
{
	throw std::runtime_error("Please do not use in military, secret service organizations, or for illegal purposes.\n"
					   		 "Syntax: ./HostDiscover [ Ipv4 address ] [ Netmask ]\n"
					   		 "	./HostDiscover [ Ipv4 address ]/[ Netmask ]");
}

int main(int argc, char *argv[])
{		
	std::vector<std::string> arguments;	
	if(argc > 1) arguments.assign(argv, argv + argc);

	try
	{		
		if(argc == 1)
		{
			printUsage();
		}
		else if(argc == 2)
		{
			size_t nPointsIP = std::count(arguments[1].begin(), arguments[1].end(), '.');
			size_t nSlashes = std::count(arguments[1].begin(), arguments[1].end(), '/');
			if (nPointsIP != 3 || nSlashes != 1 || arguments[1].size() < 12)
				printUsage();
		}
		else if(argc == 3)
		{
			size_t nPointsIP = std::count(arguments[1].begin(), arguments[1].end(), '.');
			size_t nPointsNetmask = std::count(arguments[2].begin(), arguments[2].end(), '.');
			if(nPointsIP != 3 || arguments[1].size() < 9 || arguments[2].size() < 9)
				printUsage();
		}
	}
	catch (std::runtime_error const& e)
	{
		std::cout << SET_BOLD_RED(<< e.what() << "\n");
		return 1;
	}	

	std::pair<std::string, std::string> givenIpAddrAndMask;
	std::string givenIpAddr, givenNetmask;
	if(argc == 2) // CIDR notation used
	{
		givenIpAddrAndMask = separateIPfromCIDR(arguments[1]);
		givenIpAddr = givenIpAddrAndMask.first;
		givenNetmask = givenIpAddrAndMask.second;
	}
	else
	{
		givenIpAddr = arguments[1];
		givenNetmask = arguments[2];
	}
	
	std::cout << SET_BLUE("[ Entered ip address ] " << givenIpAddr << "\n");
	std::cout << SET_BLUE("[ Entered netmask ] " << givenNetmask << "\n");

	const std::string firstIpAddr = firstIpAddrRange(givenIpAddr, givenNetmask);
	std::cout << SET_BOLD_BLUE("[ Starting from ] " << firstIpAddr << "\n");
	const std::string lastIpAddr = lastIpAddrRange(firstIpAddr, givenNetmask);
	std::cout << SET_BOLD_BLUE("[ ...to ] " << lastIpAddr << "\n\n");
	
	// scan(firstIpAddr, lastIpAddr);

	return 0;
}