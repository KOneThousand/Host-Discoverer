//******************************************************
// Filename: HostDiscoverer.cpp
// Purpose:  Scan of local networks
// Author:   KOneThousand; 
// Date:     October 21, 2021
//******************************************************

#include <iostream>
#include <string>
#include <vector>
#include <array>
#include <cmath>
#include <algorithm>

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

int countPoints(const std::vector<std::string>& arguments, const int &argvIndex)
{
	// return the number of points of the entered ip or netmask
	return std::count(std::begin(arguments[argvIndex]), std::end(arguments[argvIndex]), '.'); 
}

int countSlashes(const std::vector<std::string>& arguments, const int &argvIndex)
{
	// return the number of slashes of the entered ip or netmask
	return std::count(std::begin(arguments[argvIndex]), std::end(arguments[argvIndex]), '/'); 
}

std::string decimalToBinary(int decimalNum)
{
	std::string binaryNum;
	unsigned int reminder;
	while(decimalNum > 0)
	{
		reminder = decimalNum % 2;
		binaryNum += (reminder + '0'); // conversion int to char
		decimalNum /= 2;
	}	
	binaryNum.resize(8, '0'); // replace with zeros the empty characters
	                          // until the 8th character
	return binaryNum; 
}

std::string oppositeBinNum(std::string binaryNum) // opposite binary number
{
	for (unsigned int i = 0; i < binaryNum.length(); ++i)
	{	
		if (binaryNum[i] == '1')
		{
			binaryNum[i] = '0';
		}
		else
		{
			binaryNum[i] = '1';
		}
	}

	return binaryNum;
}

int binaryToDecimal(const std::string& binaryNum)
{
	unsigned int result = 0;
	for (unsigned int i = 0; i < binaryNum.length(); ++i)
	{	
		if (binaryNum[i] == '1')
		{
			result += pow(2, i);
		}
	}

	return result;
}

std::array<std::string, 2> separateIPfromCIDR(const std::string CIDR)
{
	std::array<std::string, 2> ipAndMask;
	ipAndMask[0].assign(CIDR, 0, CIDR.find('/')); // strip out the ip address
	std::string CIDRMask;
	CIDRMask.assign(CIDR, (CIDR.find('/') + 1), 2); // strip out the CIDR Netmask
	unsigned int int_CIDRMask = stoi(CIDRMask);

	/* CALCULATE THE NETMASK FROM CIDR NOTATION */
	std::array<std::string, 4> binNetmask;
	unsigned int index = 0;
	while(int_CIDRMask > 7)
	{
		int_CIDRMask -= 8;
		binNetmask[index].resize(8, '1'); // fill the chunk with 1's
		index++;
	}

	if(int_CIDRMask > 0)
	{
		binNetmask[index].resize(int_CIDRMask, '1'); // add a number of 1's equal to int_CIDRMask
	}

	for(unsigned int i = 0; i < ARRAY_CHUNKS_LEN; ++i)
	{
		binNetmask[i].resize(8, '0'); // replace with zeros the empty characters
									  // until the 8th character
	}
	std::string netmask;
	for(unsigned int i = 0; i < ARRAY_CHUNKS_LEN; ++i)
	{
		std::string revTemp;
		for(int j = 7; j >= 0; --j)
		{
			revTemp += binNetmask[i][j]; // reverse the binary netmask chunk
		}

		std::string decimalTemp = std::to_string(binaryToDecimal(revTemp));

		if(i < 3)
		{
			netmask += (decimalTemp + '.');
		}
		else
		{
			netmask += decimalTemp;
		}
	}

	ipAndMask[1] = netmask; // return the ip address and the netmask in CISCO notation

	return ipAndMask;
}

std::array<int, 4> getChunks(const std::string &chunksToDivide) // fill an array with the numbers between the points
{
	std::array<std::string, 4> str_Chunks;

	int arrayIndex = 0, strIndex = 0;
	for(unsigned int i = 0; i < ARRAY_CHUNKS_LEN; ++i)
	{
		while (chunksToDivide[strIndex] != '.' && strIndex < chunksToDivide.length())
		{	
			str_Chunks[arrayIndex] += chunksToDivide[strIndex];
			++strIndex;
		}
		++strIndex;
		++arrayIndex;
	}

	std::array<int, 4> int_Chunks;
	for (unsigned int i = 0; i < ARRAY_CHUNKS_LEN; ++i)
	{
		int_Chunks[i] = stoi(str_Chunks[i]);
	} 

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
		std::string binNetmaskChunk = decimalToBinary(int_netmaskChunks[i]); // convert the netmask chunk from decimal to binary
		std::string oppBinNetmaskChunk = oppositeBinNum(binNetmaskChunk); // calculate the opposite of the binary netmask chunk
		int oppDecimalNetmaskChunk = binaryToDecimal(oppBinNetmaskChunk); // convert the opposite of the netmask chunk from binary to decimal
		
		unsigned int tempCalc = oppDecimalNetmaskChunk | int_firstIpAddrChunks[i]; // bitwise OR operation
		if (i < 3)
		{
			lastIpAddr += std::to_string(tempCalc) + ".";
		}
		else
		{
			lastIpAddr += std::to_string(tempCalc - 1); // remove broadcast ip address 
		}
	}

	return lastIpAddr;
}

std::string mergeChunks(const int fstChunk, const int sndChunk, const int trdChunk, const int fthChunk) // merge the given 				
{																																		  // chunks into a unique string 
	std::string currentIpAddr = std::to_string(fstChunk) + "." + std::to_string(sndChunk) + "." +
								std::to_string(trdChunk) + "." + std::to_string(fthChunk);
	return currentIpAddr;
}

constexpr unsigned int PING_PKT_S   = 64;  // Define the Packet Constants ping packet size
constexpr unsigned int RECV_TIMEOUT = 10;  // timeout delay for receiving packets in secs

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
	
	if (send_ping(currentIpAddr.data(), sockfd, pckt, r_addr)) // if the send_ping function is able to ping the host
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
    {
        sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    }
    else
    {
        sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    }

    if(sockfd == -1)
    {
        return;
    }

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
		{
			std::cout << SET_BOLD_GREEN(<< upHosts[i] << " is up!\n");
		}
	}
	else
	{
		std::cout << SET_BOLD_RED("No up host!\n");
	}
}

int main(int argc, char *argv[])
{	
	std::vector<std::string> arguments(argv, argv + argc);

	try
	{	
		if(argc == 1)
		{
			std::runtime_error("No arguments passed. For more info use \"./HostDiscover help\"");
		}

		if(argc == 2)
		{
			if (arguments[1] == "help")
			{
				std::runtime_error("Please do not use in military, secret service organizations, or for illegal purposes.\n"
								  		"Syntax: ./HostDiscover [ Ipv4 address ] [ Netmask ] or\n"
								  		"./HostDiscover [ Ipv4 address ]/[ Netmask ]");
			}

			if (countPoints(arguments, 1) != 3 && arguments[1] != "help")
			{
				std::runtime_error("Wrong usage!\n"
										"Ex: ./HostDiscover [ Ipv4 address ]/[ Netmask ] --> 192.168.179.128/24\n"
								  		"For more info use \"./HostDiscover help\"");
			}

			if (countSlashes(arguments, 1) == 0 && arguments[1] != "help")
			{
				std::runtime_error("Wrong usage!\n"
										"Ex: ./HostDiscover [ Ipv4 address ]/[ Netmask ] --> 192.168.179.128/24\n"
								  		"For more info use \"./HostDiscover help\"");
			}

			if (countSlashes(arguments, 1) > 1 && arguments[1] != "help")
			{
				std::runtime_error("Wrong usage!\n"
										"Ex: ./HostDiscover [ Ipv4 address ]/[ Netmask ] --> 192.168.179.128/24\n"
								  		"For more info use \"./HostDiscover help\"");
			}

			if (countPoints(arguments, 1) != 3 || arguments[1].size() < 9 && arguments[1] != "help")
			{
				std::runtime_error("Wrong! Correct form: x.x.x.x/x");
			}
		}

		if(argc > 2)
		{
			if (argc > 3 && arguments[1] != "help")
			{
				std::runtime_error("Wrong usage!\n"
										"Ex: ./HostDiscover [ Ipv4 address ] [ Netmask ] --> 192.168.179.128 255.255.255.0\n"
								  		"For more info use \"./HostDiscover help\"");
			}

			if (countPoints(arguments, 1) != 3 && countPoints(arguments, 2) != 3 && arguments[1] != "help")
			{
				std::runtime_error("Wrong usage!\n"
										"Ex: ./HostDiscover [ Ipv4 address ] [ Netmask ] --> 192.168.179.128 255.255.255.0\n"
								  		"For more info use \"./HostDiscover help\"");
			}

			if (countPoints(arguments, 1) != 3 || arguments[1].size() < 7 && arguments[1] != "help")
			{
				std::runtime_error("Wrong address Ipv4 format! Correct Ipv4 address form: x.x.x.x");
			}

			if (countPoints(arguments, 2) != 3 || arguments[2].size() < 7 && arguments[1] != "help")
			{
				std::runtime_error("Wrong Netmask format! Correct Netmask form: x.x.x.x");
			}
		}
	}
	catch (std::runtime_error const& e)
	{
		std::cout << SET_BOLD_RED(<< e.what() << "\n");
		return 1;
	}	

	std::array<std::string, 2> givenIpAddrAndMask;
	std::string givenIpAddr, givenNetmask;
	if(argc == 2) // CIDR notation used
	{
		givenIpAddrAndMask = separateIPfromCIDR(arguments[1]);
		givenIpAddr = givenIpAddrAndMask[0];
		givenNetmask = givenIpAddrAndMask[1];
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
	
	scan(firstIpAddr, lastIpAddr);

	return 0;
}