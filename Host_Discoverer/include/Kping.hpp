#pragma once

unsigned short checksum(void *b, int len);

void intHandler(int var);

char *dns_lookup(char *addr_host, struct sockaddr_in *addr_con);

bool send_ping(char* ipToPing, int sockfd, struct ping_pkt &pckt, struct sockaddr_in const &r_addr);
