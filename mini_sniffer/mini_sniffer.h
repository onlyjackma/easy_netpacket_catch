#include<stdio.h>
#include<stdlib.h>
#include<pcap.h>
#include<netinet/if_ether.h>
#include<netinet/ip.h>
#include<netinet/igmp.h>
#include<linux/icmp.h>
#include<netinet/in.h>
#include<sys/types.h>
#include<string.h>
#include<fcntl.h>
#include<sys/stat.h>
#include<net/if_arp.h>
#include<sys/socket.h>
#define __FAVOR_BSD
#include<netinet/udp.h>
#define __BYTE_ORDER __LITTLE_ENDIAN
#include<netinet/tcp.h>

#define SIZE_ETHERNET 14
#define SIZE_UDPHDR 8
#define LOGBUFSIZE 4096

#define ETHERTYPE_APR 0x0806

#define LOGFILE  "/var/log/sniffer.log"



void print_datas(const u_char *pdatas,int dlen);
int handle_arps(const u_char *packet);
int sniff_log(char *log_info,int info_size);
int print_ip_info(const u_char *packet);
int print_pkthdr_info(const struct pcap_pkthdr *hdr);
int handle_udps(const u_char *packet,u_int16_t size_iph);
int handle_tcps(const u_char *packet,u_int16_t size_ipt,u_int16_t size_iph);
int handle_icmp(const u_char *packet,u_int16_t size_ipt,u_int16_t size_iph);
int handle_igmp(const u_char *packet,u_int16_t size_ipt,u_int16_t size_iph);
int handle_others(const u_char *packet, u_char *protocol);
