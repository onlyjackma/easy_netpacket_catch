#include "mini_sniffer.h"

int handle_udps(const u_char *packet,u_int16_t size_iph){
    const struct udphdr *udpheader;
    char logbuf[LOGBUFSIZE]={0};
    char tmpbuf[LOGBUFSIZE]={0};
    int p_offset;
    u_char *tt;
    int i;
    int data_size;

        print_eth_info(packet);
        print_ip_info(packet);

        //printf("the ip protocl is UDP\n");
        p_offset=SIZE_ETHERNET + size_iph;
        udpheader=(struct udphdr *)(packet + p_offset);

       // printf("udp head length %d\n",ntohs(udpheader->uh_ulen));
       // printf("udp source is %d\n",ntohs(udpheader->uh_sport));
       // printf("udp destination is %d\n",ntohs(udpheader->uh_dport));
        sprintf(logbuf,"Protocol: UDP\nUDP Total Length :%d     UDP Data Length :%d\n"
                        "UDP Source Port :%d     UDP Destination Port :%d\n",
                        ntohs(udpheader->uh_ulen),ntohs(udpheader->uh_ulen)-SIZE_UDPHDR,
                        ntohs(udpheader->uh_sport),ntohs(udpheader->uh_dport));
        printf("%slength is %d\n",logbuf,strlen(logbuf));

        data_size = ntohs(udpheader->uh_ulen) - SIZE_UDPHDR;
        sniff_log(logbuf,strlen(logbuf));
        print_datas(packet + p_offset,data_size);
        return 0;
}

int handle_tcps(const u_char *packet,u_int16_t size_ipt,u_int16_t size_iph){

    const struct tcphdr *tcpheader;
    char logbuf[LOGBUFSIZE]={0};
    int data_size;
    int size_tcph;
    int offset;

    tcpheader = (struct tcphdr *)(packet+SIZE_ETHERNET+size_iph);
    print_eth_info(packet);
    print_ip_info(packet);

    printf("TCP Header Length is :%d\n",tcpheader->th_off * 4);
    size_tcph = tcpheader->th_off * 4;
    data_size = size_ipt-size_iph-size_tcph;
    sprintf(logbuf,"Protocol: TCP\nTCP Total Length :%d      TCP Data Length :%d\n"
                   "TCP Source Port :%d         TCP Destination Port :%d\n",
                   size_ipt-size_iph,data_size,
                   ntohs(tcpheader->th_sport),ntohs(tcpheader->th_dport));

    printf("%sLength is%d\n",logbuf,strlen(logbuf));
    sniff_log(logbuf,strlen(logbuf));
    offset = SIZE_ETHERNET+size_iph+size_tcph;
    print_datas(packet+offset,data_size);


    return 0;
}

int handle_icmp(const u_char *packet,u_int16_t size_ipt,u_int16_t size_iph){

    const struct icmphdr *icmpheader;
    char logbuf[LOGBUFSIZE]={0};
    int data_size;
    int size_icmph;
    int offset;

    print_eth_info(packet);
    print_ip_info(packet);

    icmpheader = (struct icmphdr *) (packet+SIZE_ETHERNET+size_iph);
    //printf("size of icmp %d\n",sizeof(struct icmphdr));
    size_icmph = sizeof(struct icmphdr);
    offset = SIZE_ETHERNET+size_iph + size_icmph;
    data_size = size_ipt-size_iph-size_icmph;
    sprintf(logbuf,"Ptotlcol: ICMP\n ICMP TYPE: %d    ICMP CODE %d\n"
            "ICMP ECHO %d\n",icmpheader->type,icmpheader->code,icmpheader->un);
    printf("%sLength is %d\n",logbuf,strlen(logbuf));
    sniff_log(logbuf,strlen(logbuf));
    print_datas(packet+offset,data_size);
    return 0;
}

int handle_igmp(const u_char *packet,u_int16_t size_ipt,u_int16_t size_iph){
    const struct igmp *igmphdr;
    char logbuf[LOGBUFSIZE]={0};
    int offset;
    char data_size;
    int size_igmp;

    size_igmp = sizeof(struct igmp);
    print_eth_info(packet);
    print_ip_info(packet);
    igmphdr = (struct igmp *)(packet+SIZE_ETHERNET+size_iph);
    offset = SIZE_ETHERNET+size_iph + size_igmp;
    data_size = size_ipt-size_iph-size_igmp;

    sprintf(logbuf,"Protocol: IGMP\nIGMP TYPE IS %d    IGMP CODE IS %d\n",igmphdr->igmp_type,igmphdr->igmp_code);
    printf("%s%d",logbuf,strlen(logbuf));
    sniff_log(logbuf,strlen(logbuf));
    print_datas(packet+offset,data_size);
    return 0;


}

int handle_others(const u_char *packet, u_char *protocol){
    char logbuf[LOGBUFSIZE]={0};
    print_eth_info(packet);
    print_ip_info(packet);

    sprintf(logbuf,"%s\n",protocol);
    printf("%s%d",logbuf,strlen(logbuf));
    sniff_log(logbuf,strlen(logbuf));
    return 0;
}
