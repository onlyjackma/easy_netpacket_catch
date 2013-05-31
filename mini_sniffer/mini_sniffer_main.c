#include "mini_sniffer.h"
static int LOGFD;
u_int32_t TOTAL_FLOW;
u_int32_t TOTAL_PACKET=0;
int open_log_file(){
    LOGFD = open(LOGFILE,O_CREAT | O_RDWR | O_APPEND,0777);
    if(LOGFD<0){
        printf("open log file failed\n");
        return -1;
    }
    return 0;
}
int sniff_log(char *log_info,int info_size){
        int ret;

        ret = write(LOGFD,log_info,info_size);

      //  printf("write size is %d, and shou be write size is %d",ret,info_size);

        if(ret<0){
            printf("write log file failed\n");
            return -1;
        }
        if(ret==info_size){
                return 0;
        }
    return 0;
}

int print_pkthdr_info(const struct pcap_pkthdr *hdr){

        char logbuf[4096];

        memset(logbuf,0,4096);
        TOTAL_FLOW =TOTAL_FLOW + hdr->len;
       // printf("Packet length:%d\n",hdr->len);
       // printf("Sniffer time :%s\n",ctime((const time_t*)&hdr->ts.tv_sec));
       // printf("length of portion present:%d\n",hdr->caplen);
        sprintf(logbuf,"^^^^^^^^^^^^^^^^^^^^^^^^^^^ <<PACKET INFOMATION>> ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n"
                "Time : %sLength is : %d    Cap Length is : %d\n",ctime((const time_t*)&hdr->ts.tv_sec),hdr->len,hdr->caplen);
        printf("%sLenrth is : %d\n",logbuf,strlen(logbuf));
        sniff_log(logbuf,strlen(logbuf));
        return 0;

}

int print_eth_info(const u_char *packet){

        struct ether_header *eth_header;
        u_char *ptr;
        char SMAC[20]={0};
        char DMAC[20]={0};
        char tmp[4];
        int i;
        char logbuf[LOGBUFSIZE]={0};

        eth_header = (struct ether_header *)packet;
        i=0;
        ptr = eth_header->ether_dhost;

        while(i<ETHER_ADDR_LEN){
            //printf(" %x ",*ptr);
            sprintf(tmp,"%x",*ptr++);
            strncat(DMAC,tmp,strlen(tmp));
            i++;
            if(i<ETHER_ADDR_LEN){
                strncat(DMAC,":",1);
                }

        }
        i=0;
        ptr = eth_header->ether_shost;
       // printf("destination address(MAC):");
        while(i<ETHER_ADDR_LEN){
            sprintf(tmp,"%x",*ptr++);
            strncat(SMAC,tmp,strlen(tmp));
            i++;
            if(i<ETHER_ADDR_LEN){
                strncat(SMAC,":",1);
                }

        }
       // printf("\n--------------------------%s\n",SMAC);
        sprintf(logbuf,"The SMAC Address is:%s    The DMAC Address is:%s\n",SMAC,DMAC);
        printf("\nlogbuf is :%s\n",logbuf);
        sniff_log(logbuf,strlen(logbuf));

        return 0;


}

int print_ip_info(const u_char *packet){

        const struct iphdr *ipheader;
        u_char *tt = packet + SIZE_ETHERNET;
        char logbuf[LOGBUFSIZE]={0};
        ipheader = (struct iphdr *)tt;
       // printf("\nip head length %d\n",(ipheader)->ihl * 4);
       // printf("ip total length %d\n",ntohs(ipheader->tot_len));
       // printf("ip source ip:%s\n",inet_ntoa(ipheader->saddr));
       // printf("ip destination ip:%s\n",inet_ntoa(ipheader->daddr));
       // printf("ip protocl:%d\n",ipheader->protocol);
        //printf("ip protocl:%d\n",IPPROTO_UDP);
        sprintf(logbuf,"IP Total Length :%d      IP Header Length :%d\n"
                       "Source IP: %s     Destination IP: %s\n"
                       "IP Protocol Code %d\n",ntohs(ipheader->tot_len),(ipheader)->ihl * 4,
                        inet_ntoa(ipheader->saddr),inet_ntoa(ipheader->daddr),ipheader->protocol);
        printf("%s\nlength is:%d\n",logbuf,strlen(logbuf));
        sniff_log(logbuf,strlen(logbuf));
        return 0;

}




void handle_packets(u_char *user, const struct pcap_pkthdr *hdr, const u_char *packet){

        struct ether_header *eth_header;
        u_char *ptr;
        const struct iphdr *ipheader;
        u_int16_t size_ip;
        char logbuf[LOGBUFSIZE]={0};
        char buf[LOGBUFSIZE]={0};
        print_pkthdr_info(hdr);
        eth_header=(struct ether_header *)packet;
        TOTAL_PACKET++;
//print_eth_info(packet);
    if(ntohs(eth_header->ether_type)==ETHERTYPE_APR){
           // printf("handle ARP packet\n");
            handle_arps(packet);

        }
    else if(ntohs(eth_header->ether_type)==ETHERTYPE_IP){

        ptr=packet+SIZE_ETHERNET;
        ipheader=(struct iphdr *)ptr ;
        size_ip=ipheader->ihl * 4;
        //printf("ip protocl is :%d\n",ipheader->protocol);

        switch(ipheader->protocol){

            case IPPROTO_TCP:
                printf("TCP\n");
                handle_tcps(packet,ntohs(ipheader->tot_len),size_ip);
                break;
            case IPPROTO_UDP:
                printf("UDP\n");
                handle_udps(packet,size_ip);
                break;
            case IPPROTO_IP:
                printf("IP\n");
                handle_others(packet,"Protocol:IP");
                break;
            case IPPROTO_ICMP:
                printf("ICMP\n");
                handle_icmp(packet,ntohs(ipheader->tot_len),size_ip);
                break;
            case IPPROTO_IGMP:
                printf("IGMP\n");
                handle_igmp(packet,ntohs(ipheader->tot_len),size_ip);
                break;
            case IPPROTO_ROUTING:
                printf("ROUTING\n");
                handle_others(packet,"Protocol:ROUTING");
                break;
            default:
                handle_others(packet,"Protocol:UNKNOWN Protocol");


        }
    }else{

        printf("Other ethernet protocols\n");
    }
    sprintf(logbuf,"The Total Packets is :%d    The Total Flow is :%5d byte\n",TOTAL_PACKET,TOTAL_FLOW);
    printf("%s",logbuf);
    sniff_log(logbuf,strlen(logbuf));
     sleep(1);

}
void mini_sniffer_usage(char *param){
    printf("        Please Read The Infomations Below\n");
    printf("%s                      :Catch all the  packets\n",param);
    printf("%s ip                   :Catch all the ip packets\n",param);
    printf("%s tcp                  :Catch all the tcp packets\n",param);
    printf("%s udp                  :Catch all the udp packets\n",param);
    printf("%s \"tcp/udp port\"     :Catch all the tcp/udp:port packets\n",param);
    printf("%s \"ip host x.x.x.x\"  :Catch all the packets from the x.x.x.x\n",param);
    return 0;


}

int main(int argc,char *argv[]){

        pcap_t *sniffer_des;
        char errbuf[PCAP_ERRBUF_SIZE];
        char *net_dev;
        bpf_u_int32 netp;
        bpf_u_int32 maskp;
        struct bpf_program fp;
        char filter_exp[128]={0};
        int flag;
        if(argc > 2){
            mini_sniffer_usage(argv[0]);
            return 1;
        }
        strncpy(filter_exp,argv[1],strlen(argv[1]));
        flag=open_log_file();
        if(flag<0){
            printf("open log file error");
            return -1;
        }
        net_dev = pcap_lookupdev(errbuf);
        if(net_dev == NULL){
            printf("cannot get the network device info: %s\n",errbuf);
            return 1;
        }

        if(pcap_lookupnet(net_dev,&netp,&maskp,errbuf)==-1){
            printf("cannot get the network device ip info %s\n",errbuf);
            return 1;
        }

        sniffer_des = pcap_open_live(net_dev,65535,1,10000,errbuf);
        if(sniffer_des == NULL){
            printf("cannot open the network device:%s\n",errbuf);
            return 1;
        }

        if(pcap_compile(sniffer_des,&fp,filter_exp,0,maskp)==-1){
            printf("cannot compile the filter rule\n");
            return 1;
        }
        if(pcap_setfilter(sniffer_des,&fp)==-1){
            printf("cannot set the filter to the network device\n");
            return 1;
        }
        int ret = pcap_loop(sniffer_des,-1,handle_packets,NULL);

        if(ret==-1||ret==-2){
            printf("can not get packets\n");
            return 1;
        }
    close(LOGFD);
        printf("Going to shutdown the program!!\n");

        return 0;

}

