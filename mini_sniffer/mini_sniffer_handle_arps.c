#include "mini_sniffer.h"
int handle_arps(const u_char *packet){

    const struct arphdr *arpheader;
    char buf[LOGBUFSIZE]={0};
    char tmpbuf[LOGBUFSIZE]={0};
    int i=0;
    char *ptr;
    char SMAC[20]={0};
    char TMAC[20]={0};
    char tmp[4]={0};


    print_eth_info(packet);
    arpheader=(struct arphdr *)(packet+SIZE_ETHERNET);
    //sprintf(buf,"Handle ARP protocols\n");
        switch(ntohs(arpheader->ar_op)){
            case ARPOP_REQUEST:
                ptr=arpheader->__ar_tha;
                printf("ARP Request PROTOCOL\n");
                while(i<ETH_ALEN){
                    printf("%x",arpheader->__ar_sha[i]);
                    sprintf(tmp,"%x",arpheader->__ar_sha[i]);
                    strncat(SMAC,tmp,strlen(tmp));
                        i++;
                    if(i<ETHER_ADDR_LEN){
                            strncat(SMAC,":",1);
                        }
                    }
                i=0;
                while(i<ETH_ALEN){
                    printf("%x",arpheader->__ar_tha[i]);
                    sprintf(tmp,"%x",arpheader->__ar_tha[i]);
                    strncat(TMAC,tmp,strlen(tmp));
                        i++;
                    if(i<ETHER_ADDR_LEN){
                            strncat(TMAC,":",1);
                        }
                    }

                sprintf(buf,"ARP REQUEST INFOMATION \nThe SMAC Address is:%s    The DMAC Address is:%s\n",SMAC,TMAC);
                sprintf(tmpbuf,"SOURCE IP :%s    DESTINATION IP :%s\n",inet_ntoa(arpheader->__ar_sip),inet_ntoa(arpheader->__ar_tip));
                break;
            case ARPOP_REPLY:
                printf("ARP Reply PROTOCOL\n");
                while(i<ETH_ALEN){
                    printf("%x",arpheader->__ar_sha[i]);
                    sprintf(tmp,"%x",arpheader->__ar_sha[i]);
                    strncat(SMAC,tmp,strlen(tmp));
                        i++;
                    if(i<ETHER_ADDR_LEN){
                            strncat(SMAC,":",1);
                        }
                    }
                i=0;
                while(i<ETH_ALEN){
                    printf("%x",arpheader->__ar_tha[i]);
                    sprintf(tmp,"%x",arpheader->__ar_tha[i]);
                    strncat(TMAC,tmp,strlen(tmp));
                        i++;
                    if(i<ETHER_ADDR_LEN){
                            strncat(TMAC,":",1);
                        }
                    }
                sprintf(buf,"ARP REPLY INFOMATION \nThe SMAC Address is:%s    The DMAC Address is:%s\n",SMAC,TMAC);
                sprintf(tmpbuf,"SOURCE IP :%s    DESTINATION IP :%s\n",inet_ntoa(arpheader->__ar_sip),inet_ntoa(arpheader->__ar_tip));
                break;
            case ARPOP_RREQUEST:
                printf("RARP Request PROTOCOL\n");
                while(i<ETH_ALEN){
                    printf("%x",arpheader->__ar_sha[i]);
                    sprintf(tmp,"%x",arpheader->__ar_sha[i]);
                    strncat(SMAC,tmp,strlen(tmp));
                        i++;
                    if(i<ETHER_ADDR_LEN){
                            strncat(SMAC,":",1);
                        }
                    }
                i=0;
                while(i<ETH_ALEN){
                    printf("%x",arpheader->__ar_tha[i]);
                    sprintf(tmp,"%x",arpheader->__ar_tha[i]);
                    strncat(TMAC,tmp,strlen(tmp));
                        i++;
                    if(i<ETHER_ADDR_LEN){
                            strncat(TMAC,":",1);
                        }
                    }
                sprintf(buf,"RARP REQUEST INFOMATION \nThe SMAC Address is:%s    The DMAC Address is:%s\n",SMAC,TMAC);
                sprintf(tmpbuf,"SOURCE IP :%s    DESTINATION IP :%s\n",inet_ntoa(arpheader->__ar_sip),inet_ntoa(arpheader->__ar_tip));
                break;
            case ARPOP_RREPLY:
                printf("RARP Reply PROTOCOL\n");
                while(i<ETH_ALEN){
                    printf("%x",arpheader->__ar_sha[i]);
                    sprintf(tmp,"%x",arpheader->__ar_sha[i]);
                    strncat(SMAC,tmp,strlen(tmp));
                        i++;
                    if(i<ETHER_ADDR_LEN){
                            strncat(SMAC,":",1);
                        }
                    }
                i=0;
                while(i<ETH_ALEN){
                    printf("%x",arpheader->__ar_tha[i]);
                    sprintf(tmp,"%x",arpheader->__ar_tha[i]);
                    strncat(TMAC,tmp,strlen(tmp));
                        i++;
                    if(i<ETHER_ADDR_LEN){
                            strncat(TMAC,":",1);
                        }
                    }
                sprintf(buf,"RARP REPLY INFOMATION \nThe SMAC Address is:%s    The DMAC Address is:%s\n",SMAC,TMAC);
                sprintf(tmpbuf,"SOURCE IP :%s    DESTINATION IP :%s\n",inet_ntoa(arpheader->__ar_sip),inet_ntoa(arpheader->__ar_tip));
                break;
            default:
                printf("NOT ARP PACKET\n");
                sprintf(buf,"NOT ARP PACKET\n");

        }

    strncat(buf,tmpbuf,strlen(tmpbuf));
    printf("buf is:\n %s \nsize is : %d\n",buf,strlen(buf));

    sniff_log(buf,strlen(buf));

    return 0;

}
