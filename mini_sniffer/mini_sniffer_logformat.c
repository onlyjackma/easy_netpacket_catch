#include "mini_sniffer.h"

void format_log(const u_char *pdatas, int dlen, int offset){
    char tmpbuf[LOGBUFSIZE]={0};
    char logbuf[LOGBUFSIZE]={0};
    int i;
    int  gap;
    const u_char *dptr;

    printf("%05d   ",offset);
    sprintf(tmpbuf,"%05d   ",offset);
    strncat(logbuf,tmpbuf,strlen(tmpbuf));
    dptr=pdatas;

    for(i=0;i<dlen;i++){
        printf("%02x ",*dptr);
        sprintf(tmpbuf,"%02x ",*dptr);
        strncat(logbuf,tmpbuf,strlen(tmpbuf));
        dptr++;
        if(i==7){
            printf(" ");
            strncat(logbuf," ",strlen(" "));
        }
    }
    if(dlen < 8){
        printf(" ");
        strncat(logbuf," ",strlen(" "));
    }
    if(dlen<16){
        gap = 16-dlen;
        for(i=0;i<gap;i++){
            printf("   ");
            strncat(logbuf,"   ",strlen("   "));
        }
    }
    printf(" ");
    strncat(logbuf," ",strlen(" "));


    dptr=pdatas;
    for(i=0;i<dlen;i++){
        if(isprint(*dptr)){
            printf("%c",*dptr);
            sprintf(tmpbuf,"%c",*dptr);
            strncat(logbuf,tmpbuf,strlen(tmpbuf));
        }
        else{
            printf(".");
            strncat(logbuf,".",strlen("."));
        }
        dptr++;
        }

    printf("\n");
    strncat(logbuf,"\n",strlen("\n"));
    sniff_log(logbuf,strlen(logbuf));
    return;

}

void print_datas(const u_char *pdatas, int dlen){

    int left_len = dlen;
    int width = 16;
    int line_count;
    int offset = 0;
    const u_char *dptr=pdatas;

    if(dlen<0)
        return;

    if(dlen<=width){
        format_log(dptr,dlen,offset);
        return;
    }

    for(;;){

    line_count = width % left_len;
     // printf("******************line count is %d\n",line_count);
    format_log(dptr,line_count,offset);

    left_len -= line_count;
    dptr = dptr + line_count;
    offset += width;

        if(left_len <= width){
            format_log(dptr,left_len,offset);
            break;
        }

    }
    return ;
}
