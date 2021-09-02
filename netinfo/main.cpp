#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "SInterface.h"
#include "header.h"
#include "ip.h"
#include <list>
#include <iostream>

using namespace std;
int command(list<struct SInterface> lt,int cnt){
    char buff[1024];
    FILE *fp = popen("route -n | awk '{print $2, $3, $5, $8}'","r");

    if(fp == NULL){
        perror("popen() fail");
        return -1;
    }

    int j = 0;
    char* token;
    list<struct Route> route;
    list<struct SInterface>::iterator iter;
    while(fgets(buff,1024,fp)){
        if(j++<2)continue;
        struct Route tmp;

        token = strtok(buff," ");
        tmp.gateway = Ip(token);

        token = strtok(NULL," ");
        tmp.mask = Ip(token);

        token = strtok(NULL," ");
        tmp.metric = atoi(token);

        token = strtok(NULL," ");
        tmp.iface = token;


        for(iter = lt.begin(); iter!= lt.end(); iter++){
            if(iter->dev==tmp.iface&&tmp.gateway!=Ip("0.0.0.0"))
                iter->gateway = tmp.gateway;
        }
        route.push_back(tmp);
    }
    list<struct Route>::iterator riter;
    route.remove_if(riter->mask&riter->gateway!=riter->gateway&Ip("8.8.8.8"));

    int index = 0,final =0;
    Ip win = route.begin()->mask;
    for(riter = route.begin(); riter!= route.end(); riter++){
        if(win<riter->mask) final = index;
        index++;
    }

    auto it = route.begin();
    advance(it,final);
    for(iter = lt.begin(); iter!= lt.end(); iter++){
        if(iter->dev == it->iface){
            iter->best = 100;
        }
    }

    fclose(fp);
    return 0;
}
int main(int argc, char **argv){
        char *dev;
        char *net;
        char *mask;
        int ret = 0, i = 0, inum = 0;
        pcap_if_t *alldevs;
        pcap_if_t *d;
        char errbuf[PCAP_ERRBUF_SIZE];
        bpf_u_int32 netp;
        bpf_u_int32 maskp;
        struct in_addr addr;
        ret = pcap_findalldevs(&alldevs, errbuf);
        if (ret == -1){
                printf("pcap_findalldevs: %s\n", errbuf);
                exit(1);
        }
        list<struct SInterface> lt;

        for(d = alldevs; d; d = d->next){
            struct SInterface interface;
            if (d->description)
                interface.description = d->description;
            ret = pcap_lookupnet(d->name, &netp, &maskp, errbuf);

            if (ret == -1)continue;

            addr.s_addr = netp;
            net = inet_ntoa(addr);

            if (net == NULL){
                perror("inet_ntoa");
            }

            u_char* tmp = getMacAddress(d->name);

            addr.s_addr = maskp;
            mask = inet_ntoa(addr);

            if (mask == NULL){
                perror("inet_ntoa");
                exit(1);
            }
            interface.dev=d->name;
            interface.mask=Ip(mask);
            interface.net=Ip(net);
            interface.mac = tmp;
            lt.push_back(interface);
        }
        command(lt,lt.size());
        list<struct SInterface>::iterator iter;
        for(iter = lt.begin(); iter!= lt.end(),iter->best==100; iter++){
            printf("index %d \n    %s / ", 1, iter->dev,iter->description);
            printf("mac:");
            for(int i =0;i <5; i++)
                printf("%x:",iter->mac[i]);
            printf("%x ",iter->mac[5]);
            printf("ip:%x ",iter->net);
            printf("mask:%x ",iter->mask);
            printf("gateway:%x\n\n",iter->gateway);
        }


        pcap_freealldevs(alldevs);
        return 0;
}
