#include "mac.h"
#include "ip.h"
struct SInterface{
    char* dev;
    char* description;
    Ip net;
    Ip mask;
    u_char* mac;
    Ip gateway;
    int metric;
    int best;
};
struct Route{
    Ip gateway;
    Ip mask;
    int metric;
    char* iface;
};
