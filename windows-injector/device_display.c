#include <stdio.h>
#include <winsock2.h> //need winsock for int and u_char in pcap.h
#define HAVE_REMOTE
#include <pcap.h> //Winpcap

#include "device_display.h"
#include "utils.h"

#pragma comment(lib, "wpcap.lib") //For winpcap
#pragma comment(lib, "ws2_32.lib") //For winsock

//#define IPTOSBUFFERS    12
enum displayInterfacesRetvals
{
    SUCCESS,
    NO_INTERFACES_FOUND,
    WINPCAP_NOT_INSTALLED
};

char* iptos(u_long in)
{
    /*
        Converts the input u_long to a decimal IP address.
        Note that if the returned value isn't NULL, the user must free it after use.
    */
    u_char* p;
    char* decimalIP;
    int decimalIPLen = 3 * 4 + 3 + 1; //4 3-digit nunmbers + 3 dots + \x00
    int decimaLIPCharCount = decimalIPLen - 1; //4 3-digit nunmbers + 3 dots and no tailing \x00

    decimalIP = malloc(sizeof(char) * (decimalIPLen));
    if (decimalIP != NULL) {
        p = (u_char*)&in;
        _snprintf_s(decimalIP, sizeof(char) * (decimalIPLen), decimaLIPCharCount, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    }
    return decimalIP;
}

char* ip6tos(struct sockaddr* sockaddr)
{
    /*
        Converts the input u_long to a IPv6 address.
        Note that if the returned value isn't NULL, the user must free it after use.
    */
    char* address;
    int addrlen = 50;
    socklen_t sockaddrlen;

    address = malloc(sizeof(char) * addrlen);
    sockaddrlen = sizeof(struct sockaddr_in6);

    if (getnameinfo(sockaddr, sockaddrlen, address, addrlen, NULL, 0, NI_NUMERICHOST) != 0) {
        free(address);
        return NULL;
    }

    return address;
}

int displayInterfaces()
{
    int i;
    BOOLEAN should_break = FALSE;
    u_char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs, * d;
    struct pcap_addr* address;
    char* printableAddr;
    char ip6str[128] = { 0 };

    threadSafeFprintf(stdout, "Enamurating Devices:\n");

    /* Retrieve the local device list */
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        threadSafeFprintf(stderr, "*** FATAL! Error in pcap_findalldevs_ex: %s\n", errbuf);
        return NO_INTERFACES_FOUND;
    }

    i = 0;
    /* Print the list */
    for (d = alldevs; d; d = d->next)
    {
        threadSafeFprintf(stdout, "%d. ", ++i);

        if (d->description)
        {
            threadSafeFprintf(stdout, "%s\n", d->description);
        }
        else
        {
            threadSafeFprintf(stdout, "No description available.\n");
        }

        if (d->addresses) {
            for (address = d->addresses; address; address = address->next) {
                if (address->addr) {
                    printableAddr = NULL;
                    should_break = FALSE;
                    switch (address->addr->sa_family)
                    {
                    case AF_INET:
                        printableAddr = iptos(((struct sockaddr_in*)address->addr)->sin_addr.s_addr);
                        break;
                    case AF_INET6:
                        printableAddr = ip6tos(address->addr);
                        break;
                    default:
                        threadSafeFprintf(stdout, "\tError in address enumuration!\n");
                        should_break = TRUE;
                        break;
                    }
                    if (should_break) {
                        continue;
                    }
                    if (printableAddr != NULL) {
                        threadSafeFprintf(stdout, "\tAddress: %s\n", printableAddr);
                        free(printableAddr);
                    }
                    else {
                        threadSafeFprintf(stdout, "\tError translating IP address!\n");
                    }
                }
            }
        }
        else {
            threadSafeFprintf(stdout, "No Addresses found.\n");
        }

        threadSafeFprintf(stdout, "\t%s\n", d->name);
    }

    if (i == 0)
    {
        threadSafeFprintf(stderr, "No interfaces found!\n");
        return NO_INTERFACES_FOUND;
    }
    return SUCCESS;
}