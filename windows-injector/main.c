#include <stdio.h>
#include <winsock2.h> //need winsock for inet_ntoa and ntohs methods
#include <windows.h>
#include <openssl/err.h>

#define HAVE_REMOTE
#include <pcap.h> //Winpcap

#pragma comment(lib , "wpcap.lib") //For winpcap
#pragma comment(lib , "ws2_32.lib") //For winsock
#pragma comment(lib, "libssl.lib") //For libssl
#pragma comment(lib, "libcrypto.lib") //For libssl

#include "network.h"
#include "utils.h"
#include "device_display.h"

enum RETURN_CODES
{
    SUCCESS,
    BAD_USER_INPUT,
    INIT_DEVICES_ERROR,
    BAD_BPF_FILTER,
    SERVER_INIT_CONNECTION_ERROR,
    CAPTURE_ERROR,
    ADAPTER_OPEN_ERROR,
    SEND_ERROR,
    INJECTION_ERROR,
    MUTEX_ERROR,
    HANDLER_ERROR,
    SSL_WRAP_ERROR
};

const int MAX_PACKET_SIZE = 65536;
const int CAPTURE_TIMEOUT_MS = 1000; // One second
const DWORD SOCKET_READ_TIMEOUT_MS = 1000; // One second
const LPCWSTR SHOULD_QUIT_MUTEX_NAME = L"SHOULD_QUIT_MUTEX";
const char BPF_FILTER_START[] = "not (ip host ";
const char BPF_FILTER_PART_2[] = " and port ";
// USAGE
const char* USAGE_FORMAT = "%s\n%s %s\n\t%s\n\t%s\n\t%s\n\t%s\n";
const char* USAGE_TITLE = "THUB - USAGE:";
const char* USAGE_LINE_1 = "[-d | -i <TARGET_INTERFACE> -s <SERVER_IP> -p <SERVER_PORT>]";
const char* USAGE_LINE_2 = "-d Enumerate capturable devices";
const char* USAGE_LINE_3 = "-i Interface number to capture on. Can be derieved from '-d'";
const char* USAGE_LINE_4 = "-s THUB-Server IP";
const char* USAGE_LINE_5 = "-p THUB-Server port";

// The varraible is global so it would be accessible by the KeyboardInterruptHandler
BOOLEAN shouldQuit;

BOOLEAN WINAPI KeyboardInterruptHandler(_In_ DWORD dwCtrlType) {
    HANDLE shouldQuitFlagMutex;

    switch (dwCtrlType)
    {
    case CTRL_C_EVENT:
        threadSafeFprintf(stderr, "Keyboard Interrup caught! Exiting.\n");
        shouldQuitFlagMutex = CreateMutex(NULL, FALSE, SHOULD_QUIT_MUTEX_NAME);
        if (shouldQuitFlagMutex != NULL) {
            syncSetShouldQuitValue(&shouldQuit, shouldQuitFlagMutex, TRUE);
            CloseHandle(shouldQuitFlagMutex);
        }
        return TRUE;
    default:
        // Pass signal on to the next handler
        return FALSE;
    }
}

BOOLEAN isValidIpAddress(u_char* ipAddress)
{
    struct sockaddr_in s;
    s.sin_family = AF_INET;
    int result = inet_pton(AF_INET, ipAddress, &s.sin_addr);
    if (result != 1) {
        return FALSE;
    }
    return TRUE;
}

BOOLEAN parseUserInput(int argc, u_char* argv[], int* targetDevice, int* targetPort, int* serverHostPtr, BOOLEAN* shouldDisplayInterfaces) {
    int i;
    BOOLEAN isInputValid = FALSE;
    
    BOOLEAN isDeviceSet = FALSE;
    BOOLEAN isIpSet = FALSE;
    BOOLEAN isPortSet = FALSE;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-d")) {
            *shouldDisplayInterfaces = TRUE;
            return TRUE;
        }
        else {
            if (!strcmp(argv[i], "-i")) {
                if (!isDeviceSet) {
                    *targetDevice = atoi(argv[i + 1]);
                    i++;
                    isDeviceSet = TRUE;
                }
                else {
                     threadSafeFprintf(stderr, "-i provided twice!\n");
                    isDeviceSet = FALSE;
                    break;
                }
            }
            else {
                if (!strcmp(argv[i], "-p")) {
                    if (!isPortSet) {
                        *targetPort = atoi(argv[i + 1]);
                        i++;
                        isPortSet = TRUE;
                    }
                    else {
                         threadSafeFprintf(stderr, "-p provided twice!\n");
                        isPortSet = FALSE;
                        break;
                    }
                }
                else {
                    if (!strcmp(argv[i], "-s")) {
                        if (!isIpSet) {
                            *serverHostPtr = i + 1;
                            i++;
                            isIpSet = TRUE;
                        }
                        else {
                             threadSafeFprintf(stderr, "-s provided twice!\n");
                            isIpSet = FALSE;
                            break;
                        }
                    }
                    else {
                         threadSafeFprintf(stderr, "Unknown parameter: %s\n", argv[i]);
                        break;
                    }
                }
            }
        }
    }
    if (isDeviceSet && isIpSet && isPortSet) {
        if (*targetDevice <= 0) {
             threadSafeFprintf(stderr, "*** Target device is char!\n");
        }
        else {
            if ((*serverHostPtr != 0) && (!isValidIpAddress(argv[*serverHostPtr]))) {
                 threadSafeFprintf(stderr, "*** Target IP is invalid!\n");
            }
            else {
                if (*targetPort <= 0) {
                     threadSafeFprintf(stderr, "*** Target Port is invalid!\n");
                }
                else {
                    isInputValid = TRUE;
                }
            }
        }
    }
    if (!isInputValid) {
         threadSafeFprintf(stderr, USAGE_FORMAT, USAGE_TITLE, argv[0], USAGE_LINE_1, USAGE_LINE_2, USAGE_LINE_3, USAGE_LINE_4, USAGE_LINE_5);
    }
    return isInputValid;
}

BOOLEAN jumpToDevice(pcap_if_t* device, int index) {
    /* Jump to the selected adapter */
    int i = 1;
    while (device->next != NULL && i < index) {
        *device = *device->next;
        i++;
    }
    if (i != index) { return FALSE; }
    return TRUE;
}

char* generateBPFFilter(char* serverIP, int serverPort)
/*
    Allocates a new string that contains the BFP_FILTER with the given IP.
    The filter is used then to filter out the program's communication with the control server.
    *** The user must free the returned value!
*/
{
    char strPort[6];
    memset(strPort, 0, sizeof strPort);
    int strPortLen = 0;
    int IPLen = strlen(serverIP);
    int bpf1Len = strlen(BPF_FILTER_START);
    int bpf2Len = strlen(BPF_FILTER_PART_2);
    sprintf_s(strPort, 6, "%d", serverPort);
    strPortLen = strlen(strPort);
    int filterLen = bpf1Len + IPLen + bpf2Len + strPortLen + 1 + 1;
    char* filter = malloc(sizeof(char) * filterLen);
    if (filter != NULL) {
        // Copy the begining of the BPF filter without the tailing \x00
        memcpy((void*)filter, (void*)BPF_FILTER_START, bpf1Len);
        // Copy the IP address
        memcpy((void*)(filter + bpf1Len), (void*)serverIP, IPLen);
        // Copy the second part of the BPF filter without the tailing \x00
        memcpy((void*)(filter + bpf1Len + IPLen), (void*)BPF_FILTER_PART_2, bpf2Len);
        // Copy the port and close with ')'
        memcpy((void*)(filter + bpf1Len + IPLen + bpf2Len), (void*)strPort, strPortLen);
        filter[bpf1Len + IPLen + bpf2Len + strPortLen] = ')';
        // Make sure the string has an ending \x00
        filter[bpf1Len + IPLen + bpf2Len + strPortLen + 1] = 0;
    }
    return filter;
}

struct injectionMainArguemts
{
    pcap_if_t* device;
    int targetDevice;
    char* serverIP;
    int serverPort;
    int* returnValue;
};

void injectionMain(LPVOID pArgs_) {
    struct injectionMainArguemts* arguments = (struct injectionMainArguemts*)pArgs_;
    char* packet;
    int packetLen = 0;
    int socketReadReturnValue = READ_SUCCESS;
    pcap_t* fp;
    SOCKET sock = INVALID_SOCKET;
    SSL* sslSocket = NULL;
    HANDLE shouldQuitFlagMutex;
    u_char errbuf[PCAP_ERRBUF_SIZE];

    // Get all function argumets - As it is initialized in a different thread
    pcap_if_t* device = arguments->device;
    int targetDevice = arguments->targetDevice;
    char* serverIP = arguments->serverIP;
    int serverPort = arguments->serverPort;

    // Create mutex to safely access the value of shouldQuit
    shouldQuitFlagMutex = CreateMutex(NULL, FALSE, SHOULD_QUIT_MUTEX_NAME);

    if (shouldQuitFlagMutex != NULL) {
        // Connect to server
        if ((sock = connectToServer(serverIP, serverPort)) != INVALID_SOCKET) {

            // Limit socket read
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&SOCKET_READ_TIMEOUT_MS, sizeof(SOCKET_READ_TIMEOUT_MS));

            if ((sslSocket = wrapSocketSSL(sock)) != NULL) {

                // Start captureing on Device
                if ((fp = pcap_open(device->name,
                    MAX_PACKET_SIZE /* snaplen */,
                    0 /* flags */,
                    CAPTURE_TIMEOUT_MS /* read timeout */,
                    NULL /* remote authentication */,
                    errbuf)
                    ) != NULL)
                {
                    // Inform server about socket type
                    if (informInjector(sslSocket)) {

                        while (!syncGetShouldQuitValue(&shouldQuit, shouldQuitFlagMutex)) {
                            // Set socket read Timeout
                            packet = WaitForPacket(sslSocket, &packetLen, &socketReadReturnValue, &shouldQuit, shouldQuitFlagMutex);
                            if (socketReadReturnValue == READ_SUCCESS) {
                                if (pcap_sendpacket(fp, packet, packetLen) != 0) {
                                    threadSafeFprintf(stderr, "Error while injecting packet: %s\n", pcap_geterr(fp));
                                    syncSetShouldQuitValue(&shouldQuit, shouldQuitFlagMutex, TRUE);
                                    *arguments->returnValue = INJECTION_ERROR;
                                }
                            }
                            else {
                                if (socketReadReturnValue == READ_TIMEOUT) {
                                    // Timeout reached
                                    continue;
                                }
                                else {
                                    threadSafeFprintf(stderr, "Error while reading from socket! Socket return code: %d\n", socketReadReturnValue);
                                    syncSetShouldQuitValue(&shouldQuit, shouldQuitFlagMutex, TRUE);
                                    *arguments->returnValue = socketReadReturnValue;
                                }
                            }
                            // Free the current packet and reset all the values
                            if (packet != NULL) {
                                free(packet);
                            }
                            packetLen = 0;
                            socketReadReturnValue = READ_SUCCESS;
                        }
                    }
                    else
                    {
                        threadSafeFprintf(stderr, "Error while sending socket type packet - Injector \n");
                        *arguments->returnValue = SEND_ERROR;
                    }
                }
                else {
                    threadSafeFprintf(stderr, "Error opening adapter %d: %s\n", targetDevice, errbuf);
                    *arguments->returnValue = ADAPTER_OPEN_ERROR;
                }
                // SSL socket cleanup
                ShutdownSSL(sslSocket);
            }
            else {
                threadSafeFprintf(stderr, "Could not wrap socket with SSL!\n");
                *arguments->returnValue = SSL_WRAP_ERROR;
            }

            // Socket Cleanup
            closesocket(sock);
        }
    }
    else {
        threadSafeFprintf(stderr, "Could not acquire mutex!\n");
        *arguments->returnValue = MUTEX_ERROR;
    }
}

int captureMain(pcap_if_t* device, int targetDevice, char* serverIP, int serverPort) {
    pcap_t* fp;
    SOCKET sock = INVALID_SOCKET;
    SSL* sslSocket = NULL;
    u_char* pkt_data;
    char* capture_filter;
    int retval = SUCCESS;
    int netmask = 0xffffff;
    struct pcap_pkthdr* header;
    HANDLE shouldQuitFlagMutex;
    int packetQueryResult = 0;
    struct bpf_program bpfBinary;
    u_char errbuf[PCAP_ERRBUF_SIZE];

    // Create mutex to safely access the value of shouldQuit
    shouldQuitFlagMutex = CreateMutex(NULL, FALSE, SHOULD_QUIT_MUTEX_NAME);

    if (shouldQuitFlagMutex != NULL) {
        // Connect to server
        if ((sock = connectToServer(serverIP, serverPort)) != INVALID_SOCKET) {

            if ((sslSocket = wrapSocketSSL(sock)) != NULL) {
                // Start captureing on Device
                if ((fp = pcap_open(device->name,
                    MAX_PACKET_SIZE /* snaplen */,
                    PCAP_OPENFLAG_PROMISCUOUS /* flags */,
                    CAPTURE_TIMEOUT_MS /* read timeout */,
                    NULL /* remote authentication */,
                    errbuf)
                    ) != NULL)
                {
                    // Set BPF Filter
                    if (device->addresses != NULL) {
                        netmask = ((struct sockaddr_in*)(device->addresses->netmask))->sin_addr.S_un.S_addr;
                    }
                    capture_filter = generateBPFFilter(serverIP, serverPort);
                    threadSafeFprintf(stdout, "The BPF Filter is %s\n", capture_filter);
                    if (pcap_compile(fp, &bpfBinary, capture_filter, TRUE, netmask) >= 0) {
                        if (pcap_setfilter(fp, &bpfBinary) != -1) {

                            // Inform server about socket type
                            if (informCapturer(sslSocket)) {

                                // Read packets in a loop
                                while ((!syncGetShouldQuitValue(&shouldQuit, shouldQuitFlagMutex)) && ((packetQueryResult = pcap_next_ex(fp, &header, &pkt_data)) >= 0))
                                {
                                    // If res is 0 - Timeout was reached
                                    if (packetQueryResult == 0) {
                                        continue;
                                    }
                                    if (!ProcessPacket(pkt_data, header->caplen, sslSocket)) {
                                        threadSafeFprintf(stderr, "Error while sending Packet!\n");
                                        retval = SEND_ERROR;
                                        break;
                                    }
                                }

                                if (packetQueryResult == -1)
                                {
                                    threadSafeFprintf(stderr, "Error reading the packets: %s\n", pcap_geterr(fp));
                                    retval = CAPTURE_ERROR;
                                }
                            }
                            else
                            {
                                threadSafeFprintf(stderr, "Error while sending socket type packet - Capturer\n");
                                retval = SEND_ERROR;
                            }
                        }
                        else {
                            threadSafeFprintf(stderr, "Failed Setting BPF Filter: %s\n", pcap_geterr(fp));
                            retval = BAD_BPF_FILTER;
                        }
                    }
                    else {
                        threadSafeFprintf(stderr, "Failed Setting BPF Filter: %s\n", pcap_geterr(fp));
                        retval = BAD_BPF_FILTER;
                    }
                    free(capture_filter);
                }
                else {
                    threadSafeFprintf(stderr, "Error opening adapter %d: %s\n", targetDevice, errbuf);
                    return ADAPTER_OPEN_ERROR;
                }
                // SSL socket cleanup
                ShutdownSSL(sslSocket);
            }
            else {
                threadSafeFprintf(stderr, "Could not wrap socket with SSL!\n");
                return SSL_WRAP_ERROR;
            }

            // Socket Cleanup
            closesocket(sock);
        }

        syncSetShouldQuitValue(&shouldQuit, shouldQuitFlagMutex, TRUE);

        // Mutex Cleanup
        CloseHandle(shouldQuitFlagMutex);
    }
    else {
        threadSafeFprintf(stderr, "Could not acquire mutex!");
        retval = MUTEX_ERROR;
    }
    return retval;
}

int main(int argc, char* argv[])
{
    int retval = SUCCESS;
    int injectionReturnValue = SUCCESS;
    pcap_if_t* alldevs, *device;
    u_char errbuf[PCAP_ERRBUF_SIZE];

    int targetDevice = 0;
    int serverIpIndex = 0;
    int serverPort = 0;
    BOOLEAN shouldDisplayInterfaces = FALSE;

    DWORD injectionThreadID;
    HANDLE injectionThread;
    struct injectionMainArguemts threadArgs;


    /* Validate the user input parameters */
    if (parseUserInput(argc, argv, &targetDevice, &serverPort, &serverIpIndex, &shouldDisplayInterfaces)) {

        if (shouldDisplayInterfaces) {
            return displayInterfaces();
        }

        /* Get all devices on system */
        if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) != -1)
        {
            if (alldevs != NULL) {
                // Back up alldevs to properly free later
                device = alldevs;

                if (jumpToDevice(device, targetDevice)) {
                    // Open the device
                     threadSafeFprintf(stdout, "Executing on interface: %s\n", device->name);

                    if (SetConsoleCtrlHandler(KeyboardInterruptHandler, TRUE))
                    {
                        threadArgs.device = device;
                        threadArgs.targetDevice = targetDevice;
                        threadArgs.serverIP = argv[serverIpIndex];
                        threadArgs.serverPort = serverPort;
                        threadArgs.returnValue = &injectionReturnValue;

                        InitializeSSL();
                        injectionThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)injectionMain, &threadArgs, 0, &injectionThreadID);

                        retval = captureMain(device, targetDevice, argv[serverIpIndex], serverPort);
                        if (injectionThread != NULL) {
                            WaitForSingleObject(injectionThread, INFINITE);
                            CloseHandle(injectionThread);
                        }
                        DestroySSL();
                        /* If the inectionThread failed and the capture succeded,
                        set the return value to be the injectionThread return value. */
                        if (retval == SUCCESS && injectionReturnValue != SUCCESS) {
                            retval = injectionReturnValue;
                        }
                        if (injectionReturnValue != SUCCESS) {
                             threadSafeFprintf(stdout, "Error on injection thread. Response code: %d\n", injectionReturnValue);
                        }
                    }
                    else {
                         threadSafeFprintf(stderr, "Could not register Keyboard Interrupt control handler!\n");
                        retval = HANDLER_ERROR;
                    }
                    WSACleanup();
                }
                else {
                     threadSafeFprintf(stderr, "Invalid Adapter %d!\n", targetDevice);
                    retval = BAD_USER_INPUT;
                }

                // Device varraibles Cleanup
                pcap_freealldevs(alldevs);
            }
            else {
                 threadSafeFprintf(stderr, "No interfaces found! Exiting.\n");
                retval = INIT_DEVICES_ERROR;
            }
        }
        else {
             threadSafeFprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
            retval = INIT_DEVICES_ERROR;
        }
    }
    else {
        retval = BAD_USER_INPUT;
    }
    return retval;
}