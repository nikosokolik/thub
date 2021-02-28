#pragma comment(lib,"ws2_32.lib") //Winsock Library
#pragma comment(lib, "libssl.lib") //For libssl
#pragma comment(lib, "libcrypto.lib") //For libssl

enum socketReadReturnValues
{
	READ_SUCCESS,
	READ_TIMEOUT,
	SOCKET_CLOSED
};

SOCKET connectToServer(char* host, int port);

BOOLEAN ProcessPacket(char* packetData, int packetLen, SSL* ssl);

char* WaitForPacket(SSL* ssl, int* packetSize, int* returnValue, BOOLEAN* shouldQuit, HANDLE shouldQuitMutex);

BOOLEAN informCapturer(SSL* ssl);

BOOLEAN informInjector(SSL* ssl);

void InitializeSSL();

void DestroySSL();

void ShutdownSSL(SSL* cSSL);

SSL* wrapSocketSSL(SOCKET sock);
