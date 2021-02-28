#include <stdio.h>
#include <errno.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "network.h"
#include "utils.h"

// Note that the messages must be of size 5 bytes
const char* THUB_INECTOR_SOCKET_TYPE_READER = "TISTR";
const char* THUB_OUTPUT_SOCKET_TYPE_CAPTURER = "TISTW";

void InitializeSSL()
{
	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();
}

void DestroySSL()
{
	ERR_free_strings();
	EVP_cleanup();
}

void ShutdownSSL(SSL* cSSL)
{
	SSL_shutdown(cSSL);
	SSL_free(cSSL);
}

SOCKET connectToServer(char* host, int port)
{
	SOCKET s;
	WSADATA wsa;
	struct sockaddr_in server;

	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		threadSafeFprintf(stderr, "Failed.Error Code : %d\n", WSAGetLastError());
		return INVALID_SOCKET;
	}

	//Create a socket
	if ((s = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
	{
		threadSafeFprintf(stderr, "Could not create socket : %d\n", WSAGetLastError());
		return INVALID_SOCKET;
	}

	server.sin_family = AF_INET;
	server.sin_port = htons((unsigned short)port);
	if (inet_pton(AF_INET, host, &server.sin_addr) != 1) {
		threadSafeFprintf(stderr, "Invalid host!\n");
		return INVALID_SOCKET;
	}

	//Connect to remote server
	if (connect(s, (struct sockaddr*) &server, sizeof(server)) < 0)
	{
		threadSafeFprintf(stderr, "Server connect error!\n");
		return INVALID_SOCKET;
	}

	return s;
}

SSL* wrapSocketSSL(SOCKET sock) {
	int sslConnectRetval;
	SSL* sslSock;
	SSL_CTX* sslctx;
	if ((sslctx = SSL_CTX_new(SSLv23_client_method())) != NULL) {
		if ((sslSock = SSL_new(sslctx)) != NULL) {
			if (SSL_set_fd(sslSock, sock)) {
				sslConnectRetval = SSL_connect(sslSock);
				if (sslConnectRetval) {
					SSL_CTX_free(sslctx);
					return sslSock;
				}
				else {
					threadSafeFprintf(stderr, "SSL connect error! Errornum: %d\n", SSL_get_error(sslSock, sslConnectRetval));
				}
				SSL_CTX_free(sslctx);
				ShutdownSSL(sslSock);
			}
			else {
				threadSafeFprintf(stderr, "Couldn't set SSL fd for socket!\n");
			}
		}
		else {
			threadSafeFprintf(stderr, "Couldn't create SSL object!\n");
		}
	}
	else {
		threadSafeFprintf(stderr, "Couldn't create SSL context!\n");
	}
	return NULL;
}

BOOLEAN ProcessPacket(char* packetData, int packetLen, SSL* ssl) {
	int retval = FALSE;
	int sendReturnCode = 0;
	int errCode;
	char strPacketLen[6] = { 0 };
	char* data;
	_itoa_s(packetLen, strPacketLen, sizeof(strPacketLen), 10);
	// First five bytes are to indicate the size, rest is the packet
	data = (char*)malloc(sizeof(char) * ( 5 * sizeof(char) + packetLen) );
	// Copy the data
	memcpy(data, strPacketLen, 5 * sizeof(char));
	memcpy(data + sizeof(char) * 5, packetData, packetLen * sizeof(char));
	// Send the data
	sendReturnCode = SSL_write(ssl, data, 5 + packetLen);
	if (sendReturnCode != SOCKET_ERROR) {
		retval = TRUE;
	}
	else {
		if ((errCode = (SSL_get_error(ssl, sendReturnCode)) != 5)) {
			threadSafeFprintf(stderr, "Socket (SSL) error: %d\n", errCode);
		}
		else {
			threadSafeFprintf(stderr, "Socket error: %d while writing\n", WSAGetLastError());
		}
	}
	free(data);
	return retval;
}

char* WaitForPacket(SSL* ssl, int* packetSize, int* returnValue, BOOLEAN* shouldQuit, HANDLE shouldQuitMutex)
/*
   Returns the packet that was read from the socket.
   **** Note that the user must free the returned buffer!
   * packetSize recieves the size of the packet sent.
   * returnValue recieves the return value of the funciton.
   * shouldQuit will cause the function to quit even if
   * shouldQuitMutex - An open handle to syncronize access to shouldQuit

   About the protocol: The first five bytes represent the size of the packet (As the maximum size is 65536). The rest is the packet.
   Therefore the flow is as follows:
   * Read the first 5 bytes, convert to int - That is the packet size
   * allocate the target packet
   * Read the packet into the buffer
*/
{
	char* packet;
	int expected_packet_size;
	int recv_size = 0;
	int totalBytesRead = 0;
	int socketErrorNum = 0;
	char strPacketLen[5] = { 0 };

	*returnValue = READ_SUCCESS;
	recv_size = SSL_read(ssl, strPacketLen, sizeof(strPacketLen));

	if (recv_size < 0)
	{
		if ((socketErrorNum = SSL_get_error(ssl, recv_size)) != 5) {
			*returnValue = socketErrorNum;
		}
		else {
			if ((socketErrorNum = WSAGetLastError()) == WSAETIMEDOUT) {
				*returnValue = READ_TIMEOUT;
			}
			else {
				*returnValue = socketErrorNum;
			}
		}
		return NULL;
	}

	if (recv_size == 0) {
		*returnValue = SOCKET_CLOSED;
		return NULL;
	}

	// Convert the packet size into int
	expected_packet_size = atoi(strPacketLen);
	packet = malloc(expected_packet_size * sizeof(char));

	// Read loop
	while ((recv_size != SOCKET_ERROR) && (totalBytesRead < expected_packet_size)) {
		recv_size = SSL_read(ssl, packet + totalBytesRead, expected_packet_size - totalBytesRead);
		if (recv_size > 0) {
			totalBytesRead += recv_size;
		}
		else {
			/* If we have recieved a timeout while reading a big packet halfway-through (probably due to high latency),
			continue trying to read the whole packet */
			if ((!syncGetShouldQuitValue(shouldQuit, shouldQuitMutex)) && (WSAGetLastError() == WSAETIMEDOUT)) {
				*returnValue = SSL_get_error(ssl, recv_size);
				recv_size = SOCKET_ERROR;
			}
		}
	}

	if (recv_size == SOCKET_ERROR)
	{
		free(packet);
		return NULL;
	}

	*packetSize = totalBytesRead;
	return packet;
}

BOOLEAN sendMessage(SSL* ssl, char* informMessage) {
	int returnValue;
	int errnum;
	// Note that we send 5 bytes and not 6 (no tailing \x00). That is why we use strlen and not sizeof.
	if ((returnValue = SSL_write(ssl, informMessage, strlen(informMessage))) == strlen(informMessage)) {
		return TRUE;
	}
	if ((errnum = SSL_get_error(ssl, returnValue)) != 5) {
		threadSafeFprintf(stderr, "Socket (SSL) error: %d\n", errnum);
	}
	else {
		threadSafeFprintf(stderr, "Socket error: %d while sending\n", WSAGetLastError());
	}
	return FALSE;
}

BOOLEAN informCapturer(SSL* ssl) {
	return sendMessage(ssl, THUB_OUTPUT_SOCKET_TYPE_CAPTURER);
}

BOOLEAN informInjector(SSL* ssl) {
	return sendMessage(ssl, THUB_INECTOR_SOCKET_TYPE_READER);
}
