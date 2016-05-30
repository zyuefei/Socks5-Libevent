#ifndef _TURN_CLENT_H_
#define _TURN_CLENT_H_
#include <stdlib.h>
#include <stdio.h>
#ifdef __cplusplus
extern "C" {
#endif
	extern int init_turn_client(char* turnserver, unsigned short serverport, int* psock, char* relay_ip, unsigned short* relay_port);

	extern int turnclient_connect_peer(int sock, char* turnserver, unsigned short serverport, char* peer_ip, unsigned short peer_port, int* psock2);

	extern int turnclient_wait_connection(int sock, char* turnserver, unsigned short serverport, int* psock2,char* relay_ip);

	extern int turnclient_refresh(int sock, char* turnserver, unsigned short serverport,unsigned long lifetime);

#ifdef __cplusplus
}
#endif

#endif  
