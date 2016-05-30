/**
* \file test_turn_client.c
 * \author hong.he
 * \date 2012-2013
* \date 2010
*/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * 安卓下使用 logcat
 *
 * 编译的时候需要加 debug
 *
 * ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./Android.mk NDK_DEBUG=1
 *
 */
#ifdef ANDROID
#include<android/log.h>

#define fprintf(f, ...) __android_log_print(ANDROID_LOG_DEBUG, "<<<---", __VA_ARGS__)
#endif

#ifndef _MSC_VER
/* Microsoft compiler does not have it */
#include <stdint.h>
#else
/* Microsoft compiler does not want users
* to use snprintf directly...
*/
#define snprintf _snprintf
/* Microsoft compiler use closesocket()
* instead of close() to close a socket
*/
#define close closesocket
#endif

#if defined(_WIN32) || defined(_WIN64)
/* Windows needs Winsock2 include
* to have access to network functions
*/
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <inaddr.h>
#include <Ws2tcpip.h>
#else
#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif

#include "util_sys.h"
#include "util_crypto.h"
#include "protocol.h"
#include "turn_client.h"
#ifdef ANDROID_TURN
#include <linux/in.h>
#elif defined(IOS_TURN)
#else
#endif

/*
typedef struct in_addr {
union {
struct { UCHAR s_b1,s_b2,s_b3,s_b4; } S_un_b;
struct { USHORT s_w1,s_w2; } S_un_w;
ULONG S_addr;
} S_un;
*/
/**
* \def SOFTWARE_DESCRIPTION
* \brief Name of the software.
*/
#define SOFTWARE_DESCRIPTION "TURN client example 0.1"

static int  fd_has_data(int fd, int timeout, int enwrite)
{
	sfd_set fdsr;
	struct timeval tv;
	int nsock = 0;
	int res ;
	tv.tv_sec = timeout; /* 10 seconds before timeout */
	tv.tv_usec = 0;
	SFD_ZERO(&fdsr);
	SFD_SET(fd, &fdsr);

	nsock = fd + 1;
	if(enwrite)
	{
		res = select(nsock, NULL,(fd_set*)(void*)&fdsr,  NULL, &tv);
	}
	else
	{
		res = select(nsock,(fd_set*)(void*)&fdsr, NULL,  NULL, &tv);

	}

	if(res > 0)
	{
		return 1;
	}
	else
	{

		return 0;
	}
}


static int set_socket_timeout(int socket, int time_out)
{
    int nNetTimeout = time_out * 1000;
	struct timeval time_out_v;
    time_out_v.tv_sec = time_out;
    time_out_v.tv_usec = 0;
#ifdef WIN32
    
    setsockopt(socket,SOL_SOCKET,SO_SNDTIMEO,(char*)&nNetTimeout,sizeof(nNetTimeout));
    setsockopt(socket,SOL_SOCKET,SO_RCVTIMEO,(char*)&nNetTimeout,sizeof(nNetTimeout));
#else
    
    setsockopt(socket,SOL_SOCKET, SO_SNDTIMEO, (char*)&time_out_v,sizeof(struct timeval));
    setsockopt(socket,SOL_SOCKET,SO_RCVTIMEO, (char*)&time_out_v,sizeof(struct timeval));
#endif
    
    return 0;
}

/**
* \brief Receive TURN message.
* \param transport_protocol transport protocol
* \param sock socket descriptor
* \param speer TLS peer
* \param buf receive buffer
* \param buflen buf length
* \return number of bytes received if success, -1 if error
*/
static int client_recv_message(int transport_protocol, int sock, char* buf, size_t buflen)
{
	ssize_t nb = -1;	
	if((nb = recv(sock, buf, buflen, 0)) == -1)
	{
			return -1;
	}

	return nb;
}

/**
* \brief Setup local socket.
* \param transport_protocol transport protocol (UDP or TCP)
* \param addr local address
* \param port local port
* \param sock if function succeed, will store socket descriptor
* \param speer if function succeed and speer is valid pointer,
* it will store TLS stuff
* \param ca_file certification authority file
* \param certificate_file SSL certificate file
* \param key_file SSL private key file
* \return 0 if success, -1 if error
*/
static int client_setup_socket(int transport_protocol, const char* addr, uint16_t port, int* sock)
{

	if(sock)
	{
		*sock = socket_create(transport_protocol, addr, port, 0, 1);
		return (*sock != -1) ? 0 : -1;
	}

	return -1;
}

/**
* \brief Connect to TURN server.
* \param transport_protocol transport protocol (UDP or TCP)
* \param addr server address
* \param addr_size sizeof addr
* \param sock socket descriptor
* \param speer connect with TLS if not NULL
* \return 0 if success, -1 if error
*/
static int client_connect_server(int transport_protocol, const struct sockaddr* addr, socklen_t addr_size,
								 int sock)
{
    int on=1;
    struct linger so_linger;
    so_linger.l_onoff = 1;
    so_linger.l_linger = 0;

	if(sock != -1)
	{
		if(transport_protocol == IPPROTO_TCP)
		{
			if(connect(sock, addr, addr_size) == -1)
			{
				return -1;
			}
            
            setsockopt(sock, SOL_SOCKET, SO_LINGER, &so_linger, sizeof(so_linger));
            setsockopt(sock, IPPROTO_TCP, TCP_NODELAY,&on,sizeof(on));
			return 0;
		}
		else if(transport_protocol == IPPROTO_UDP)
		{
			/* no need to connect in UDP */
			return 0;
		}
	}

	return -1;
}

/**
* \brief Send a TURN Allocate request.
* \param transport_protocol transport protocol used
* \param relay_protocol relay protocol used
* \param sock socket descriptor
* \param speer TLS peer
* \param addr server address
* \param addr_size sizeof addr
* \param family peer address family (STUN_ATTR_FAMILY_IPV4 or STUN_ATTR_FAMILY_IPV6)
* \param user username
* \param domain domain
* \param md_buf MD5 hash of user:domain:password
* \param nonce nonce, for first request server nonce will be filled into this variable
* \param nonce_len nonce length, for first request server nonce length will be filled into this variable
* \return 0 if success or -1 if error. Note that the first request will returns -1 (need nonce)
*/
static int client_allocate_address(int transport_protocol, int relay_protocol, int sock, const struct sockaddr* addr, socklen_t addr_size, uint8_t family, char* relay_ip, unsigned short* relay_port)
{
	struct turn_message message;
	struct turn_msg_hdr* hdr = NULL;
	struct turn_attr_hdr* attr = NULL;
	struct iovec iov[16];
	size_t index = 0;
	uint8_t id[12];
	ssize_t nb = -1;
	char buf[8192];
	uint16_t tabu[16];
	size_t tabu_size = sizeof(tabu) / sizeof(uint16_t);
	struct in_addr relay_addr;
	unsigned long cookie;
	uint16_t msb_cookie;
	char md_buf[16];
	turn_generate_transaction_id(id);

	/* Allocate request */
	hdr = turn_msg_allocate_request_create(0, id, &iov[index]);
	index++;


	/* LIFETIME */
	attr = turn_attr_lifetime_create(60, &iov[index]);
	hdr->turn_msg_len += iov[index].iov_len;
	index++;

	/* SOFTWARE */
	attr = turn_attr_software_create("Client TURN 0.1 test", strlen("Client TURN 0.1 test"), &iov[index]);
	hdr->turn_msg_len += iov[index].iov_len;
	index++;

	/* REQUESTED-TRANSPORT */
	attr = turn_attr_requested_transport_create(relay_protocol, &iov[index]);
	hdr->turn_msg_len += iov[index].iov_len;
	index++;

	/* REQUESTED-ADDRESS-FAMILY */
	attr = turn_attr_requested_address_family_create(family, &iov[index]);
	hdr->turn_msg_len += iov[index].iov_len;
	index++;

	(void)attr;


	memset(md_buf,0,sizeof(md_buf));
	if(turn_add_message_integrity(iov, &index, md_buf, 16,0) == -1)
	{
		/* MESSAGE-INTEGRITY option has to be in message, so
		* deallocate ressources and return
		*/
		iovec_free_data(iov, index);
		return -1;
	}

	fprintf(stdout, "Send Allocate request.\n");

	if(turn_send_message(transport_protocol, sock, addr, addr_size,
		ntohs(hdr->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, index) == -1)
	{
		fprintf(stderr, "Send failed!\n");
		iovec_free_data(iov, index);
		return -1;
	}

	iovec_free_data(iov, index);

	nb = client_recv_message(transport_protocol, sock, buf, sizeof(buf));

	if(nb <= 0)
	{
		fprintf(stderr, "Receive failed!\n");
		return -1;
	}

	if(turn_parse_message(buf, nb, &message, tabu, &tabu_size) == -1)
	{
		fprintf(stderr, "Parsing failed!\n");
		return -1;
	}

	if(message.relayed_addr)
	{
		unsigned long laddr;
		memcpy(&laddr, message.relayed_addr->turn_attr_address,sizeof(laddr));
		relay_addr.s_addr =htonl(STUN_MAGIC_COOKIE)^laddr;
		if(relay_ip)
		{
			strcpy(relay_ip,inet_ntoa(relay_addr));

			cookie = htonl(STUN_MAGIC_COOKIE);
			msb_cookie = ((uint8_t*)&cookie)[0] << 8 | ((uint8_t*)&cookie)[1];
			*relay_port = ntohs(message.relayed_addr->turn_attr_port) ^msb_cookie;
		}
		else{
			if(relay_port)
				*relay_port = 0;
		}
	}
	else
	{
		if(relay_port)
			*relay_port = 0;
	}

	return STUN_IS_ERROR_RESP(ntohs(message.msg->turn_msg_type)) ? -1 : 0;
}

/**
* \brief Send a TURN CreatePermission request.
* \param transport_protocol transport protocol used
* \param sock socket descriptor
* \param speer TLS peer
* \param addr server address
* \param addr_size sizeof addr
* \param lifetime lifetime (0 to release allocation)
* \param user username
* \param md_buf MD5 of user:domain:password
* \param domain domain
* \param nonce nonce
* \param nonce_len nonce length
* \return 0 if success or -1 if error.
*/
static int client_refresh_allocation(int transport_protocol, int sock, const struct sockaddr* addr, socklen_t addr_size, uint32_t lifetime)
{
	struct turn_message message;
	struct turn_msg_hdr* hdr = NULL;
	struct turn_attr_hdr* attr = NULL;
	struct iovec iov[16];
	size_t index = 0;
	uint8_t id[12];
	ssize_t nb = -1;
	char buf[1500];
	uint16_t tabu[16];
	size_t tabu_size = sizeof(tabu) / sizeof(uint16_t);
	char md_buf[16];

	turn_generate_transaction_id(id);

	/* Refresh request */
	hdr = turn_msg_refresh_request_create(0, id, &iov[index]);
	index++;

	/* LIFETIME */
	attr = turn_attr_lifetime_create(lifetime, &iov[index]);
	hdr->turn_msg_len += iov[index].iov_len;
	index++;

	/* SOFTWARE */
	attr = turn_attr_software_create(SOFTWARE_DESCRIPTION, strlen(SOFTWARE_DESCRIPTION), &iov[index]);
	hdr->turn_msg_len += iov[index].iov_len;
	index++;

	(void)attr;

	memset(md_buf,0,sizeof(md_buf));
	if(turn_add_message_integrity(iov, &index, md_buf, 16, 0) == -1)
	{
		/* MESSAGE-INTEGRITY option has to be in message, so
		* deallocate ressources and return
		*/
		iovec_free_data(iov, index);
		return -1;
	}

	fprintf(stdout, "Send Refresh request.\n");

	if(turn_send_message(transport_protocol, sock, addr, addr_size,
		ntohs(hdr->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, index) == -1)
	{
		fprintf(stderr, "client_refresh_allocation Send failed!\n");
		iovec_free_data(iov, index);
		return -1;
	}

	iovec_free_data(iov, index);
    
    
    nb = client_recv_message(transport_protocol, sock, buf, sizeof(struct turn_msg_hdr));
    
	if(nb !=  sizeof(struct turn_msg_hdr))
	{
		fprintf(stderr, "client_refresh_allocation Receive failed!\n");
		return -1;
	}
	hdr = (struct turn_msg_hdr*)buf;
    
	nb = client_recv_message(transport_protocol, sock, buf + sizeof(struct turn_msg_hdr), ntohs(hdr->turn_msg_len));
	if(nb != ntohs(hdr->turn_msg_len) )
	{
        
		fprintf(stderr, "client_refresh_allocation Receive failed!\n");
		return -1;
	}
    
	if(turn_parse_message(buf, nb + sizeof(struct turn_msg_hdr), &message, tabu, &tabu_size) == -1)
	{
		fprintf(stderr, "client_refresh_allocation Parsing failed!\n");
		return -1;
	}

	return STUN_IS_ERROR_RESP(ntohs(message.msg->turn_msg_type)) ? -1 : 0;
}


/**
* \brief Send a TURN-TCP Connect request and if success, send a ConnectionBind.
* \param transport_protocol transport protocol used
* \param sock socket descriptor
* \param speer TLS peer
* \param addr server address
* \param addr_size sizeof addr
* \param peer_addr peer address
* \param sock_tcp pointer that will receive socket descriptor if function succeed
* \param user username
* \param md_buf MD5 of user:domain:password
* \param domain domain
* \param nonce nonce
* \param nonce_len nonce length
* \return 0 if success or -1 if error.
*/
static int client_send_connect(int transport_protocol, int sock,
							   const struct sockaddr* addr, socklen_t addr_size, const struct sockaddr* peer_addr,
							   int* sock_tcp)
{
	struct turn_message message;
	struct turn_msg_hdr* hdr = NULL;
	struct turn_attr_hdr* attr = NULL;
	struct iovec iov[16];
	size_t index = 0;
	uint8_t id[12];
	ssize_t nb = -1;
	char buf[1500];
	uint16_t tabu[16];
	char md_buf[16];
    int on = 1;
	size_t tabu_size = sizeof(tabu) / sizeof(uint16_t);
    struct linger so_linger;
    so_linger.l_onoff = 1;
    so_linger.l_linger = 0;


	turn_generate_transaction_id(id);

	/* Connect request */
	hdr = turn_msg_connect_request_create(0, id, &iov[index]);
	index++;

	/* SOFTWARE */
	attr = turn_attr_software_create(SOFTWARE_DESCRIPTION, strlen(SOFTWARE_DESCRIPTION), &iov[index]);
	hdr->turn_msg_len += iov[index].iov_len;
	index++;

	/* XOR-PEER-ADDRESS */
	attr = turn_attr_xor_peer_address_create(peer_addr, STUN_MAGIC_COOKIE, id, &iov[index]);
	hdr->turn_msg_len += iov[index].iov_len;
	index++;

	(void)attr;

	if(turn_add_message_integrity(iov, &index, md_buf, 16, 0) == -1)
	{
		/* MESSAGE-INTEGRITY option has to be in message, so
		* deallocate ressources and return
		*/
		iovec_free_data(iov, index);
		return -1;
	}

	fprintf(stdout, "Send Connect request.\n");

	if(turn_send_message(transport_protocol, sock, addr, addr_size,
		ntohs(hdr->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, index) == -1)
	{
		fprintf(stderr, "client_send_connect Send failed!\n");
		iovec_free_data(iov, index);
		return -1;
	}

	iovec_free_data(iov, index);
	index = 0;
    
    
    
    nb = client_recv_message(transport_protocol, sock, buf, sizeof(struct turn_msg_hdr));
    
	if(nb !=  sizeof(struct turn_msg_hdr))
	{
		fprintf(stderr, "client_send_connect Receive failed!\n");
		return -1;
	}
	hdr = (struct turn_msg_hdr*)buf;
	nb = client_recv_message(transport_protocol, sock, buf + sizeof(struct turn_msg_hdr), ntohs(hdr->turn_msg_len));
	if(nb != ntohs(hdr->turn_msg_len) )
	{
        
		fprintf(stderr, "client_send_connect Receive failed!\n");
		return -1;
	}
    
    if(turn_parse_message(buf, nb + sizeof(struct turn_msg_hdr), &message, tabu, &tabu_size) == -1)
	{
		fprintf(stderr, "client_send_connect Parsing failed!\n");
		return -1;
	}

	if(!message.connection_id)
	{
		fprintf(stderr, "client_send_connect No connection ID.\n");
		return -1;
	}

	*sock_tcp = socket(addr->sa_family, SOCK_STREAM, IPPROTO_TCP);

    /**
     * 安卓下 vpn 模式需要处理出 fd
     *
     *
     */
	if(*sock_tcp == -1 || protect_socket(*sock_tcp) == -1 ||  connect(*sock_tcp, addr, addr_size) == -1)
	{
		fprintf(stderr, "client_send_connect Failed to connect to TURN server.\n");
		return -1;
	}
    
    set_socket_timeout(*sock_tcp, 5);
    
    setsockopt(*sock_tcp, SOL_SOCKET, SO_LINGER, &so_linger,sizeof(so_linger));
    setsockopt(*sock_tcp, IPPROTO_TCP, TCP_NODELAY,&on,sizeof(on));
    

	turn_generate_transaction_id(id);

	/* ConnectionBind request */
	hdr = turn_msg_connectionbind_request_create(0, id, &iov[index]);
	index++;

	/* CONNECTION-ID */
	attr = turn_attr_connection_id_create(message.connection_id->turn_attr_id, &iov[index]);
	hdr->turn_msg_len += iov[index].iov_len;
	index++;

	/* SOFTWARE */
	attr = turn_attr_software_create(SOFTWARE_DESCRIPTION, strlen(SOFTWARE_DESCRIPTION), &iov[index]);
	hdr->turn_msg_len += iov[index].iov_len;
	index++;

	memset(md_buf,0,sizeof(md_buf));
	if(turn_add_message_integrity(iov, &index, md_buf, 16, 0) == -1)
	{
		/* MESSAGE-INTEGRITY option has to be in message, so
		* deallocate ressources and return
		*/
		iovec_free_data(iov, index);
		return -1;
	}

	fprintf(stdout, "client_send_connect Send ConnectionBind request.\n");

	if(turn_send_message(transport_protocol, *sock_tcp, addr, addr_size,
		ntohs(hdr->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, index) == -1)
	{
		fprintf(stderr, "Send failed!\n");
		iovec_free_data(iov, index);
		return -1;
	}
	iovec_free_data(iov, index);

	nb = client_recv_message(transport_protocol, *sock_tcp, buf, sizeof(struct turn_msg_hdr));

	if(nb !=  sizeof(struct turn_msg_hdr))
	{
		fprintf(stderr, "client_send_connect Receive failed!\n");
		return -1;
	}
	hdr = (struct turn_msg_hdr*)buf;

	nb = client_recv_message(transport_protocol, *sock_tcp, buf + sizeof(struct turn_msg_hdr), ntohs(hdr->turn_msg_len));
	if(nb != ntohs(hdr->turn_msg_len) )
	{

		fprintf(stderr, "client_send_connect Receive failed!\n");
		return -1;
	}
	if(turn_parse_message(buf, nb + sizeof(struct turn_msg_hdr), &message, tabu, &tabu_size) == -1)
	{
		fprintf(stderr, "client_send_connect Parsing failed!\n");
		return -1;
	}
	fprintf(stdout, "Receive ConnectionBind response OK\n");

	return STUN_IS_ERROR_RESP(ntohs(message.msg->turn_msg_type)) ? -1 : 0;
}

/**
* \brief Wait a ConnectionAttempt and send ConnectionBind request.
* \param transport_protocol transport protocol used
* \param sock socket descriptor
* \param speer TLS peer
* \param addr server address
* \param addr_size sizeof addr
* \param peer_addr peer address
* \param sock_tcp pointer that will receive socket descriptor if function succeed
* \param user username
* \param md_buf MD5 of user:domain:password
* \param domain domain
* \param nonce nonce
* \param nonce_len nonce length
* \return 0 if success or -1 if error.
*/
static int client_wait_connection(int transport_protocol, int sock,
								  const struct sockaddr* addr, socklen_t addr_size, const struct sockaddr* peer_addr,
								  int* sock_tcp)
{
	struct turn_message message;
	struct turn_msg_hdr* hdr = NULL;
	struct turn_attr_hdr* attr = NULL;
	struct iovec iov[16];
	size_t index = 0;
	uint8_t id[12];
	ssize_t nb = -1;
	char buf[1500];
	uint16_t tabu[16];
	size_t tabu_size = sizeof(tabu) / sizeof(uint16_t);
	sfd_set fdsr;
	struct timeval tv;
	char md_buf[16];
	int nsock = 0;
    int on = 1;
    int error = 0;
    int len = sizeof(int);
    struct linger so_linger;
    so_linger.l_onoff = 1;
    so_linger.l_linger = 0;
	tv.tv_sec = 1; /* 10 seconds before timeout */
	tv.tv_usec = 0;
	SFD_ZERO(&fdsr);
	SFD_SET(sock, &fdsr);

	nsock = sock + 1;

	if(select(nsock, (fd_set*)(void*)&fdsr, NULL, NULL, &tv) <= 0)
	{
        
		return -1;
	}
    else
    {
        getsockopt(nsock, SOL_SOCKET, SO_ERROR, &error, (socklen_t *)&len);
        if(error != 0)
        {
            return -2;
        }
    }

	/* here we are sure that data are available on socket */
    

    nb = client_recv_message(transport_protocol, sock, buf, sizeof(struct turn_msg_hdr));
    
	if(nb !=  sizeof(struct turn_msg_hdr))
	{
		fprintf(stderr, "client_wait_connection Receive failed!\n");
		return -2;
	}
	hdr = (struct turn_msg_hdr*)buf;
    
	nb = client_recv_message(transport_protocol, sock, buf + sizeof(struct turn_msg_hdr), ntohs(hdr->turn_msg_len));
	if(nb != ntohs(hdr->turn_msg_len) )
	{
        
		fprintf(stderr, "client_wait_connection Receive failed!\n");
		return -2;
	}
    

	if(turn_parse_message(buf, nb + sizeof(struct turn_msg_hdr), &message, tabu, &tabu_size) == -1)
	{
		fprintf(stderr, "client_wait_connection Parsing failed!\n");
		return -2;
	}

	if(!message.connection_id)
	{
		fprintf(stderr, "client_wait_connection No connection ID.\n");
		return -2;
	}

	turn_generate_transaction_id(id);

	*sock_tcp = socket(addr->sa_family, SOCK_STREAM, IPPROTO_TCP);

	/* establish relay connection */
	if(*sock_tcp == -1 || connect(*sock_tcp, addr, addr_size) == -1)
	{
		fprintf(stderr, "client_wait_connection Failed to connect to TURN server.\n");
		return -2;
	}
    
    set_socket_timeout(*sock_tcp, 5);
    setsockopt(*sock_tcp, IPPROTO_TCP, TCP_NODELAY,&on,sizeof(on));
    setsockopt(*sock_tcp, SOL_SOCKET,SO_LINGER, &so_linger,sizeof(so_linger));
    
    
	turn_generate_transaction_id(id);

	/* ConnectionBind request */
	hdr = turn_msg_connectionbind_request_create(0, id, &iov[index]);
	index++;

	/* CONNECTION-ID */
	attr = turn_attr_connection_id_create(message.connection_id->turn_attr_id, &iov[index]);
	hdr->turn_msg_len += iov[index].iov_len;
	index++;

	/* SOFTWARE */
	attr = turn_attr_software_create(SOFTWARE_DESCRIPTION, strlen(SOFTWARE_DESCRIPTION), &iov[index]);
	hdr->turn_msg_len += iov[index].iov_len;
	index++;

	memset(md_buf,0,sizeof(md_buf));

	if(turn_add_message_integrity(iov, &index, md_buf, 16, 0) == -1)
	{
		iovec_free_data(iov, index);
		return -2;
	}

	fprintf(stdout, "client_wait_connection Send ConnectionBind request.\n");

	if(turn_send_message(transport_protocol, *sock_tcp, addr, addr_size,
		ntohs(hdr->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, index) == -1)
	{
		fprintf(stderr, "client_wait_connection Send failed!\n");
		iovec_free_data(iov, index);
		return -2;
	}

	iovec_free_data(iov, index);

	nb = client_recv_message(transport_protocol, *sock_tcp, buf, sizeof(struct turn_msg_hdr));

	if(nb !=  sizeof(struct turn_msg_hdr))
	{
		fprintf(stderr, "client_wait_connection Receive failed!\n");
		return -2;
	}
	hdr = (struct turn_msg_hdr*)buf;

	nb = client_recv_message(transport_protocol, *sock_tcp, buf + sizeof(struct turn_msg_hdr), ntohs(hdr->turn_msg_len));
	if(nb != ntohs(hdr->turn_msg_len) )
	{

		fprintf(stderr, "client_wait_connection Receive failed!\n");
		return -2;
	}
	if(turn_parse_message(buf, nb + sizeof(struct turn_msg_hdr), &message, tabu, &tabu_size) == -1)
	{
		fprintf(stderr, "client_wait_connection Parsing failed!\n");
		return -2;
	}
	fprintf(stdout, "Receive ConnectionBind response OK\n");

	return STUN_IS_ERROR_RESP(ntohs(message.msg->turn_msg_type)) ? -2 : 0;

}

/**
* \brief Entry point of the program.
* \param argc number of argument
* \param argv array of argument
* \return EXIT_SUCCESS or EXIT_FAILURE
*/


int init_turn_client(char* turnserver, unsigned short serverport, int* psock, char* relay_ip, unsigned short* relay_port)
{

	char port_str[8];
	struct addrinfo hints;
	struct addrinfo* res = NULL;
	int r = -1;
	int ret = 0;
	struct sockaddr_storage server_addr;
	socklen_t server_addr_size = 0;
#if defined(_WIN32) || defined(_WIN64)
	/* Windows need to initialize and startup
	* WSAData object otherwise network-related
	* functions will fail
	*/
	WSADATA wsa;
	if(WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		return -1;
	}
#endif

    /**
     * 安卓下 vpn 模式需要处理出 fd
     *
     *
     */
	*psock = -1;
	if(client_setup_socket(IPPROTO_TCP, "0.0.0.0", 0, psock) == -1 || protect_socket(*psock) < 0)
	{
		return -1;
	}
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype =  SOCK_STREAM;
	hints.ai_protocol = 0;
	hints.ai_flags = AI_PASSIVE;

	memset(port_str,0,8);
	sprintf(port_str,"%d",serverport);
	if((r = getaddrinfo(turnserver, port_str, &hints, &res)) != 0)
	{
		return -1;
	}

	memcpy(&server_addr, res->ai_addr, res->ai_addrlen);
	server_addr_size = res->ai_addrlen;
	freeaddrinfo(res);
	if(client_connect_server(IPPROTO_TCP, (struct sockaddr*)&server_addr, server_addr_size, *psock) == -1)
	{
		return -1;
	}
    
    set_socket_timeout(*psock, 5);

	if(client_allocate_address(IPPROTO_TCP, IPPROTO_TCP,*psock, (struct sockaddr*)&server_addr, server_addr_size, STUN_ATTR_FAMILY_IPV4,relay_ip,relay_port) == -1)
	{
		ret = -1;
	}

	return ret;
}


int turnclient_refresh(int sock, char* turnserver, unsigned short serverport,unsigned long lifetime)
{

	char port_str[8];
	struct addrinfo hints;
	struct addrinfo* res = NULL;
	socklen_t server_addr_size = 0;
	int r = -1;
	struct sockaddr_storage server_addr;
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype =  SOCK_STREAM;
	hints.ai_protocol = 0;
	hints.ai_flags = AI_PASSIVE;
	memset(port_str,0,8);
	sprintf(port_str,"%d",serverport);
	if((r = getaddrinfo(turnserver, port_str, &hints, &res)) != 0)
	{
		return -1;
	}
	memcpy(&server_addr, res->ai_addr, res->ai_addrlen);
	server_addr_size = res->ai_addrlen;

	if(client_refresh_allocation(IPPROTO_TCP, sock, (struct sockaddr*)&server_addr, server_addr_size, lifetime) == -1)
	{
		return -1;
	}
	return 0;
}

int turnclient_connect_peer(int sock, char* turnserver, unsigned short serverport, char* peer_ip, unsigned short peer_port, int* psock2)
{
	char port_str[8];
	struct addrinfo hints;
	struct addrinfo* res = NULL;
	socklen_t server_addr_size = 0;
	int r = -1;
	struct sockaddr_storage server_addr;
	struct sockaddr_storage peer_addr;
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype =  SOCK_STREAM;
	hints.ai_protocol = 0;
	hints.ai_flags = AI_PASSIVE;
	memset(port_str,0,8);
	sprintf(port_str,"%d",serverport);
	if((r = getaddrinfo(turnserver, port_str, &hints, &res)) != 0)
	{
		return -1;
	}
	memcpy(&server_addr, res->ai_addr, res->ai_addrlen);
	server_addr_size = res->ai_addrlen;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype =  SOCK_STREAM;
	hints.ai_protocol = 0;
	hints.ai_flags = AI_PASSIVE;
	memset(port_str,0,8);
	sprintf(port_str,"%d",peer_port);
	if((r = getaddrinfo(peer_ip, port_str, &hints, &res)) != 0)
	{
		return -1;
	}
	memcpy(&peer_addr, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);

	if(client_send_connect(IPPROTO_TCP, sock, (struct sockaddr*)&server_addr, server_addr_size, (struct sockaddr*)&peer_addr, psock2) == -1)
	{
		return -1;
	}


	return 0;
}


int turnclient_wait_connection(int sock, char* turnserver, unsigned short serverport, int* psock2,char* relay_ip)
{

	char port_str[8];
	struct addrinfo hints;
	struct addrinfo* res = NULL;
	socklen_t server_addr_size = 0;
	int r = -1;
	struct sockaddr_storage server_addr;
	struct sockaddr_storage peer_addr;
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype =  SOCK_STREAM;
	hints.ai_protocol = 0;
	hints.ai_flags = AI_PASSIVE;

	memset(port_str,0,8);
	sprintf(port_str,"%d",serverport);
	if((r = getaddrinfo(turnserver, port_str, &hints, &res)) != 0)
	{
		return -1;
	}
	memcpy(&server_addr, res->ai_addr, res->ai_addrlen);
	server_addr_size = res->ai_addrlen;
    freeaddrinfo(res);

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype =  SOCK_STREAM;
	hints.ai_protocol = 0;
	hints.ai_flags = AI_PASSIVE;
	if((r = getaddrinfo(relay_ip, "0", &hints, &res)) != 0)
	{
		return -1;
	}
	memcpy(&peer_addr, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);

	return client_wait_connection(IPPROTO_TCP, sock, (struct sockaddr*)&server_addr, server_addr_size, (struct sockaddr*)&peer_addr, psock2);
	
}
