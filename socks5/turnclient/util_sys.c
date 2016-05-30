
/**
 * \file util_sys.c
 * \author hong.he
 * \date 2012-2013
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <fcntl.h>

#include <sys/stat.h>

#if !defined(_WIN32) && !defined(_WIN64)
#include <unistd.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <time.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#elif defined(_MSC_VER)
/* Microsoft compiler does not want users
* to use snprintf directly...
*/
#define snprintf _snprintf
#endif

#include "util_sys.h"

/**
 * \def UNKNOWN_ERROR
 * \brief Error string used when no other error string
 * are available.
 */
#define UNKNOWN_ERROR "Unknown error!"

#ifdef __cplusplus
extern "C"
{ /* } */
#endif

int msleep(unsigned long usec)
{
  unsigned long sec = 0;
  struct timeval tv;

  sec = (unsigned long)usec / 1000000;
  usec = (unsigned long)usec % 1000000;

  tv.tv_sec = sec;
  tv.tv_usec = usec;

  select(0, NULL, NULL, NULL, &tv);

  return 0;
}


int is_big_endian(void)
{
  long one = 1;
  return !(*((char *)(&one)));
}

int is_little_endian(void)
{
  long one = 1;
  return (*((char *)(&one)));
}

char* get_error(int errnum, char* buf, size_t buflen)
{
  char* error = NULL;
# if _POSIX_C_SOURCE == 200112L && !defined(_GNU_SOURCE)
  /* POSIX version */
  int ret = 0;
  ret = strerror_r(errnum, buf, buflen);
  if(ret == -1)
  {
    strncpy(buf, UNKNOWN_ERROR, buflen - 1);
    buf[buflen - 1] = 0x00;
  }
  error = buf;
#elif defined(_GNU_SOURCE)
  /* GNU libc */
  error = strerror_r(errnum, buf, buflen);
#else
  /* no strerror_r() function, assume that strerror is reentrant! */
  strncpy(buf, strerror(errnum), buflen);
  error = buf;
#endif
  return error;
}

int go_daemon(const char* dir, mode_t mask, void (*cleanup)(void* arg),
    void* arg)
{
  pid_t pid = -1;
  long i = 0;
  long max = 0;
  int fd = -1;

#if defined(_WIN32) || defined(_WIN64)
  return -1;
#else

  pid = fork();

  if(pid > 0) /* father */
  {
    if(cleanup)
    {
      cleanup(arg);
    }
    _exit(EXIT_SUCCESS);
  }
  else if(pid == -1) /* error */
  {
    return -1;
  }

  /* child */

  if(setsid() == -1)
  {
    return -1;
  }

  max = sysconf(_SC_OPEN_MAX);
  for(i = STDIN_FILENO + 1 ; i < max ; i++)
  {
    close(i);
  }

  /* change directory */
  if(!dir)
  {
    dir = "/";
  }

  if(chdir(dir) == -1)
  {
    return -1;
  }

  /* change mask */
  umask(mask);

  /* redirect stdin, stdout and stderr to /dev/null */
  /* open /dev/null */
  if((fd = open("/dev/null", O_RDWR, 0)) != -1)
  {
    /* redirect stdin, stdout and stderr to /dev/null */
    close(STDIN_FILENO);
    dup2(fd, STDIN_FILENO);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);

    if(fd > -1)
    {
      close(fd);
    }
  }

  return 0;
#endif
}


#if defined(_XOPEN_SOURCE) && _XOPEN_SOURCE < 500
char* strdup(const char* str)
{
  char* ret = NULL;
  size_t nb = strlen(str);

  ret = malloc(nb + 1);
  if(!ret)
  {
    return NULL;
  }
  memcpy(ret, str, nb); /* also copy the NULL character */
  return ret;
}
#endif

#if defined(_WIN32) || defined(_WIN64)
ssize_t sock_readv(int fd, const struct iovec *iov, size_t iovcnt,
    const struct sockaddr* addr, socklen_t* addr_size)
{
  /* it should be sufficient,
   * the dynamically allocation is timecost.
   * We could use a static WSABUF* winiov but
   * the function would be non reentrant.
   */
  WSABUF winiov[50];
  DWORD winiov_len = iovcnt;
  size_t i = 0;
  DWORD ret = 0;

  if(iovcnt > sizeof(winiov))
  {
    return -1;
  }

  for(i = 0 ; i < iovcnt ; i++)
  {
    winiov[i].len = iov[i].iov_len;
    winiov[i].buf = iov[i].iov_base;
  }

  if(addr) /* UDP case */
  {
    if(WSARecvFrom(fd, winiov, winiov_len, &ret, NULL, (struct sockaddr*)addr,
          addr_size, NULL, NULL) != 0)
    {
      return -1;
    }
  }
  else /* TCP case */
  {
    if(WSARecv(fd, winiov, winiov_len, &ret, NULL, NULL, NULL) != 0)
    {
      return -1;
    }
  }

  return (ssize_t)ret;
}

ssize_t sock_writev(int fd, const struct iovec *iov, size_t iovcnt,
    const struct sockaddr* addr, socklen_t addr_size)
{
  /* it should be sufficient,
   * the dynamically allocation is timecost.
   * We could use a static WSABUF* winiov but
   * the function would be non reentrant.
   */
  WSABUF winiov[50];
  DWORD winiov_len = iovcnt;
  size_t i = 0;
  DWORD ret = 0; /* number of byte read or written */

  if(iovcnt > sizeof(winiov))
  {
    return -1;
  }

  for(i = 0 ; i < iovcnt ; i++)
  {
    winiov[i].len = iov[i].iov_len;
    winiov[i].buf = iov[i].iov_base;
  }

  /* UDP case */
  if(addr)
  {
    if(WSASendTo(fd, winiov, winiov_len, &ret, 0, (struct sockaddr*)addr,
          addr_size, NULL, NULL) != 0)
    {
      /* error send */
      return -1;
    }
  }
  else /* TCP case */
  {
    if(WSASend(fd, winiov, winiov_len, &ret, 0, NULL, NULL) != 0)
    {
      /* error send */
      return -1;
    }
  }
  return (ssize_t)ret;
}
#endif

void iovec_free_data(struct iovec* iov, uint32_t nb)
{
  size_t i = 0;

  for(i = 0 ; i < nb ; i++)
  {
    free(iov[i].iov_base);
    iov[i].iov_base = NULL;
  }
}

    
void hex_convert(const unsigned char* bin, size_t bin_len, unsigned char* hex,
    size_t hex_len)
{
  size_t i = 0;
  unsigned char j = 0;

  for(i = 0 ; i < bin_len && (i * 2) < hex_len ; i++)
  {
    j = (bin[i] >> 4) & 0x0f;

    if(j <= 9)
    {
      hex[i * 2] = (j + '0');
    }
    else
    {
      hex[i * 2] = (j + 'a' - 10);
    }

    j = bin[i] & 0x0f;

    if(j <= 9)
    {
      hex[i * 2 + 1] = (j + '0');
    }
    else
    {
      hex[i * 2 + 1] = (j + 'a' - 10);
    }
  }
}

void uint32_convert(const unsigned char* data, size_t data_len, uint32_t* t)
{
  unsigned int i = 0;
  *t = 0;

  for(i = 0 ; i < data_len ; i++)
  {
    *t = (*t) * 16;

    if(data[i] >= '0' && data[i] <= '9')
    {
      *t += data[i] - '0';
    }
    else if(data[i] >= 'a' && data[i] <='f')
    {
      *t += data[i] - 'a' + 10;
    }
  }
}

void uint64_convert(const unsigned char* data, size_t data_len, uint64_t* t)
{
  unsigned int i = 0;
  *t = 0;

  for(i = 0 ; i < data_len ; i++)
  {
    *t = (*t) * 16;

    if(data[i] >= '0' && data[i] <= '9')
    {
      *t += data[i] - '0';
    }
    else if(data[i] >= 'a' && data[i] <='f')
    {
      *t += data[i] - 'a' + 10;
    }
  }
}

int socket_create(enum protocol_type type, const char* addr, uint16_t port,
				  int reuse, int nodelay)
{
	int sock = -1;
    struct sockaddr_in addr_serv;
    sock = socket(AF_INET, (type == TCP ? SOCK_STREAM : SOCK_DGRAM),(type == TCP ? IPPROTO_TCP : IPPROTO_UDP));
    int on = 1;
    if(reuse)
    {
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int));
    }
    
    if (type == TCP && nodelay)
    {
        setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(int));
    }
    if(port > 0)
    {
        memset(&addr_serv,0,sizeof(struct sockaddr_in));
        addr_serv.sin_family= AF_INET;
        addr_serv.sin_port= htons(port);
        addr_serv.sin_addr.s_addr= htonl(INADDR_ANY);
        if(bind(sock,(struct sockaddr *)&addr_serv ,sizeof(struct sockaddr_in)) <0)
        {
            close(sock);
			sock = -1;
            
        }
    }
    

#if 0
	struct addrinfo hints;
	struct addrinfo* res = NULL;
	struct addrinfo* p = NULL;
	char service[8];

	snprintf(service, sizeof(service), "%u", port);
	service[sizeof(service)-1] = 0x00;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = (type == TCP ? SOCK_STREAM : SOCK_DGRAM);
	hints.ai_protocol = (type == TCP ? IPPROTO_TCP : IPPROTO_UDP);
	hints.ai_flags = AI_PASSIVE;

	if(getaddrinfo(addr, service, &hints, &res) != 0)
	{
		return -1;
	}

	for(p = res ; p ; p = p->ai_next)
	{
		int on = 1;

		sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if(sock == -1)
		{
			continue;
		}

		if(reuse)
		{
			setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int));
		}

		if (type == TCP && nodelay)
		{
			setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(int));
		}


		if(bind(sock, p->ai_addr, p->ai_addrlen) == -1)
		{
			close(sock);
			sock = -1;
			continue;
		}

		/* socket bound, break the loop */
		break;
	}

	freeaddrinfo(res);
	p = NULL;
#endif
    
	return sock;
}



#ifdef __cplusplus
}
#endif

