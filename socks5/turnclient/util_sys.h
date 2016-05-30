
/**
 * \file util_sys.h
 * \author hong.he
 * \date 2012-2013
 */

#ifndef UTIL_SYS_H
#define UTIL_SYS_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#if !defined(_WIN32) && !defined(_WIN64)
#include <sys/uio.h>
#include <sys/select.h>
#else
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#endif

#ifndef _MSC_VER
#include <stdint.h>
#include <sys/types.h>
#else
/* replace stdint.h types for MS Windows */
typedef __int8 int8_t;
typedef unsigned __int8 uint8_t;
typedef __int16 int16_t;
typedef unsigned __int16 uint16_t;
typedef __int32 int32_t;
typedef unsigned __int32 uint32_t;
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;
typedef int mode_t;
typedef int ssize_t;
typedef int pid_t;
#define inline __inline
#endif

#if defined(_WIN32) || defined(_WIN64)
/**
 * \struct iovec
 * \brief iovector structure for win32.
 */
typedef struct iovec
{
  void* iov_base; /**< Pointer on data */
  size_t iov_len; /**< Size of data */
}iovec;

/* some unix types are not defined for Windows
 * (even with MinGW) so declare it here
 */
typedef int socklen_t;
typedef int uid_t;
typedef int gid_t;
#endif


#if defined(_WIN32) || defined(_WIN64)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
typedef int socklen_t;
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif
/**
 * \def MAX
 * \brief Maximum number of the two arguments.
 */
#define	MAX(a, b) ((a) > (b) ? (a) : (b))

/**
 * \def MIN
 * \brief Minimum number of the two arguments.
 */
#define	MIN(a, b) ((a) < (b) ? (a) : (b))

#ifdef _POSIX_C_SOURCE
/**
 * \brief Definition of fd_mask for select() operations.
 */
typedef long int fd_mask;
#endif

/* to specify a user-defined FD_SETSIZE */
#ifndef SFD_SETSIZE
/**
 * \def SFD_SETSIZE
 * \brief User defined FD_SETSIZE.
 */
#define SFD_SETSIZE FD_SETSIZE
#endif

/**
 * \struct sfd_set
 * \brief An fd_set-like structure.
 *
 * Replacement for the classic fd_set.
 * Ensure that select() can manage the maximum open files
 * on a system.
 */
#ifdef ANDROID_TURN
typedef uint32_t   fd_mask;
#endif

typedef struct sfd_set
{
#if !defined(_WIN32) && !defined(_WIN64)
  fd_mask fds_bits[SFD_SETSIZE / (8 * sizeof(fd_mask)) + 1]; /**< Bitmask */

  /**
   * \def __fds_bits
   * \brief Definition of __fds_bits for *BSD.
   */
#define __fds_bits fds_bits
#else
  SOCKET fd_array[SFD_SETSIZE]; /**< Bitmask */
#define fd_mask
#endif
}sfd_set;

/**
 * \def SFD_ZERO
 * \brief FD_ZERO wrapper.
 */
#define SFD_ZERO(set) memset((set), 0x00, sizeof(sfd_set))

/**
 * \def SFD_SET
 * \brief FD_SET wrapper.
 */
#define SFD_SET(fd, set) FD_SET((fd), (set))

/**
 * \def SFD_ISSET
 * \brief FD_ISSET wrapper.
 */
#define SFD_ISSET(fd, set) FD_ISSET((fd), (set))

/**
 * \def SFD_CLR
 * \brief FD_CLR wrapper.
 */
#define SFD_CLR(fd, set) FD_CLR((fd), (set))

/**
 * \brief Test if socket has data to read.
 *
 * It is a convenient function to test if socket is valid, can be tested in
 * select and if it has data to read.
 * \param sock socket to read
 * \param nsock parameter of (p)select() function
 * \param fdsr set of descriptor (see select())
 * \return 1 if socket has data, 0 otherwise
 */


enum protocol_type
{
	UDP = IPPROTO_UDP, /**< UDP protocol */
	TCP = IPPROTO_TCP, /**< TCP protocol */
};


#ifdef __cplusplus
extern "C"
{ /* } */
#endif

/**
 * \brief Sleep for usec microseconds.
 * \param usec number of microseconds
 * \return 0 if success, -1 otherwise
 */
int msleep(unsigned long usec);


/**
 * \brief Return if host machine is big endian.
 * \return 1 if big endian
 */
int is_big_endian(void);

/**
 * \brief Return if host machine is little endian.
 * \return 1 if little endian, 0 otherwise
 */
int is_little_endian(void);

/**
 * \brief Return the error which correspond to errnum.
 * \param errnum error number (i.e errno)
 * \param buf a buffer
 * \param buflen size of buffer
 * \return pointer on buf
 * \note This function use strerror_r if available, and assume strerror() is
 * reentrant on systems which do not have strerror_r().
 * \warning If you do a multithreaded program, be sure strerror_r() is available
 * or strerror() is reentrant on your system.
 */
char* get_error(int errnum, char* buf, size_t buflen);

/**
 * \brief Go in daemon mode.
 * \param dir change directory to this, default is /.
 * \param mask to fix permission: mask & 0777, default is 0.
 * \param cleanup cleanup function, if not NULL it is executed before father
 * _exit()
 * \param arg argument of cleanup function
 * \return -1 if error\n
 * In case of father, this function never returns (_exit)\n
 * If success 0 is returned in case of child
 */
int go_daemon(const char* dir, mode_t mask, void (*cleanup)(void* arg),
    void* arg);

/**
 * \brief Free elements of an iovec array.
 * It does not freed the array (if allocated).
 * \param iov the iovec array
 * \param nb number of elements
 */
void iovec_free_data(struct iovec* iov, uint32_t nb);






#if __STDC_VERSION__ >= 199901L /* C99 */
/**
 * \brief Secure version of strncpy.
 * \param dest destination buffer
 * \param src source buffer to copy
 * \param n maximum size to copy
 * \return pointer on dest
 */
static inline char* s_strncpy(char* dest, const char* src, size_t n)
{
  char* ret = NULL;

  ret = strncpy(dest, src, n - 1);
  dest[n - 1] = 0x00; /* add the final NULL character */

  return ret;
}

/**
 * \brief Secure version of snprintf.
 * \param str buffer to copy
 * \param size maximum size to copy
 * \param format the format (see printf)
 * \param ... a list of arguments
 * \return number of character written
 */
static inline int s_snprintf(char* str, size_t size, const char* format, ...)
{
  va_list args;
  int ret = 0;

  va_start(args, format);
  ret = snprintf(str, size - 1, format,  args);
  str[size - 1] = 0x00; /* add the final NULL character */

  return ret;
}
#else
#undef s_strncpy
/**
 * \def s_strncpy
 * \brief Secure version of strncpy.
 * \param dest destination buffer
 * \param src source buffer to copy
 * \param n maximum size to copy
 * \warning It does not return a value (like strncpy does).
 */
#define s_strncpy(dest, src, n) do { \
  strncpy((dest), (src), (n) - 1); \
  dest[n - 1] = 0x00; \
}while(0);

#endif

#if defined(_XOPEN_SOURCE) && _XOPEN_SOURCE < 500
/**
 * \brief strdup replacement.
 *
 * strdup() is from X/OPEN (XSI extension).
 * \param s string to duplicate
 * \return pointer on duplicate string
 * \warning Do not forget to free the pointer after use
 * \author Sebastien Vincent
 */
char* strdup(const char* s);
#endif

/**
 * \brief Convert a binary stream into hex value.
 * \param bin binary data
 * \param bin_len data length
 * \param hex buffer
 * \param hex_len length of buffer
 */
void hex_convert(const unsigned char* bin, size_t bin_len, unsigned char* hex,
    size_t hex_len);

/**
 * \brief Convert a ascii stream into integer value.
 * \param data ascii data
 * \param data_len data length
 * \param t a 32 bit unsigned integer
 */
void uint32_convert(const unsigned char* data, size_t data_len, uint32_t* t);

/**
 * \brief Convert a ascii stream into integer value.
 * \param data ascii data
 * \param data_len data length
 * \param t a 64 bit unsigned integer
 */
void uint64_convert(const unsigned char* data, size_t data_len, uint64_t* t);

#if defined(_WIN32) || defined(_WIN64)
/**
 * \brief The writev() function for win32 socket.
 * \param fd the socket descriptor to write the data
 * \param iov the iovector which contains the data
 * \param iovcnt number of element that should be written
 * \param addr source address to send with UDP, set to NULL if you want to send
 * with TCP
 * \param addr_size sizeof addr
 * \return number of bytes written or -1 if error
 * \warning this function work only with socket!
 */
ssize_t sock_writev(int fd, const struct iovec *iov, size_t iovcnt,
    const struct sockaddr* addr, socklen_t addr_size);

/**
 * \brief The readv() function for win32 socket.
 * \param fd the socket descriptor to read the data
 * \param iov the iovector to store the data
 * \param iovcnt number of element that should be filled
 * \param addr if not NULL it considers using a UDP socket, otherwise it
 * considers using a TCP one
 * \param addr_size pointer on address size, will be filled by this function
 * \return number of bytes read or -1 if error
 * \warning this function work only with socket!
 */
ssize_t sock_readv(int fd, const struct iovec *iov, size_t iovcnt,
    const struct sockaddr* addr, socklen_t* addr_size);
#endif


/**
* \brief Create and bind socket.
* \param type transport protocol used
* \param addr address or FQDN name
* \param port to bind
* \param reuse allow socket to reuse transport address (SO_REUSE)
* \param nodelay disable naggle algorithm for TCP sockets only (TCP_NODELAY)
* \return socket descriptor, -1 otherwise
*/
int socket_create(enum protocol_type type, const char* addr, uint16_t port,
				  int reuse, int nodelay);

#ifdef __cplusplus
}
#endif

#endif /* UTIL_SYS_H */

