// +----------------------------------------------------------------------
// | ZYSOFT [ MAKE IT OPEN ]
// +----------------------------------------------------------------------
// | Copyright (c) 2016 ZYSOFT All rights reserved.
// +----------------------------------------------------------------------
// | Licensed ( http://www.apache.org/licenses/LICENSE-2.0 )
// +----------------------------------------------------------------------
// | Author: zy_cwind <391321232@qq.com>
// +----------------------------------------------------------------------

#include <string.h>
#include <stdlib.h>
#include <unistd.h>

/**
 * 安卓 vpn 下通信管道
 *
 *
 */
#define PROTECTPATH "/data/data/com.zed1.luaservice/protect_path"

/**
 * windows 下要是用 closesocket 函数关闭连接
 *
 *
 */
#ifndef WIN32
#include <sys/un.h>
#include <netdb.h>

#define closesocket close
#endif

/**
 * 安卓下 vpn 模式需要处理出 fd
 *
 *
 */
long protect_socket(int fd) {
#ifdef ANDROID
    long l_fd;
    if ((l_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
        return -1;
    struct timeval tv = {1};
    setsockopt(l_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval));
    setsockopt(l_fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(struct timeval));
    
    struct sockaddr_un sin;
    memset(&sin, 0, sizeof(struct sockaddr_un));
    sin.sun_family = AF_UNIX;
    strncpy(sin.sun_path, PROTECTPATH, sizeof(sin.sun_path) - 1);
    
    char b = 0;
    if (connect(l_fd, (struct sockaddr *) &sin, sizeof(struct sockaddr_un)) < 0 || ancil_send_fd(l_fd, fd) || recv(l_fd, &b, 1, 0) < 0) {
        closesocket(l_fd);
        return -1;
    }
    closesocket(l_fd);
    return b;
#else
    return 0;
#endif
}

/**
 * TURN 缺失函数
 *
 *
 */
long pj_rand() {
    srand(time(NULL));
    return (rand() & 0xFFFF) | ((rand() & 0xFFFF) << 16);
}
