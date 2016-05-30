// +----------------------------------------------------------------------
// | ZYSOFT [ MAKE IT OPEN ]
// +----------------------------------------------------------------------
// | Copyright (c) 2016 ZYSOFT All rights reserved.
// +----------------------------------------------------------------------
// | Licensed ( http://www.apache.org/licenses/LICENSE-2.0 )
// +----------------------------------------------------------------------
// | Author: zy_cwind <391321232@qq.com>
// +----------------------------------------------------------------------

/**
 * $ gcc -g -o server_socks5 server_socks5.c ./turnclient/win32/lib/libturnclient.a ./libevent-release-2.0.22-stable/win32/lib/libevent.a ./turnclient/win32/lib/libcrypto.a -I./libevent-release-2.0.22-stable/win32/include/ -I./turnclient/ -lws2_32 -lgdi32
 *
 *
 */
#include <assert.h>
#include <unistd.h>

#include <stdio.h>
#include <event.h>
#include <event2/listener.h>

#define MAX_BUF_SIZE 512
#define CLOSETIME 5

#define EXPIRE 300

/**
 * windows 下要是用 closesocket 函数关闭连接
 *
 *
 */
#ifndef WIN32
#define closesocket close
#endif

typedef struct cache_t cache_t;

struct cache_t {
    /**
     * 对每个用户流量进行统计
     * 
     * 
     */
    long tx;
    long rx;
    
    long expire;
    char buf[MAX_BUF_SIZE];
    long len;
    
    cache_t *next;
    cache_t *prev;
};

/**
 * 服务器结构,包含了当前 socks5 状态
 *
 *
 */
struct context_t {
    long status;
    cache_t *ua;
    
    /**
     * 处理后剩下的数据
     *
     *
     */
    char buf[MAX_BUF_SIZE];
    long pos;
    
    struct event *tick;
    struct bufferevent *server;
    struct bufferevent *remote;
};

struct socks5_request_t {
    char ver;
    char cmd;
    char rsv;
    
    /**
     * 地址类型
     *
     *
     */
    char atyp;
};

struct cache_t head;

struct event_base *base;
struct event *ev = NULL;

char *listen_address = "127.0.0.1";
char *listen_port = "8888";

/**
 * 鉴权地址
 *
 *
 */
char *server_auth;

void verify_user(struct context_t *context) {
    int ulen = context->buf[1];
    int plen = context->buf[ulen + 2];
    cache_t *p =  head.next;
    cache_t *q = &head;
    while (p) {
        if (!memcmp(&p->buf[0], &context->buf[0], 2 + ulen + 1 + plen))
            break;
        q = p;
        p = p->next;
    }
    /**
     * 通过缓存验证
     *
     *
     */
    if (p) {
        if (time(NULL) < p->expire + EXPIRE) {
            p->prev->next = p->next;
            p->next->prev = p->prev;
            free(p);
        } else {
            context->ua = p;
            context->status = 2;
            return;
        }
    }
    /**
     * 通过接口验证用户,验证通过,进行存储,使用 curl 在另一个线程请求
     *
     *
     */
    
}

void freecontext(struct context_t *context) {
    fprintf(stdout, "connection closed\n");
    
    bufferevent_free(context->server);
    if (context->remote)
        bufferevent_free(context->remote);
    free(context);
}

void close_later(int fd, short events, void *arg) {
    freecontext((struct context_t *) arg);
}

/**
 * 出错时断开
 *
 *
 */
void status_quit(struct bufferevent *bev, short events, void *arg) {
    struct context_t *context = (struct context_t *) arg;
    if (events & (BEV_EVENT_ERROR | BEV_EVENT_EOF)) {
        /**
         * 删除 timer
         * 
         * 
         */
        if (context->tick)
            evtimer_del(context->tick);
        freecontext(context);
    }
    return ;
}

void remote_read(struct bufferevent *bev, void *arg) {
    struct context_t *context = (struct context_t *) arg;
    bufferevent_write_buffer(context->server, bufferevent_get_input(bev));
    return ;
}

/**
 * 创建一个新连接
 *
 *
 */
void open_remote(struct context_t *context, struct sockaddr_in *sin) {
    fprintf(stdout, "connect to %s:%d\n", inet_ntoa(sin->sin_addr), ntohs(sin->sin_port));
    
    struct bufferevent *bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
    bufferevent_socket_connect(bev, (struct sockaddr *) sin, sizeof(struct sockaddr_in));
    bufferevent_setcb(bev, remote_read, NULL, status_quit, context);
    bufferevent_enable(bev, EV_READ | EV_PERSIST);
    context->remote = bev;
    return ;
}

void server_read(struct bufferevent *bev, void *arg) {
    struct context_t *context = (struct context_t *) arg;
    
    long size;
    if ((size = bufferevent_read(bev, &context->buf[context->pos], sizeof(context->buf) - context->pos)) < 0) {
        freecontext(context);
        return ;
    }
    context->pos += size;
    while (1) {
        long len;
        if (context->status == 0) {
            /**
             * VER NMETHOD METHOD
             *
             *
             */
            if (context->pos >= 2 && context->pos >= (len = context->buf[1] + 2)) {
                if (context->buf[0]!= 5) {
                    freecontext(context);
                    return ;
                }
                
                unsigned long i;
                context->status = 4;
                for (i = 0; i <(unsigned)  context->buf[1]; i++)
                    if (context->buf[2 + i] == 2) {
                        context->status = 1;
                        break;
                    }
                /**
                 * 没有支持的方法
                 *
                 *
                 */
                if (context->status == 4)
                    bufferevent_write(bev, "\x05\xFF", 2);
                else
                    bufferevent_write(bev, "\x05\x02", 2);
                
                context->pos -= len;
                if (context->pos)
                    memmove(&context->buf[0],&context->buf[len], context->pos);
            } else
                return ;
        } else if (context->status == 1) {
            /**
             * VER ULEN UNAME PLEN PASSWD
             *
             *
             */
            if (context->pos >= 2 && context->pos >= (len = context->buf[1] + 2) && context->pos >= (len += context->buf[context->buf[1] + 2] + 1)) {
                if (context->buf[0]!= 1) {
                    freecontext(context);
                    return ;
                }
                
                context->status = 5;
                verify_user(context);
                
                context->pos -= len;
                if (context->pos)
                    memmove(&context->buf[0],&context->buf[len], context->pos);
            } else
                return ;
        } else if (context->status == 2) {
            /**
             * VER CMD RSV ATYP DST.ADDR DST.PORT
             *
             *
             */
            if (context->pos >= 4) {
                if (context->buf[0]!= 5) {
                    freecontext(context);
                    return ;
                }
                
                struct socks5_request_t *request = (struct socks5_request_t *) &context->buf[0];
                char buf[MAX_BUF_SIZE] = {0x05, 0x00, 0x00, 0x01};
                /**
                 * 返回的地址类型不能是 domain_name
                 *
                 *
                 */
                
                if (request->cmd == 1) {
                    /**
                     * CONNECT
                     *
                     *
                     */
                    struct sockaddr_in sin;
                    
                    if (request->atyp == 1) {
                        if (context->pos >= 10) {
                            sin.sin_family = AF_INET;
                            sin.sin_addr = * (struct in_addr *) &context->buf[4];
                            sin.sin_port = * (unsigned short *) &context->buf[8];
                            memcpy(&buf[8], &sin.sin_port, sizeof(unsigned short));
                            
                            context->pos -= 10;
                            if (context->pos)
                                memmove(&context->buf[0], &context->buf[10], context->pos);
                        } else
                            return ;
                    } else if (request->atyp == 3) {
                        if (context->pos >= 4 && context->pos >= (len = context->buf[4] + 7)) {
                            char domain_name[MAX_BUF_SIZE];
                            memcpy(domain_name, &context->buf[5], context->buf[4]);
                            domain_name[context->buf[4]] = 0;
                            struct hostent *host;
                            if ((host = gethostbyname(domain_name)) == NULL) {
                                freecontext(context);
                                return ;
                            }
                            sin.sin_family = AF_INET;
                            sin.sin_addr = * (struct in_addr *) host->h_addr;
                            sin.sin_port = * (unsigned short *) &context->buf[len - 2];
                            memcpy(&buf[8], &sin.sin_port, sizeof(unsigned short));
                            
                            context->pos -= len;
                            if (context->pos)
                                memmove(&context->buf[0], &context->buf[len], context->pos);
                        } else
                            return ;
                    } else {
                        /**
                         * 不支持的地址类型
                         *
                         *
                         */
                        buf[1] = 8;
                        context->status = 4;
                    }
                    
                    if (context->status!= 4) {
                        context->status = 3;
                        open_remote(context,  &sin);
                    }
                } else {
                    /**
                     * 不支持的命令
                     *
                     *
                     */
                    {
                        buf[1] = 7;
                        context->status = 4;
                    }
                }
                {
                    /**
                     * BND.ADDR BND.PORT 返回相关端口
                     *
                     *
                     */
                    bufferevent_write(bev, buf, 10);
                }
            } else
                return ;
        } else if (context->status == 3) {
            if (context->pos > 0) {
                bufferevent_write(context->remote, context->buf, context->pos);
                context->pos = 0;
            }
            return ;
        } else if (context->status == 4) {
            /**
             * 返回协议错误
             *
             *
             */
            struct timeval tv = {CLOSETIME};
            context->tick = evtimer_new(base, close_later, context);
            evtimer_add(context->tick, &tv);
            context->status = 5;
        } else if (context->status == 5)
            return ;
    }
    return ;
}

/**
 * 创建一个新出口
 *
 *
 */
void open_server(struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *sin, int slen, void *arg) {
    fprintf(stdout, "accept a connection\n");
    /**
     * 当读写错误时关闭 fd
     *
     *
     */
    struct context_t *context = (struct context_t *) malloc(sizeof(struct context_t));
    memset(context, 0, sizeof(struct context_t));
    if (context) {
        struct bufferevent *bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
        
        context->server = bev;
        bufferevent_setcb(bev, server_read, NULL, status_quit, context);
        bufferevent_setwatermark(bev, EV_READ, 0, MAX_BUF_SIZE);
        bufferevent_enable(bev, EV_READ | EV_PERSIST);
    } else
        closesocket(fd);
    return ;
}

/**
 * 输出帮助,必要参数为管理服务器地址
 *
 *
 */
void show_useage() {
    const char *useage = \
        "useage:\n" \
            "\t -u authentication url\n" \
            "\t[-b listen address], default is 127.0.0.1\n" \
            "\t[-i listen port], default is 8888\n";
    fprintf(stdout, useage);
    return ;
}

long main(int argc, char *argv[]) {
#ifdef WIN32
    WSADATA wsaData;
    assert(WSAStartup(MAKEWORD(1, 1), &wsaData) == 0);
#endif

    /**
     * 参数配置
     *
     *
     */
    opterr = 0;
    
    int c;
    while ((c = getopt(argc, argv, "u:b:i:")) != -1)
        switch(c) {
        case 'u':
            server_auth    = optarg;
            break;
        case 'b':
            listen_address = optarg;
            break;
        case 'i':
            listen_port    = optarg;
            break;
        }
    if (opterr) {
        show_useage();
        exit(0);
    }
    
    if (server_auth == NULL) {
        show_useage();
        exit(0);
    }
    
    /**
     * 启动服务
     *
     *
     */
    base = event_base_new();
    assert(base != NULL);
    
    /**
     * 监听连接
     *
     *
     */
    struct sockaddr_in sin;
    struct hostent *host;
    assert(host = gethostbyname(listen_address));
    sin.sin_family = AF_INET;
    sin.sin_addr = * (struct in_addr *) host->h_addr;
    sin.sin_port = htons(atoi(listen_port));
    assert(evconnlistener_new_bind(base, open_server, NULL, LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, 5, (struct sockaddr *) &sin, sizeof(struct sockaddr)));
    
    fprintf(stdout, "listen: %s:%s\n", listen_address, listen_port);
    
    event_base_dispatch(base);
    
    return 0;
}
