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
 * $ gcc -g -o server server.c ./turnclient/win32/lib/libturnclient.a ./libevent-release-2.0.22-stable/win32/lib/libevent.a ./turnclient/win32/lib/libcrypto.a -I./libevent-release-2.0.22-stable/win32/include/ -I./turnclient/ -lws2_32 -lgdi32
 *
 *
 */
#include <assert.h>
#include <unistd.h>

#include <stdio.h>
#include <event.h>

#define MAX_BUF_SIZE 512
#define CLOSETIME 5

/**
 * TURN 刷新时间
 *
 *
 */
#define LIFETIME 600
#define REFRESHTIME (LIFETIME - 60)

/**
 * windows 下要是用 closesocket 函数关闭连接
 *
 *
 */
#ifndef WIN32
#define closesocket close
#endif

/**
 * 服务器结构,包含了当前 socks5 状态
 *
 *
 */
struct context_t {
    long status;
    
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

struct sync_t {
    long connected;
    struct bufferevent *bev;
};

struct event_base *base;
struct event *ev = NULL;

char *id;

char *manage_address = "202.109.165.79";
char *manage_port = "9000";
char *server_address = "203.156.199.168";
char *server_port = "5000";

/**
 * TURN 虚拟地址
 *
 *
 */
char  report_address[MAX_BUF_SIZE];
unsigned short report_port;

/**
 * 上报频率 (秒)
 *
 *
 */
char *sync_freq = "5";

void conn(int no_fd, short events, void *arg) {
    int fd = (int) arg;
    if (turnclient_refresh(fd, server_address, atoi(server_port), LIFETIME) == 0) {
        /**
         * refresh 失败会重连
         *
         *
         */
        struct timeval tv = {REFRESHTIME};
        evtimer_add(evtimer_new(base, conn,  (void *) fd), &tv);
    }
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
                context->status = 3;
                for (i = 0; i <(unsigned)  context->buf[1]; i++)
                    if (context->buf[2 + i] == 0) {
                        context->status = 1;
                        break;
                    }
                /**
                 * 没有支持的方法
                 *
                 *
                 */
                if (context->status == 3)
                    bufferevent_write(bev, "\x05\xFF", 2);
                else
                    bufferevent_write(bev, "\x05\x00", 2);
                
                context->pos -= len;
                if (context->pos)
                    memmove(&context->buf[0],&context->buf[len], context->pos);
            } else
                return ;
        } else if (context->status == 1) {
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
                        context->status = 3;
                    }
                    
                    if (context->status!= 3) {
                        context->status = 2;
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
                        context->status = 3;
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
        } else if (context->status == 2) {
            if (context->pos > 0) {
                bufferevent_write(context->remote, context->buf, context->pos);
                context->pos = 0;
            }
            return ;
        } else if (context->status == 3) {
            /**
             * 返回协议错误
             *
             *
             */
            struct timeval tv = {CLOSETIME};
            context->tick = evtimer_new(base, close_later, context);
            evtimer_add(context->tick, &tv);
            return ;
        }
    }
    return ;
}

/**
 * 创建一个新出口
 *
 *
 */
void open_server(int fd, short events, void *arg) {
    int new_fd;
    if (turnclient_wait_connection(fd, server_address, atoi(server_port), &new_fd, report_address) == 0) {
        fprintf(stdout, "accept a connection\n");
        /**
         * 当读写错误时关闭 fd
         *
         *
         */
        struct context_t *context = (struct context_t *) malloc(sizeof(struct context_t));
        memset(context, 0, sizeof(struct context_t));
        if (context) {
            struct bufferevent *bev = bufferevent_socket_new(base, new_fd, BEV_OPT_CLOSE_ON_FREE);
            
            context->server = bev;
            bufferevent_setcb(bev, server_read, NULL, status_quit, context);
            bufferevent_setwatermark(bev, EV_READ, 0, MAX_BUF_SIZE);
            bufferevent_enable(bev, EV_READ | EV_PERSIST);
        } else
            closesocket(new_fd);
    } else {
        /**
         * 重新建立到 turn 的连接
         *
         *
         */
        if (fd != -1) {
            closesocket(fd);
            event_del(ev);
        }
        if (init_turn_client(server_address, atoi(server_port), &fd, report_address, &report_port) == 0) {
            fprintf(stdout, "id: %s\nserver: %s:%s\nturn: %s:%s\nrelay: %s:%d\n", id, manage_address, manage_port, server_address, server_port, report_address, report_port);
            ev = event_new(base, fd, EV_READ | EV_PERSIST, open_server, NULL);
            event_add(ev, NULL);
            
            /**
             * 启动刷新
             *
             *
             */
            struct timeval tv = {REFRESHTIME};
            evtimer_add(evtimer_new(base, conn, (void *) fd), &tv);
        }
    }
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
            "\t -k id\n" \
            "\t[-m server address], default is 202.109.165.79\n" \
            "\t[-n server port], default is 9000\n" \
            "\t[-s turnserver address], default is 203.156.199.168\n" \
            "\t[-p turnserver port], default is 5000\n" \
            "\t[-t report frequency], default is 5(s)\n";
    fprintf(stdout, useage);
    return ;
}

/**
 * 出错时断开
 *
 *
 */
void status_rest(struct bufferevent *bev, short events, void *arg) {
    struct sync_t *s = (struct sync_t *) arg;
    if (events & (BEV_EVENT_ERROR | BEV_EVENT_EOF)) {
        s->connected = -1;
        bufferevent_free(bev);
    }
    return ;
}

/**
 * 定时上报参数
 *
 *
 */
void sync(int fd, short events, void *arg) {
    struct sync_t *s = (struct sync_t *) arg;
    if (s->connected) {
        struct bufferevent *bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
        s->bev = bev;
        bufferevent_socket_connect_hostname(bev, NULL, AF_INET, manage_address, atoi(manage_port));
        bufferevent_setcb(bev, NULL, NULL, status_rest, s);
        /**
         * 如果初始化 event 的时候设置了 EV_PERSIST,则使用 event_add 将其添加到侦听事件集合后(pending 状态),该 event 会持续保持 pending 状态,即该 event 可以无限次参加 libevent 的事件侦听
         *
         *
         */
        bufferevent_enable(bev, EV_PERSIST);
        s->connected =  0;
    }
    /**
     * 每次都更新 buf 上报一些运行状态
     *
     *
     */
    char buf[MAX_BUF_SIZE];
    sprintf(buf, "GET /manage/cgi/api!register.action?uid=%s&turn_server=%s:%s&relay_info=%s:%d&size=0 HTTP/1.1\r\nHost: 127.0.0.1:80\r\nConnection: Keep-Alive\r\n\r\n", id, server_address, server_port, report_address, report_port);
    bufferevent_write(s->bev, buf, strlen(buf));
    
    /**
     * 定时上报
     *
     *
     */
    struct timeval tv = {atoi(sync_freq)};
    evtimer_add(evtimer_new(base, sync,  s), &tv);
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
    while ((c = getopt(argc, argv, "k:m:n:s:p:t:")) != -1)
        switch(c) {
        case 'k':
            id             = optarg;
            break;
        case 'm':
            manage_address = optarg;
            break;
        case 'n':
            manage_port    = optarg;
            break;
        case 's':
            server_address = optarg;
            break;
        case 'p':
            server_port    = optarg;
            break;
        case 't':
            sync_freq      = optarg;
            break;
        }
    if (opterr) {
        show_useage();
        exit(0);
    }
    
    /**
     * TURN 地址,管理服务器地址均有默认值
     *
     *
     */
    if (id == NULL) {
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
    open_server(-1, EV_READ, NULL);
    
    struct sync_t s = {-1};
    
    /**
     * 定时上报
     *
     *
     */
    struct timeval tv = {atoi(sync_freq)};
    evtimer_add(evtimer_new(base, sync, &s), &tv);
    event_base_dispatch(base);
    
    return 0;
}
