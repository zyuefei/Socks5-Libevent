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
 * $ gcc -o server.dll -shared server.c ./turnclient/win32/lib/libturnclient.a ./libevent-release-2.0.22-stable/win32/lib/libevent.a -I./libevent-release-2.0.22-stable/win32/include/ -I./turnclient/ -lws2_32 -lgdi32 -static-libgcc
 *
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
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
 * 根
 *
 *
 */
#define ROOT_ADDR "proxy.zed1.cn"
#define ROOT_PORT 9000

/**
 * windows 下要是用 closesocket 函数关闭连接
 *
 *
 */
#ifndef WIN32
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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

/**
 * HTTP报文
 *
 */
struct http_t {
    char  buf[MAX_BUF_SIZE];
    long  pos;
    void *arg;
    /**
     * 回调
     *
     */
    void (*callback)(struct http_t *context);
};

struct event_base *base;
/**
 * TURN 连接事件
 *
 *
 */
struct event *ev = NULL;

char  id[MAX_BUF_SIZE];

char manage_address[MAX_BUF_SIZE];
unsigned short manage_port;
char server_address[MAX_BUF_SIZE];
unsigned short server_port;
char report_address[MAX_BUF_SIZE];
unsigned short report_port;

/**
 * 日志文件
 * 在安卓下统一输出到 LOGCAT
 *
 */
FILE *log_fd;

/**
 * 上报频率 (秒)
 *
 *
 */
char *beat_freq = "30";

void conn(int *fd) {
    if (turnclient_refresh(*fd, server_address, server_port, LIFETIME)) {
        closesocket(*fd);
        event_del(ev);
        *fd = -1;
    }
}

void freecontext(struct context_t *context) {
    fprintf(log_fd, "connection closed\n");
    
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
    fprintf(log_fd, "connect to %s:%d\n", inet_ntoa(sin->sin_addr), ntohs(sin->sin_port));
    
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
 * 简易的 HTTP 处理
 *
 *
 */
void http_packet(struct bufferevent *bev, void *arg) {
    struct http_t *context = (struct http_t *) arg;
    if (context->callback)
        if ((context->pos = bufferevent_read(bev, context->buf, sizeof(context->buf))) > 0)
            context->callback(context);
    /**
     * 不解析报头以及 content
     *
     *
     */
    bufferevent_free(bev);
    free(context);
}

void http_status(struct bufferevent *bev, short events, void *arg) {
    struct http_t *context = (struct http_t *) arg;
    if (events & (BEV_EVENT_ERROR | BEV_EVENT_EOF)) {
        bufferevent_free(bev);
        free(context);
    }
    /**
     * 一次性的
     *
     *
     */
    if (events &  BEV_EVENT_CONNECTED)
        bufferevent_write(bev, context->buf, context->pos);
    return ;
}

/**
 * 定时上报参数
 *
 *
 */
void beat() {
    struct http_t *context = (struct http_t *) malloc(sizeof(struct http_t));
#ifdef NODLL
    sprintf(context->buf, "GET /manage/cgi/api!register.action?uid=%s&turn_server=%s:%d&relay_info=%s:%d&size=0&type=0&mac= HTTP/1.1\r\nHost: 127.0.0.1:80\r\nConnection: Keep-Alive\r\n\r\n", id, server_address, server_port, report_address, report_port);
#else
    sprintf(context->buf, "GET /manage/cgi/api!register.action?uid=%s&turn_server=%s:%d&relay_info=%s:%d&size=0&type=0&mac= HTTP/1.1\r\nHost: 127.0.0.1:80\r\nConnection: Keep-Alive\r\n\r\n", id, server_address, server_port, report_address, report_port);
#endif
    context->pos = strlen(context->buf);
    context->arg = NULL;
    context->callback = NULL;
    
    struct bufferevent *bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
    bufferevent_socket_connect_hostname(bev, NULL, AF_INET, manage_address, manage_port);
    bufferevent_setcb(bev, http_packet, NULL, http_status, context);
    /**
     * 如果初始化 event 的时候设置了 EV_PERSIST,则使用 event_add 将其添加到侦听事件集合后(pending 状态),该 event 会持续保持 pending 状态,即该 event 可以无限次参加 libevent 的事件侦听
     *
     *
     */
    bufferevent_enable(bev, EV_READ | EV_PERSIST);
    return ;
}

/**
 * 创建一个新出口
 *
 *
 */
void open_server(int fd, short events, void *arg) {
    int  new_fd;
    int *tun_fd = (int *) arg;
    if (turnclient_wait_connection(fd, server_address, server_port, &new_fd, report_address)) {
        closesocket(fd);
        event_del(ev);
        *tun_fd = -1;
    } else {
        fprintf(log_fd, "accept a connection\n");
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
            "\t[-t report frequency], default is 30(s)\n" \
            "\t[-f log file]\n";
    fprintf(stdout, "%s", useage);
    return ;
}

/**
 * 设置管理服务器
 *
 *
 */
void init_manage(struct http_t *context) {
    char *address = strstr(context->buf, "\r\n\r\n") + 4;
    char *port;
    if (address) {
        port = strstr(address, ":");
        if (port) {
            memset(manage_address, 0, MAX_BUF_SIZE);
            memcpy(manage_address, address, port - address);
            
            char buf[MAX_BUF_SIZE];
            memset(buf, 0, MAX_BUF_SIZE);
            port++;
            memcpy(buf, port, context->buf + context->pos - port);
            manage_port = atoi(buf);
            * (int *) context->arg = 1;
            return ;
        }
    }
    return ;
}

void guid(struct http_t *context) {
    char *uid = strstr(context->buf, "\"uid\":") + 7;
    if (uid) {
        char *address = strstr(context->buf, "\"uri\":") + 7;
        char *port;
        if (address) {
            port = strstr(address, ":");
            if (port) {
                memset(id, 0, MAX_BUF_SIZE);
                memcpy(id, uid, strstr(uid, "\"") - uid);
                
                memset(server_address, 0, MAX_BUF_SIZE);
                memcpy(server_address, address, port - address);
                
                char buf[MAX_BUF_SIZE];
                memset(buf, 0, MAX_BUF_SIZE);
                port++;
                memcpy(buf, port, strstr(port, "\"") - port);
                server_port = atoi(buf);
                
                * (int *) context->arg = 2;
                return ;
            }
        }
    }
    return ;
}

/**
 * 定时任务
 *
 *
 */
void step(int fd, short events, void *arg) {
    static unsigned long second;
    static int tun_fd = -1;
    
    /**
     * 管理流程
     *
     *
     */
    static int state;
    static int timer;
    
    /**
     * 重连
     *
     *
     */
    if (tun_fd == -1) {
        switch(state) {
        case 0:
            {
                /**
                 * 从指定的接口获取管理
                 *
                 *
                 */
                struct http_t *context = (struct http_t *) malloc(sizeof(struct http_t));
#ifdef NODLL
                sprintf(context->buf, "GET /manage/cgi/root!getManageServer.action?type=1 HTTP/1.1\r\nHost: 127.0.0.1:80\r\nConnection: Keep-Alive\r\n\r\n");
#else
                sprintf(context->buf, "GET /manage/cgi/root!getManageServer.action?type=0 HTTP/1.1\r\nHost: 127.0.0.1:80\r\nConnection: Keep-Alive\r\n\r\n");
#endif
                context->pos = strlen(context->buf);
                context->arg = &state;
                context->callback = init_manage;
                
                struct bufferevent *bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
                bufferevent_socket_connect_hostname(bev, NULL, AF_INET, ROOT_ADDR, ROOT_PORT);
                bufferevent_setcb(bev, http_packet, NULL, http_status, context);
                bufferevent_enable(bev, EV_READ | EV_PERSIST);
                /**
                 * 等待设定
                 *
                 *
                 */
                timer = 0;
                state = 3;
            }
            break;
        case 1:
            {
                /**
                 * 从管理获取 id
                 *
                 *
                 */
                struct http_t *context = (struct http_t *) malloc(sizeof(struct http_t));
                sprintf(context->buf, "GET /manage/cgi/api!getTurnList.action HTTP/1.1\r\nHost: 127.0.0.1:80\r\nConnection: Keep-Alive\r\n\r\n");
                context->pos = strlen(context->buf);
                context->arg = &state;
                context->callback = guid;
                
                struct bufferevent *bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
                bufferevent_socket_connect_hostname(bev, NULL, AF_INET, manage_address, manage_port);
                bufferevent_setcb(bev, http_packet, NULL, http_status, context);
                bufferevent_enable(bev, EV_READ | EV_PERSIST);
                
                timer = 0;
                state = 3;
            }
            break;
        case 2:
            {
                if (init_turn_client(server_address, server_port, &tun_fd, report_address, &report_port) == 0) {
                    fprintf(log_fd, "id: %s\nserver: %s:%d\nturn: %s:%d\nrelay: %s:%d\n", id, manage_address, manage_port, server_address, server_port, report_address, report_port);
                    ev = event_new(base, tun_fd, EV_READ | EV_PERSIST, open_server, &tun_fd);
                    event_add(ev, NULL);
                    second =  0;
                } else if (tun_fd != -1) {
                    closesocket(tun_fd);
                    tun_fd = -1;
                }
                state = 0;
            }
            break;
        case 3:
            /**
             * 超时
             *
             *
             */
            if (++timer == 30)
                state = 0;
            break;
        }
    }
    
    if (tun_fd != -1)
        if (second % REFRESHTIME == 0)
            conn(&tun_fd);
    if (tun_fd != -1)
        if (!(second % atoi(beat_freq)))
            beat();
    
    second++;
    struct timeval tv = {1};
    evtimer_add(evtimer_new(base, step, NULL), &tv);
}

#ifdef NODLL
long main(int argc, char *argv[]) {
#else
long loop(int argc, char *argv[]) {
#endif
    char *log_file = NULL;
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
    while ((c = getopt(argc, argv, "t:f:")) != -1)
        switch(c) {
        case 't':
            beat_freq      = optarg;
            break;
        case 'f':
            log_file       = optarg;
            break;
        }
    if (opterr) {
        show_useage();
        exit(0);
    }
    
    log_fd = stdout;
    if (log_file) {
        FILE *fp = fopen(log_file, "a");
        if (fp)
            log_fd = fp;
    }
    
    /**
     * 启动服务
     *
     *
     */
    base = event_base_new();
    assert(base != NULL);
    
    /**
     * 消息循环
     *
     *
     */
    step(0, EV_TIMEOUT, NULL);
    event_base_dispatch(base);
    fclose(log_fd);
    
    return 0;
}
