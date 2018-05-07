/**
 *  本文件中的所有数据结构均应与rocnet相同 
 */

#ifndef PLUGIN_H
#define PLUGIN_H

#include <time.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <algorithm>

typedef struct
{
    uint32_t head;
    uint32_t tail;
    char *data;
    uint32_t size;
} roc_ringbuf;

static inline uint32_t roc_ringbuf_read(roc_ringbuf *self,
                                        char *data,
                                        uint32_t len)
{
    uint32_t head_n;
    len = std::min(len, self->tail - self->head);
    head_n = std::min(len, self->size - (self->head & (self->size - 1)));
    memcpy(data, self->data + (self->head & (self->size - 1)), head_n);
    memcpy(data + head_n, self->data, len - head_n);
    self->head += len; /* 到达最大值后溢出, 逻辑仍然成立 */
    return len;
}
struct roc_svr_s;
struct roc_link_s;
typedef struct roc_svr_s roc_svr;
typedef struct roc_link_s roc_link;
typedef void roc_handle_func_link(roc_link *link, void *custom_data);
typedef void roc_handle_func_svr(roc_svr *svr, void *custom_data);
typedef int roc_send_func(roc_link *link, void *buf, int len);
typedef void roc_log_func(int level, const char *format, ...);

struct roc_plugin_s;
typedef struct roc_plugin_s roc_plugin;
struct roc_plugin_s
{
    void *so_handle;
    void *data_so_handle;
    roc_handle_func_link *connect_handler;
    roc_handle_func_link *recv_handler;
    roc_handle_func_link *close_handler;

    roc_handle_func_svr *init_handler;
    roc_handle_func_svr *fini_handler;
    int level; /* level == -1表示该插件未初始化 */
};

#define ROC_EVENT_NONE 0
#define ROC_EVENT_INPUT 1
#define ROC_EVENT_OUTPUT 2
#define ROC_EVENT_BARRIER 4
#define ROC_EVENT_EPOLLET 8
#define ROC_EVENT_IOET (ROC_EVENT_INPUT | ROC_EVENT_OUTPUT | ROC_EVENT_EPOLLET)

#define ROC_SOCK_CONNECT 0
#define ROC_SOCK_DATA 0
#define ROC_SOCK_DRAIN 1
#define ROC_SOCK_CLOSE 2
#define ROC_SOCK_EVTEND 3

#define ROC_NOMORE -1
#define ROC_DELETED_EVENT_ID -1

#define ROC_FILE_EVENTS 1
#define ROC_TIME_EVENTS 2
#define ROC_ALL_EVENTS (ROC_FILE_EVENTS | ROC_TIME_EVENTS)
#define ROC_DONT_WAIT 4
#define ROC_CALL_AFTER_SLEEP 8

struct roc_evt_loop;

/* Types and data structures */
typedef void roc_io_proc(struct roc_evt_loop *evt_loop,
                         int fd, void *custom_data, int mask);
typedef int roc_time_proc(struct roc_evt_loop *evt_loop,
                          int64_t id, void *custom_data);

/* File event structure */
typedef struct roc_io_evt
{
    int mask; /* one of ROC_(INPUT_EVENT|OUTPUT_EVENT|EVENT_BARRIER) */
    roc_io_proc *iporc;
    roc_io_proc *oproc;
    void *custom_data;
} roc_io_evt;

/* Time event structure */
typedef struct roc_time_evt
{
    int64_t id;       /* time event identifier. */
    int64_t when_sec; /* seconds */
    int64_t when_ms;  /* milliseconds */
    roc_time_proc *tproc;
    void *custom_data;
    struct roc_time_evt *next;
} roc_time_evt;

typedef struct roc_ready_evt
{
    int fd;
    int mask;
} roc_ready_evt;

typedef struct roc_evt_loop
{
    int size;           /* max number of file descriptors tracked */
    volatile int maxfd; /* highest file descriptor currently registered */

    roc_io_evt *all_io_evts; /* Registered events */
    roc_time_evt *time_evt_head;
    roc_ready_evt *ready_evts; /* Fired events */

    int64_t time_evt_next_id;
    time_t last_time; /* Used to detect system clock skew */

    int stop;
    int epfd;
    struct epoll_event *ret_evts;
} roc_evt_loop;

#define ROC_PLUGIN_MAX 16

struct roc_svr_s
{
    int fd;
    int port;
    int domain;
    int type;
    int backlog;
    int maxlink;
    int nonblock;
    int next_plugin_level;
    roc_evt_loop *evt_loop;
    roc_handle_func_link *handler[ROC_SOCK_EVTEND];
    roc_handle_func_link *close_link;
    roc_plugin plugin[ROC_PLUGIN_MAX];
    roc_send_func *send;
    roc_log_func *log;
};

struct roc_link_s
{
    int fd;
    int port;
    char *ip;
    int next_plugin_level;
    roc_ringbuf *ibuf;
    roc_ringbuf *obuf;
    roc_evt_loop *evt_loop;
    roc_handle_func_link *handler[ROC_SOCK_EVTEND];
    roc_svr *svr;
};

#endif
