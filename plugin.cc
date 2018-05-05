#include <map>
#include <string.h>
#include <iostream>
#include "plugin.h"
#include "rocws.h"

std::map<int, ws_link *> status_mgr;
roc_send_func *tcp_send;
int ws_send(roc_link *link, void *buf, int len)
{
    status_mgr[link->fd]->ws_send((char *)buf, len);
}

extern "C" {
void connect_handler(roc_link *link)
{
    link->svr->log(0, "TCP connected\n");
    status_mgr[link->fd] = new ws_link(link);
}

void recv_handler(roc_link *link)
{
    link->svr->log(0, "TCP data\n");
    status_mgr[link->fd]->tcp_recv();
}

void close_handler(roc_link *link)
{
}

void init_handler(roc_svr *svr)
{
    tcp_send = svr->send;
    svr->send = ws_send;
    svr->log(0, "svr inited\n");
}

void fini_handler(roc_svr *svr)
{
    svr->log(0, "svr finied\n");
}
}