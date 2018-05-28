#include <map>
#include <string.h>
#include <iostream>
#include "roc_interface.h"
#include "roc_websocket.h"

std::map<int, ws_link *> status_mgr;
roc_send_func *tcp_send;
int ws_send(roc_link *link, void *buf, int len)
{
    status_mgr[link->fd]->ws_send((char *)buf, len);
}

extern "C" {
void connect_handler(roc_link *link, void *custom_data)
{
    link->svr->log(0, "ws tcp connected\n");
    status_mgr[link->fd] = new ws_link(link);
    link->next_plugin_level++;
    if (link->svr->plugin[link->next_plugin_level].level != -1)
    {
        link->svr->plugin[link->next_plugin_level]
            .connect_handler(link, custom_data);
    }
    else
    {
        link->next_plugin_level = 0;
    }
}

void recv_handler(roc_link *link, void *custom_data)
{
    link->svr->log(0, "ws tcp data\n");
    status_mgr[link->fd]->tcp_recv();
}

void close_handler(roc_link *link, void *custom_data)
{
    int fd = link->fd;
    delete status_mgr[fd];
    status_mgr.erase(fd);
    link->svr->log(0, "ws tcp closed,fd:%d\n", fd);
    link->next_plugin_level++;
    if (link->svr->plugin[link->next_plugin_level].level != -1)
    {
        link->svr->plugin[link->next_plugin_level]
            .close_handler(link, custom_data);
    }
    else
    {
        link->next_plugin_level = 0;
    }
}

void init_handler(roc_svr *svr, void *custom_data)
{
    tcp_send = svr->send;
    svr->send = ws_send;
    svr->log(0, "ws svr inited:%d\n", svr->next_plugin_level);
    svr->next_plugin_level++;
    if (svr->plugin[svr->next_plugin_level].level != -1)
    {
        svr->plugin[svr->next_plugin_level]
            .init_handler(svr, custom_data);
    }
    else
    {
        svr->next_plugin_level = 0;
    }
}

void fini_handler(roc_svr *svr, void *custom_data)
{
    svr->log(0, "ws svr finied\n");
    svr->next_plugin_level++;
    if (svr->plugin[svr->next_plugin_level].level != -1)
    {
        svr->plugin[svr->next_plugin_level]
            .fini_handler(svr, custom_data);
    }
    else
    {
        svr->next_plugin_level = 0;
    }
}
}
