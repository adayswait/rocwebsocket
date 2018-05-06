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
void connect_handler(roc_link *link, void *custom_data)
{
    link->svr->log(0, "TCP connected\n");
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
    link->svr->log(0, "TCP data\n");
    status_mgr[link->fd]->tcp_recv();
}

void close_handler(roc_link *link, void *custom_data)
{
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
    svr->log(0, "svr inited:%d\n", svr->next_plugin_level);
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
    svr->log(0, "svr finied\n");
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
