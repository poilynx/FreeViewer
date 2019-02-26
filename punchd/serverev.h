#ifndef _SERVEREV_H_
#define _SERVEREV_H_
#include <event2/bufferevent.h>
void serverev_event_cb(struct bufferevent *bev, short events, void *arg);
void serverev_read_cb(struct bufferevent *bev, void *arg);
void serverev_write_cb(struct bufferevent *bev, void *arg);
#endif
