#ifndef _CLIENTEV_H_
#define _CLIENTEV_H_
struct bufferevent;
void clientev_read_cb(struct bufferevent * bev, void * arg);
void clientev_event_cb(struct bufferevent *bev, short events, void *arg);
#endif
