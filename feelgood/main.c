#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <pthread.h>
#include <unistd.h>
#include <event2/thread.h>
void readcb(struct bufferevent *bev, void *arg) {
	struct evbuffer *in = bufferevent_get_input(bev);
	size_t len = evbuffer_get_length(in);
	unsigned char *p = evbuffer_pullup(in, len);
	for(int i=0; i<len; i++)
		putchar(p[i]);
	evbuffer_drain(in, len);
}

void *child(void *arg) {
	struct event *timeout = (struct event *) arg;
	while(1) {
		sleep(1);

		struct timeval tv;
		tv.tv_sec = 0;
		tv.tv_usec = 0;
		evtimer_add(timeout, &tv);
	}
	pthread_exit(NULL);
}

void timeout_cb(int fd, short event, void *arg) {
	printf("timeout\n");
}

int main() {
	pthread_t t;
	printf("hello\n");
	//evthread_use_pthreads();
	struct event_base *evbase = event_base_new();
	
	struct event *timeout = evtimer_new(evbase, timeout_cb, NULL);
	pthread_create(&t, NULL, child, timeout);


	struct bufferevent *bev = bufferevent_socket_new(evbase, 0, BEV_OPT_CLOSE_ON_FREE);
	bufferevent_enable(bev, EV_READ);
	bufferevent_disable(bev, EV_WRITE);
	bufferevent_setcb(bev, readcb, NULL, NULL, NULL);
	event_base_loop(evbase , 0);
	
}

