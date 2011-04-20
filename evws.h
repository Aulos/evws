/*
 * Author: Pawel Zubrycki <paw.zubr@gmail.com>
 */

#ifndef EVWS_H
#define EVWS_H

#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>
#include <sys/queue.h>
#include "utils.h"

struct evws_header
{
	TAILQ_ENTRY(evws_header) next;
	char *key;
	char *value;
};

struct evws_header *evws_header_new(char *key, char *value);
void evws_header_free(struct evws_header *header);

struct evws_connection
{
	TAILQ_ENTRY(evws_connection) next;
	struct evws *ws;
	char *uri;
	char *protocol;
	struct bufferevent *bufev;
	int state;
	int fd;
	TAILQ_HEAD(wsheadersq, evws_header) headers;
};

char *evws_find_header(const struct wsheadersq *q, const char *key);

typedef void (*cb_type)(struct evws_connection *, char *, void *);

struct evws_cb
{
	TAILQ_ENTRY(evws_cb) next;
	char * uri;
	cb_type cb;
	void * cb_arg;
};

struct evws_connection *evws_connection_new(struct evws *ws, evutil_socket_t fd);
void evws_connection_free(struct evws_connection *conn);

TAILQ_HEAD(evwsconq, evws_connection);

struct evws
{
	struct evconnlistener *listener;

	TAILQ_HEAD(wscbq, evws_cb) callbacks;

	struct evwsconq connections;

	// generic callback
	cb_type gencb;
	void * gencb_arg;

	struct event_base *base;
};

struct evws *evws_new(struct event_base *base);
void evws_free(struct evws *ptr);
void evws_bind_socket(struct evws * ws, unsigned short port);
int evws_set_cb(struct evws * ws, const char * pattern, cb_type cb, void * arg);
cb_type evws_set_gencb(struct evws *ws, cb_type cb, void * arg);
void evws_broadcast_data(struct evws *ws, const char *pattern, void *data);
void evws_send_data(struct evws_connection *conn, char *data);

#endif
