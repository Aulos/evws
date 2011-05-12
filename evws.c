/*
 * Author: Pawel Zubrycki <paw.zubr@gmail.com>
 */

#include "evws.h"
#include "utils.h"
#include <stdlib.h>
#include <string.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

void gen_md5(const char *k1, const char *k2, const char *k3, char *out);
static int evws_parse_first_line(struct evws_connection *conn, char *line);
static int evws_parse_header_line(char *line, char **skey, char **svalue);

// Callbacks
void cb_accept(struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *address, int socklen, void *ctx); 
void cb_accept_error(evutil_socket_t fd, short what, void *arg);
void cb_read_handshake(struct bufferevent *bev, void *arg);
void cb_read(struct bufferevent *bev, void *arg);

struct evws *evws_new(struct event_base *base)
{
	struct evws *ret_obj = (struct evws*)calloc(1, sizeof(struct evws));
	ret_obj->base = base;
	ret_obj->listener = NULL;

	TAILQ_INIT(&ret_obj->connections);
	TAILQ_INIT(&ret_obj->callbacks);

	return ret_obj;
}

void evws_free(struct evws *ptr)
{
	// Tu wiecej czyszczenia
	free(ptr);
}

void evws_bind_socket(struct evws * ws, unsigned short port)
{
	struct sockaddr_in sin;

	// Creating serverside socket
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(0);
	sin.sin_port = htons(port);

	if(!(ws->listener = evconnlistener_new_bind(ws->base, cb_accept, ws, LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE, -1, (struct sockaddr*)&sin, sizeof(sin)))) {
		return;
	}
}

int evws_set_cb(struct evws * ws, const char * uri, cb_type cb, void * arg)
{
	struct evws_cb *ws_cb;

	TAILQ_FOREACH(ws_cb, &ws->callbacks, next) {
		if (strcmp(ws_cb->uri, uri) == 0)
			return (-1);
	}

	if((ws_cb = (struct evws_cb*)calloc(1, sizeof(struct evws_cb))) == NULL) {
		return (-2);
	}

	ws_cb->uri = (char*)strdup(uri);
	ws_cb->cb = cb;
	ws_cb->cb_arg = arg;

	TAILQ_INSERT_TAIL(&ws->callbacks, ws_cb, next);

	return (0);
}

cb_type evws_set_gencb(struct evws *ws, cb_type cb, void * arg)
{
	cb_type old_cb = ws->gencb;
	ws->gencb = cb;
	ws->gencb_arg = arg;
	return old_cb;
}

// Broadcast data to all buffers associated with pattern
void evws_broadcast(struct evws *ws, const char *uri, void *data)
{
	struct evws_connection *ws_connection;
	TAILQ_FOREACH(ws_connection, &ws->connections, next) {
		if (strcmp(ws_connection->uri, uri) == 0)
			evws_send_data(ws_connection, data);
	}
}

void evws_send_data(struct evws_connection *conn, char *data)
{
	char tmp[255] = {0x00};
	strcpy(tmp+1, data);
	tmp[strlen((char*)data)+1] = 0xFF;
	struct evbuffer *buffer =  bufferevent_get_output(conn->bufev);
	evbuffer_add(buffer, tmp, strlen((char*)data)+2);
}

void gen_md5(const char *k1, const char *k2, const char *k3, char *out) 
{
	unsigned int spaces = 0, len;
	unsigned long num1 = 0, num2 = 0;
	unsigned char buf[17];
	int i;
	const char * k; 
	unsigned char *tmp; 

	k = k1;
	tmp = buf;
	for(i=0; i < 2; ++i, k = k2, tmp = buf + 4){
		unsigned long num = 0;
		unsigned int spaces = 0;
		char * end = (char*)k + strlen(k);
		for (; k != end; ++k) {
			spaces += (int)(*k == ' ');
			if (*k >= '0' && *k <= '9')
				num = num * 10 + (*k - '0');
		}
		num /= spaces;
		tmp[0] = (num & 0xff000000) >> 24;
		tmp[1] = (num & 0xff0000) >> 16;
		tmp[2] = (num & 0xff00) >> 8;
		tmp[3] = num & 0xff;
	}

	memcpy(buf + 8, k3, 8);
	buf[16] = '\0';

	md5_buffer(buf, (uint8_t*)out);
	out[16] = '\0';
}

//Callback to accept
void cb_accept(struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *address, int socklen, void *arg)
{
	struct evws *ws = arg;
	struct evws_connection *ws_conn = evws_connection_new(ws, fd);
	
	bufferevent_setcb(ws_conn->bufev, cb_read_handshake, NULL, NULL, ws_conn);
	bufferevent_enable(ws_conn->bufev, EV_READ);
}

int evws_parse_first_line(struct evws_connection *conn, char *line)
{
	char *method;
	char *uri;
	char *version;
	const char *hostname;
	const char *scheme;

	/* Parse the request line */
	method = strsep(&line, " ");
	if (line == NULL)
		return (-1);
	uri = strsep(&line, " ");
	if (line == NULL)
		return (-1);
	version = strsep(&line, " ");
	if (line != NULL)
		return (-1);

	if ((conn->uri = strdup(uri)) == NULL) {
		return (-1);
	}

	return (0);
}

// Callback to read handshake
void cb_read_handshake(struct bufferevent *bev, void *arg)
{
	struct evws_connection *ws_conn = arg;
	char *line, *skey, *svalue;
	struct evbuffer *buffer = bufferevent_get_input(bev);
	size_t line_length;
	const char *key1, *key2, *host, *origin, *proto;
	char key3[21], chksum[17];

	switch(ws_conn->state) {
	case 0:
		line = evbuffer_readln(buffer, &line_length, EVBUFFER_EOL_CRLF);
		evws_parse_first_line(ws_conn, line);
		ws_conn->state = 1;
		free(line);
	case 1:
		while ((line = evbuffer_readln(buffer, &line_length, EVBUFFER_EOL_CRLF))
			   != NULL) {
			if (*line == '\0') { /* Last header - Done */
				free(line);
				ws_conn->state = 2;
				break;
			}
			evws_parse_header_line(line, &skey, &svalue);
			if(strcmp(skey, "Sec-WebSocket-Protocol") == 0) {
				ws_conn->protocol = strdup(svalue);
			}else{ 
				struct evws_header *header = evws_header_new(skey, svalue);
				TAILQ_INSERT_TAIL(&ws_conn->headers, header, next);
			}

			free(line);
		}
	case 2:
		{
			int n = evbuffer_remove(buffer, key3, sizeof(key3)-1);
			key3[n] = '\0';
			ws_conn->state = 3;
			break;
		}
	case 3:
		break;
	default:
		break;
	};

	key1 = evws_find_header(&ws_conn->headers, "Sec-WebSocket-Key1");
	key2 = evws_find_header(&ws_conn->headers, "Sec-WebSocket-Key2");
	host = evws_find_header(&ws_conn->headers, "Host");
	origin = evws_find_header(&ws_conn->headers, "Origin");
	gen_md5(key1, key2, key3, chksum); 
	{
		char location[255] = "ws://";
		strcpy(&(location[5]), host);
		strcpy(&(location[5+strlen(host)]), ws_conn->uri);
		evbuffer_add_printf(bufferevent_get_output(ws_conn->bufev), 
			"HTTP/1.1 101 WebSocket Protocol Handshake\r\n"
			"Upgrade: WebSocket\r\n"
			"Connection: Upgrade\r\n"
			"Sec-WebSocket-Origin: %s\r\n"
			"Sec-WebSocket-Location: %s"
			"%s%s\r\n"
			"\r\n"
			"%s", 
			origin, location,
			(ws_conn->protocol != NULL) ? "\r\nSec-WebSocket-Protocol: " : "",
			(ws_conn->protocol != NULL) ? ws_conn->protocol : "",
			chksum
		);
	}
	bufferevent_setcb(ws_conn->bufev, cb_read, NULL, NULL, ws_conn);

	TAILQ_INSERT_TAIL(&(ws_conn->ws->connections), ws_conn, next);
}

int evws_parse_header_line(char *line, char **skey, char **svalue)
{
	*svalue = line;
	*skey = strsep(svalue, ":");
	if (*svalue == NULL)
		return -1;

	*svalue += strspn(*svalue, " ");

	return (0);
}

// Callback to read sent data
void cb_read(struct bufferevent *bev, void *arg)
{
	struct evws_connection *conn = arg;
	struct evws *ws = conn->ws;
	char readbuf[256];
	struct evbuffer *buffer = bufferevent_get_input(bev);
	int n = evbuffer_remove(buffer, readbuf, sizeof(readbuf)-1);
	if(n > 0){
		struct evws_cb *ws_cb;
		readbuf[n-1] = '\0';
		TAILQ_FOREACH(ws_cb, &ws->callbacks, next) {
			if (strcmp(ws_cb->uri, conn->uri) == 0) {
				ws_cb->cb(conn, readbuf+1, ws_cb->cb_arg);
				return;
			}
		}
		ws->gencb(conn, readbuf+1, ws->gencb_arg);
	}
}

struct evws_connection *evws_connection_new(struct evws *ws, evutil_socket_t fd)
{
	struct evws_connection *conn = calloc(1, sizeof(struct evws_connection));
	conn->ws = ws;
	conn->fd = fd;
	conn->bufev = bufferevent_socket_new(ws->base, fd, BEV_OPT_CLOSE_ON_FREE);
	conn->state = 0; // Read first line
	TAILQ_INIT(&conn->headers);
	return conn;
}

void evws_connection_free(struct evws_connection *conn)
{
	struct evws_header *header;
	bufferevent_free(conn->bufev);
	free(conn->uri);
	free(conn->protocol);
	TAILQ_FOREACH(header, &conn->headers, next) {
		evws_header_free(header);
	}
	free(conn);
}

struct evws_header *evws_header_new(char *key, char *value)
{
	struct evws_header *head = calloc(1, sizeof(struct evws_header));
	head->key = strdup(key);
	head->value = strdup(value);
	return head;
}

void evws_header_free(struct evws_header *header)
{
	free(header->key);
	free(header->value);
	free(header);
}

char *evws_find_header(const struct wsheadersq *q, const char *key)
{
	struct evws_header *hdr;
	char * ret = NULL;
	TAILQ_FOREACH(hdr, q, next) {
		if(strcmp(hdr->key, key) == 0) {
			ret = hdr->value;
			break;
		}
	}
	return ret;
}

