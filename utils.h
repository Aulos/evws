#ifndef UTILS_H
#define UTILS_H
#include <stdint.h>
#include <event2/event_struct.h>

void md5_buffer(unsigned char *password, uint8_t * ikey);
void md5_buffer_c(unsigned char *password, char key[33]);

#endif

