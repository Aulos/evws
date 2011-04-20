/*
 * Author: Pawel Zubrycki <paw.zubr@gmail.com>
 */

#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>

void md5_buffer(unsigned char *password, uint8_t * ikey);
void md5_buffer_c(unsigned char *password, char key[33]);

#endif

