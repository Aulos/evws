/*
 * Author: Pawel Zubrycki <paw.zubr@gmail.com>
 */

#include <mhash.h>
#include "utils.h"

void md5_buffer(unsigned char *password, uint8_t * ikey) {
	int len = 0;
	for(; password[len] != '\0'; ++len);
	mhash_keygen(KEYGEN_MCRYPT, MHASH_MD5, 1, ikey, 16, NULL, 0, (uint8_t *)password, len);
}


void md5_buffer_c(unsigned char *password, char *key) {
	uint8_t ikey[16];
	int i;
	md5_buffer(password, ikey);
	for(i = 0; i < 16; ++i)
		sprintf(&(key[2*i]), "%.2x", ikey[i]);
	key[32] = '\0';
}

