#ifndef _RSA_STREAM_H_
#define _RSA_STREAM_H_

#include <stdlib.h>
#include <stdio.h>

#define EOB (-1)

typedef struct {
	unsigned char *buf;
	int length;
	int current;
	unsigned char mode; /* read: 1<<0, write: 1<<1 */
} BUFFER;

BUFFER *bopen(const char *path, const char *mode);
int bclose(BUFFER *bp);

size_t bread(void *ptr, size_t size, size_t nmemb, BUFFER *buffer);
size_t bwrite(const void *ptr, size_t size, size_t nmemb, BUFFER *buffer);
int bseek(BUFFER *buffer, long offset, int whence);


#endif

