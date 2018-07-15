#ifndef _RSA_STREAM_H_
#define _RSA_STREAM_H_

#include <stdlib.h>
#include <stdio.h>

#define EOS (-1)

typedef void rsa_stream_t;

enum rsa_stream_type {
	RSA_STREAM_TYPE_FILE,
	RSA_STREAM_TYPE_MEMORY,
	RSA_STREAM_TYPE_NONE,
};

struct rsa_stream_init {
	enum rsa_stream_type type;
	union {
		/* file based parameters */
		struct {
			char *path;
			char *mode;
		} file;
		/* memory based parameters */
		struct {
			unsigned char *buf;
			int len;
		} memory;
	} params;
};

rsa_stream_t *sopen(struct rsa_stream_init *init);
int sclose(rsa_stream_t *s);

size_t sread(void *ptr, size_t size, size_t nmemb, rsa_stream_t *s);
size_t swrite(void *ptr, size_t size, size_t nmemb, rsa_stream_t *s);
int sseek(rsa_stream_t *s, long offset, int whence);
#endif

