#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "rsa_stream.h"

#define MIN(a, b) ((a) < (b) ? (a) : (b))

#define EOB (-1)

typedef struct {
	unsigned char *buf;
	int length;
	int current;
} BUFFER;

struct rsa_stream {
	union {
		FILE *file;
		BUFFER *buffer;
	} data;
	enum rsa_stream_type type;
};

static void stream_err(const char *fmt, ...)
{
	va_list va;

	fprintf(stderr, "rsa stream error: ");
	va_start(va, fmt);
	vfprintf(stderr, fmt, va);
	va_end(va);
	fprintf(stderr, "\n");
}

static BUFFER *bopen(unsigned char *buf, int len)
{
	BUFFER *buffer;

	if (!(buffer = (BUFFER*)calloc(1, sizeof(BUFFER))))
		return NULL;

	if (buf) {
		buffer->length = len;
		buffer->buf = (unsigned char*)calloc(len,
			sizeof(unsigned char));

		if (!buffer->buf) {
			free(buffer);
			return NULL;
		}

		memcpy(buffer->buf, buf, len);
	}

	buffer->current = 0;
	return buffer;
}

static int bclose(BUFFER *buffer)
{
	free(buffer->buf);
	free(buffer);
	return 0;
}

static size_t bio(void *ptr, size_t size, size_t nmemb, BUFFER *buffer,
		int is_read)
{
	size_t ret;
	size_t bytes;
	void *from;
	void *to;

	if (!size || !nmemb)
		return 0;

	if (is_read) {
		from = (void*)(buffer->buf + buffer->current);
		to = ptr;
	} else {
		from = ptr;
		to = (void*)(buffer->buf + buffer->current);
	}

	ret = MIN(nmemb, (buffer->length - buffer->current) / size);
	bytes = ret * size;
	memcpy(to, from, bytes);
	buffer->current += bytes;
	return ret;
}

static size_t bread(void *ptr, size_t size, size_t nmemb, BUFFER *buffer)
{
	return bio(ptr, size, nmemb, buffer, 1);
}

static size_t bwrite(void *ptr, size_t size, size_t nmemb, BUFFER *buffer)
{
	if ((buffer->length - buffer->current) / size < nmemb) {
		buffer->length = buffer->current + nmemb * size;
		buffer->buf = realloc(buffer->buf, buffer->length);
		if (!buffer->buf) {
			buffer->length = 0;
			buffer->current = 0;
			return 0;
		}
	}

	return bio(ptr, size, nmemb, buffer, 0);
}

static int bseek(BUFFER *buffer, long offset, int whence)
{
	switch (whence) {
	case SEEK_SET:
		if (buffer->length < offset) {
			buffer->length = offset;
			buffer->buf = realloc(buffer->buf, buffer->length);
			if (!buffer->buf) {
				buffer->length = 0;
				buffer->current = 0;
				return -1;
			}
		}

		buffer->current = offset;
		break;
		/* not supported */
	case SEEK_CUR:
	case SEEK_END:
	default:
		return -1;
	}

	return 0;
}

rsa_stream_t *sopen(struct rsa_stream_init *init)
{
	struct rsa_stream *stream;
	char *stream_type;

	stream = (struct rsa_stream*)calloc(1, sizeof(struct rsa_stream));
	if (!stream)
		return NULL;

	switch (init->type) {
	case RSA_STREAM_TYPE_FILE:
		stream->data.file = fopen(init->params.file.path,
			init->params.file.mode);
		if (!stream->data.file) {
			stream_type = "file";
			goto error;
		}
		break;
	case RSA_STREAM_TYPE_MEMORY:
		stream->data.buffer = bopen(init->params.memory.buf,
			init->params.memory.len);
		if (!stream->data.buffer) {
			stream_type = "memory";
			goto error;
		}
		break;
	default:
		goto error;
		break;
	}

	stream->type = init->type;
	return (rsa_stream_t*)stream;

error:
	free(stream);
	stream_err("could not open %s based stream", stream_type);
	return NULL;
}

int sclose(rsa_stream_t *s)
{
	struct rsa_stream *stream = (struct rsa_stream*)s;
	int ret;

	switch (stream->type) {
	case RSA_STREAM_TYPE_FILE:
		ret = fclose(stream->data.file);
		break;
	case RSA_STREAM_TYPE_MEMORY:
		ret = bclose(stream->data.buffer);
		break;
	default:
		ret = EOS;
		break;
	}

	free(stream);
	return ret;
}

static size_t sio(void *ptr, size_t size, size_t nmemb,
		struct rsa_stream *stream, int is_read)
{
	switch (stream->type) {
	case RSA_STREAM_TYPE_FILE:
		if (is_read)
			return fread(ptr, size, nmemb, stream->data.file);
		else
			return fwrite(ptr, size, nmemb, stream->data.file);
	case RSA_STREAM_TYPE_MEMORY:
		if (is_read)
			return bread(ptr, size, nmemb, stream->data.buffer);
		else
			return bwrite(ptr, size, nmemb, stream->data.buffer);
	default:
		break;
	}

	return 0;
}

size_t sread(void *ptr, size_t size, size_t nmemb, rsa_stream_t *s)
{
	struct rsa_stream *stream = (struct rsa_stream*)s;

	return sio(ptr, size, nmemb, stream, 1);
}

size_t swrite(void *ptr, size_t size, size_t nmemb, rsa_stream_t *s)
{
	struct rsa_stream *stream = (struct rsa_stream*)s;

	return sio(ptr, size, nmemb, stream, 0);
}

int sseek(rsa_stream_t *s, long offset, int whence)
{
	struct rsa_stream *stream = (struct rsa_stream*)s;

	switch (stream->type) {
	case RSA_STREAM_TYPE_FILE:
		return fseek(stream->data.file, offset, whence);
	case RSA_STREAM_TYPE_MEMORY:
		return bseek(stream->data.buffer, offset, whence);
	default:
		break;
	}

	return -1;
}

