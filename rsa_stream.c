#include <stdlib.h>
#include <stdio.h>

#define MODE_READ (1<<0)
#define MODE_WRITE (1<<1)

#define MIN(a, b) ((a) < (b) ? (a) : (b))

BUFFER *bopen(const char *path, const char *mode)
{
	BUFFER *buffer;
	int *buf;

	if (!(buffer = (BUFFER*)calloc(1, sizeof(BUFFER))))
		return NULL;

	if (path) {
		buffer->length = *(int*)path;
		buffer->buf = (unsigned char*)calloc(length,
			sizeof(unsigned char));

		if (!buffer->buf) {
			free(buffer);
			return NULL;
		}

		memcpy(buffer->buf, path + sizeof(int), buffer->length);
	}

	buffer->current = 0;
	buffer->mode = MODE_READ | MODE_WRITE;
	return buffer;
}

int bclose(BUFFER *bp)
{
	free(buffer->buf);
	free(buffer);
	return 0;
}

static bio(void *ptr, size_t size, size_t nmemb, BUFFER *buffer, int is_read)
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

size_t bread(void *ptr, size_t size, size_t nmemb, BUFFER *buffer)
{
	return bio(ptr, size, nmemb, buffer, 1);
}

size_t bwrite(const void *ptr, size_t size, size_t nmemb, BUFFER *buffer)
{
	if ((buffer->length - buffer->current) / size < nmemb) {
		buffer->length = buffer->current + nmemb * size;
		buffer->buf = realloc(buffer->buf, buffer->length);
		if (!bufer->buf) {
			buffer->length = 0;
			buffer->current = 0;
			return 0;
		}
	}

	return bio(ptr, size, nmemb, buffer, 0);
}

int bseek(BUFFER *buffer, long offset, int whence)
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
	case SEEK_CUR:
	default:
		return -1;
	}

	return 0;
}

