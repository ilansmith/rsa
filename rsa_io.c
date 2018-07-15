#include "rsa.h"
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define FILENAME_PREFFIX_LEN 255
#define COUNTER_MAX_LEN 3
#define FILENAME_SUFFIX ".rsa"
#define FILENAME_SUFFIX_LEN 4

typedef int (* stat_func_t) (const char *fname, struct stat *buf);
typedef int (* io_func_t)(void *ptr, size_t size, size_t nmemb, FILE *stream);

static char *rsa_file_name(char *preffix, stat_func_t stat_f, int is_new)
{
    static char name_buf[FILENAME_PREFFIX_LEN + FILENAME_SUFFIX_LEN + 1]; 
    char name_counter[COUNTER_MAX_LEN], *counter_ptr = name_buf + 
	strlen(preffix) + 1;
    int i = 1, file_exists;
    struct stat buf;

    if (strlen(preffix) > FILENAME_PREFFIX_LEN)
	return NULL;
    strncpy(name_buf, preffix, FILENAME_PREFFIX_LEN);
    strcat(name_buf, FILENAME_SUFFIX);

    while ((file_exists = !stat_f(name_buf, &buf)) && is_new)
    {
	if (snprintf(name_counter, COUNTER_MAX_LEN, "_%i", i++) >= 
	    COUNTER_MAX_LEN)
	{
	    return NULL;
	}
	*counter_ptr = 0;
	strcat(name_buf, name_counter);
	strcat(name_buf, FILENAME_SUFFIX);
    }

    return (file_exists && !is_new) || (!file_exists && is_new) ? name_buf : 
	NULL;
}

FILE *rsa_file_open(char *preffix, int is_slink, int is_new)
{
    char *fname = NULL;

    if (!(fname = rsa_file_name(preffix, is_slink ? lstat : stat, is_new)))
	return NULL;

    return fopen(fname, is_new ? "w+" : "r+");
}

int rsa_file_close(FILE *fp)
{
    return fclose(fp);
}

static int rsa_file_io_u1024(FILE *fptr, void *buf, int is_half, int is_write)
{
    int nmemb = BYTES_SZ(u1024_t) / BYTES_SZ(u64);
    int size = sizeof(u64);
    io_func_t io_func = is_write ? (io_func_t)fwrite : (io_func_t)fread;

    if (is_half)
	nmemb /= 2;

    return io_func(buf, size, nmemb, fptr);
}

static int rsa_file_io_u1024_half(FILE *fptr, u1024_t *num, int is_write, 
    int is_hi)
{
    u64 *ptr = is_hi ? (u64 *)num + (BYTES_SZ(u1024_t)) / BYTES_SZ(u64) : 
	(u64 *)num;

    return rsa_file_io_u1024(fptr, (void *)ptr, 1, is_write);
}

int rsa_file_write_u1024_hi(FILE *fptr, u1024_t *num)
{
    return rsa_file_io_u1024_half(fptr, num, 1, 1);
}

int rsa_file_read_u1024_hi(FILE *fptr, u1024_t *num)
{
    return rsa_file_io_u1024_half(fptr, num, 0, 1);
}

int rsa_file_write_u1024_low(FILE *fptr, u1024_t *num)
{
    return rsa_file_io_u1024_half(fptr, num, 1, 0);
}

int rsa_file_read_u1024_low(FILE *fptr, u1024_t *num)
{
    return rsa_file_io_u1024_half(fptr, num, 0, 0);
}

int rsa_file_write_u1024(FILE *fptr, u1024_t *num)
{
    return rsa_file_io_u1024(fptr, (void *)fptr, 0, 1);
}

int rsa_file_read_u1024(FILE *fptr, u1024_t *num)
{
    return rsa_file_io_u1024(fptr, (void *)fptr, 0, 0);
}

