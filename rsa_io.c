#include "rsa_num.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define HOMEDIR_LEN 255
#define RSADIR_LEN 4
#define RSASUBDIR_LEN 3
#define FILENAME_PREFFIX_LEN 255
#define COUNTER_MAX_LEN 4
#define FILENAME_SUFFIX_LEN 4
#define RSAPATH_LEN (HOMEDIR_LEN + 1 + RSADIR_LEN + 1 + RSASUBDIR_LEN + 1 + \
    FILENAME_PREFFIX_LEN + COUNTER_MAX_LEN + FILENAME_SUFFIX_LEN)

#define ENV_VAR_PATH "RSA_PATH"
#define ENV_HOME_DIR "HOME"
#define RSA_DIR ".rsa"
#define RSA_PRV_DIR "prv"
#define RSA_PUB_DIR "pub"
#define LOCAL_DIR "./"

#define SUFFIX_RSA ".rsa"
#define SUFFIX_DEC ".dec"
#define SUFFIX_PRV ".prv"
#define SUFFIX_PUB ".pub"

typedef int (* stat_func_t) (const char *fname, struct stat *buf);

static char rsa_path[RSAPATH_LEN];
#if RSA_MASTER || RSA_DECRYPTER
static char rsa_path_prv[RSAPATH_LEN];
#endif
#if RSA_MASTER || RSA_ENCRYPTER
static char rsa_path_pub[RSAPATH_LEN];
#endif

static int rsa_mkdir_single(char *prefix, char *new_dir)
{
    struct stat buf;
    char path[RSAPATH_LEN];

#if 0
    if (stat(prefix, &buf))
	return -1;
#endif

    /* path length must be less than RSAPATH_LEN */
    if (snprintf(path, RSAPATH_LEN, "%s/%s", prefix, new_dir) >= RSAPATH_LEN)
	return -1;

    /* create the new directory if it does not yet exist */
    if (stat(path, &buf) && mkdir(path, S_IRWXU | S_IRWXG | S_IRWXO))
	return -1;

    return 0;
}

static char *skip_slashes(char *str)
{
    for ( ; *str == '/'; str++);
    return str;
}

static int rsa_mkdir_full(char *path)
{
    char buf[RSAPATH_LEN], *start, *end;

    snprintf(buf, RSAPATH_LEN, "%s", path);
    end = buf;
    do
    {
	start = skip_slashes(end);
	end = strchr(start, '/');
	if (end)
	    *end = 0;
	if (rsa_mkdir_single(start == buf ? "./" : buf, start))
	    return -1;
	if (end)
	    *end = '/';
    }
    while (end);
    return 0;
}

int rsa_io_init(char *path)
{
    int ret = 0;

    /* path is either provided by command line or by environment variable */
    if (path || (path = getenv(ENV_VAR_PATH)))
	snprintf(rsa_path, HOMEDIR_LEN, "%s", path);
    /* assume path is at home directory */
    else
	snprintf(rsa_path, HOMEDIR_LEN, "%s/%s", getenv(ENV_HOME_DIR), RSA_DIR);

#if RSA_MASTER || RSA_DECRYPTER
    /* private key path */
    snprintf(rsa_path_prv, RSAPATH_LEN, "%s/%s", rsa_path, RSA_PRV_DIR);
    ret += rsa_mkdir_full(rsa_path_prv);
#endif
#if RSA_MASTER || RSA_ENCRYPTER
    /* puglic key path */
    snprintf(rsa_path_pub, RSAPATH_LEN, "%s/%s", rsa_path, RSA_PUB_DIR);
    ret += rsa_mkdir_full(rsa_path_pub);
#endif

    return ret;
}

static char *rsa_file_name(char *path, char *preffix, char *suffix, 
    stat_func_t stat_f, int is_new)
{
    static char name_buf[RSAPATH_LEN]; 
    char name_counter[COUNTER_MAX_LEN], *counter_ptr = name_buf + 
	strlen(path) + strlen(preffix);
    int i = 1, file_exists;
    struct stat buf;

    if (strlen(preffix) > FILENAME_PREFFIX_LEN)
	return NULL;
    bzero(name_buf, sizeof(name_buf));
    sprintf(name_buf, path);
    strcat(name_buf, preffix);
    strcat(name_buf, suffix);

    while ((file_exists = !stat_f(name_buf, &buf)) && is_new)
    {
	if (snprintf(name_counter, COUNTER_MAX_LEN, "_%i", i++) >= 
	    COUNTER_MAX_LEN)
	{
	    return NULL;
	}
	*counter_ptr = 0;
	strcat(name_buf, name_counter);
	strcat(name_buf, suffix);
    }

    return (file_exists && !is_new) || (!file_exists && is_new) ? name_buf : 
	NULL;
}

FILE *rsa_file_open(char *path, char *preffix, char *suffix, int is_slink, 
    int is_new)
{
    char *fname = NULL;

    if (!(fname = rsa_file_name(path, preffix, suffix, is_slink ? lstat : 
	stat, is_new)))
    {
	return NULL;
    }

    return fopen(fname, is_new ? "wb+" : "rb+");
}

int rsa_file_close(FILE *fp)
{
    return fclose(fp);
}

#if RSA_MASTER || RSA_DECRYPTER
FILE *rsa_file_create(char *suffix)
{
    char *preffix;

#if RSA_MASTER
    preffix = "master";
#else
    preffix = VENDOR;
#endif
    return rsa_file_open(LOCAL_DIR, preffix, suffix, 0, 1);
}

/* XXX create files in the .rsa/prv directory */
FILE *rsa_file_create_private(void)
{
    return rsa_file_create(SUFFIX_PRV);
}

/* XXX create files in the .rsa/pub directory */
FILE *rsa_file_create_public(void)
{
    return rsa_file_create(SUFFIX_PUB);
}
#endif

static int rsa_file_io_u1024(FILE *fptr, void *buf, int is_half, int is_write)
{
    int nmemb = block_sz_u1024;
    int size = BYTES_SZ(u64);

    if (is_half)
	nmemb /= 2;

    return nmemb != (is_write ? fwrite(buf, size, nmemb, fptr) : 
	fread(buf, size, nmemb, fptr));
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
    return rsa_file_io_u1024(fptr, num, 0, 1);
}

int rsa_file_read_u1024(FILE *fptr, u1024_t *num)
{
    return rsa_file_io_u1024(fptr, num, 0, 0);
}

int str2u1024_t(u1024_t *num, char *str)
{
    int i;

    number_reset(num);
    for (i = 0; i < (sizeof(u1024_t) / sizeof(char)) && str + i && *(str + i); 
	i++)
    {
	*((char *)num + i) = *(str + i);
    }

    return i;
}

int u1024_t2str(u1024_t *num, char *str)
{
    int i;

    bzero(str, sizeof(u1024_t) / sizeof(char));
    for (i = 0; i < (sizeof(u1024_t) / sizeof(char)) && *((char *)num + i); i++)
	*(str + i) = *((char *)num + i);

    return i;
}

#if RSA_MASTER || RSA_DECRYPTER
FILE *rsa_open_decryption_file(char *path, char *file_name)
{
    char *tmp_name;

    /* append .dec to encrypted file's name if it does not end with .rsa */
    if (strlen(file_name) <= strlen(SUFFIX_RSA) || strncmp(file_name + 
	(strlen(file_name) - strlen(SUFFIX_RSA)), SUFFIX_RSA, 
	strlen(SUFFIX_RSA)))
    {
	file_name = rsa_file_name(path, file_name, SUFFIX_DEC, stat, 1);
    }
    /* remove the .rsa suffix from the encrypted file's name */
    else
    {
	tmp_name = calloc(1, strlen(file_name) - (strlen(SUFFIX_RSA) - 1));
	memcpy(tmp_name, file_name, strlen(file_name) - strlen(SUFFIX_RSA));
	tmp_name[strlen(file_name)] = 0;
	file_name = rsa_file_name(path, tmp_name, "", stat, 1);
	free(tmp_name);
    }

    return file_name ? fopen(file_name, "wb+") : NULL;
}
#endif

#if RSA_MASTER || RSA_ENCRYPTER
FILE *rsa_open_encryption_file(char *path, char *file_name)
{
    /* append .rsa to the encrypted file's name */
    file_name = rsa_file_name(path, file_name, SUFFIX_RSA, stat, 1);

    return file_name ? fopen(file_name, "wb+") : NULL;
}
#endif

static FILE *rsa_key_open(char *preffix, int is_decrypt)
{
    char *path = NULL, *suffix = NULL;

#if RSA_MASTER || RSA_DECRYPTER
    if (is_decrypt)
    {
	path = rsa_path_prv;
	suffix = SUFFIX_PRV;
    }
#endif

#if RSA_MASTER || RSA_ENCRYPTER
    if (!is_decrypt)
    {
	path = rsa_path_pub;
	suffix = SUFFIX_PUB;
    }
#endif

    return rsa_file_open(path, preffix, suffix, 1, 0);
}

int rsa_key_get_params(char *vendor, u1024_t *n, u1024_t *exp, 
    u1024_t *montgomery_factor, int is_decrypt)
{
    FILE *key;

    if (!(key = rsa_key_open(vendor, is_decrypt)))
	return -1;

    number_reset(n);
    number_reset(exp);
    number_reset(montgomery_factor);

    if (rsa_file_read_u1024(key, n) || rsa_file_read_u1024(key, exp) || 
	rsa_file_read_u1024(key, montgomery_factor))
    {
	return -1;
    }

    rsa_file_close(key);
    return 0;
}


#if RSA_DECRYPTER || RSA_ENCRYPTER
int rsa_key_get_vendor(u1024_t *vendor, int is_decrypt)
{
    int i;
    FILE *key;

    if (!(key = rsa_key_open(VENDOR, is_decrypt)))
	return -1;

    for (i = 0; i < 3; i++)
    {
	if (rsa_file_read_u1024(key, vendor))
	    return -1;
    }

    number_reset(vendor);
    if (rsa_file_read_u1024(key, vendor))
	return -1;

    rsa_file_close(key);
    return 0;
}
#endif
