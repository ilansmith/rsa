#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdio.h>
#include "rsa_num.h"
#include "rsa_stream.h"
#include "mt19937_64.h"

#define MAX_FILE_NAME_LEN 256
#define MAX_LINE_LENGTH 128
#define KEY_DATA_MAX_LEN 16
#define MAX_HIGHLIGHT_STR 128

#define ARRAY_SZ(arr) (sizeof(arr) / sizeof(arr[0]))
#define IS_WHITESPACE(c) ((c) == ' ' || (c) == '\t')

#ifdef CONFIG_RSA_COLOURS
#define C_GREY "\033[00;37m"
#define C_NORMAL "\033[00;00;00m"
#define C_HIGHLIGHT "\033[01m"
#else
#define C_GREY ""
#define C_NORMAL ""
#define C_HIGHLIGHT ""
#endif
#define C_INDENTATION_FMT "\r\E[%dC%%s"

#ifdef CONFIG_MERSENNE_TWISTER
#define RSA_RANDOM() (u64)genrand64_int64()
#else
#if defined(__linux__)
#define RSA_RANDOM() (u64)random()
#else
#define RSA_RANDOM() (u64)rand()
#endif
#endif

#define RSA_KEY_TYPE_PRIVATE (1<<0)
#define RSA_KEY_TYPE_PUBLIC (1<<1)

typedef enum {
	V_NORMAL = 0,
	V_QUIET,
	V_VERBOSE,
} verbose_t;

typedef enum {
	RSA_ERR_NONE,
	RSA_ERR_REVISION,
	RSA_ERR_ARGREP,
	RSA_ERR_ARGNAN,
	RSA_ERR_TIMUNIT,
	RSA_ERR_ARGCONFLICT,
	RSA_ERR_NOACTION,
	RSA_ERR_MULTIACTION,
	RSA_ERR_FNAME_LEN,
	RSA_ERR_FILE_TOO_LARGE,
	RSA_ERR_FILE_NOT_EXIST,
	RSA_ERR_FILE_IS_DIR,
	RSA_ERR_FILE_NOT_REG,
	RSA_ERR_FOPEN,
	RSA_ERR_FILEIO,
	RSA_ERR_OPTARG,
	RSA_ERR_KEYPATH,
	RSA_ERR_KEYNAME,
	RSA_ERR_KEYGEN,
	RSA_ERR_KEYNOTEXIST,
	RSA_ERR_KEYMULTIENTRIES,
	RSA_ERR_KEY_STAT_PUB_DEF,
	RSA_ERR_KEY_STAT_PRV_DEF,
	RSA_ERR_KEY_STAT_PRV_DYN,
	RSA_ERR_KEY_CORRUPT,
	RSA_ERR_KEY_CORRUPT_BUF,
	RSA_ERR_KEY_OPEN,
	RSA_ERR_KEY_OPEN_BUF,
	RSA_ERR_KEY_TYPE,
	RSA_ERR_KEY_TYPE_BUF,
	RSA_ERR_BUFFER_NULL,
	RSA_ERR_STREAM_TYPE_UNKNOWN,
	RSA_ERR_LEVEL,
	RSA_ERR_INTERNAL,
} rsa_errno_t;

typedef struct code2code_t {
	int code;
	int val;
	int disabled;
} code2code_t;

typedef struct code2str_t {
	int code;
	char *str;
	int disabled;
} code2str_t;

typedef struct rsa_key_t {
	struct rsa_key_t *next;
	char type;
	char name[KEY_DATA_MAX_LEN];
	rsa_stream_t *stream;
	struct rsa_stream_init stream_init;
	u1024_t n;
	u1024_t exp;
} rsa_key_t;

extern int rsa_encryption_level;

int code2code(code2code_t *list, int code);
char *code2str(code2str_t *list, int code);

void rsa_error_message(rsa_errno_t err, ...);
void rsa_warning_message(rsa_errno_t err, ...);
int rsa_printf(int is_verbose, int ind, char *fmt, ...);
char *rsa_strcat(char *dest, char *fmt, ...);
char *rsa_vstrcat(char *dest, char *fmt, va_list ap);
int rsa_sprintf_nows(char *str, char *fmt, ...);
int rsa_read_u1024(rsa_stream_t *s, u1024_t *num);
int rsa_write_u1024(rsa_stream_t *s, u1024_t *num);
int rsa_read_u1024_full(rsa_stream_t *s, u1024_t *num);
int rsa_write_u1024_full(rsa_stream_t *s, u1024_t *num);
int rsa_read_str(rsa_stream_t *s, char *str, int len);
int rsa_write_str(rsa_stream_t *s, char *str, int len);
void rsa_verbose_set(verbose_t level);
verbose_t rsa_verbose_get(void);
#if defined (__linux__)
int is_fwrite_enable(char *name);
#endif
char *rsa_highlight_str(char *fmt, ...);
int rsa_timeline_init(int len, int write_block_sz);
void rsa_timeline_update(void);
void rsa_timeline_uninit(void);

void rsa_encode(u1024_t *res, u1024_t *data, u1024_t *exp, u1024_t *n);
void rsa_decode(u1024_t *res, u1024_t *data, u1024_t *exp, u1024_t *n);
rsa_key_t *rsa_key_open(struct rsa_stream_init *init, char accept,
	int is_expect_key);
void rsa_key_close(rsa_key_t *key);
int rsa_key_enclev_set(rsa_key_t *key, int new_level);
int rsa_encrypt_seed(rsa_key_t *key, rsa_stream_t *ciphertext);

int is_optional_argument(int argc, char **argv, char **optarg, int *optind);
char *comma_separated_tok(char *str);

#endif

