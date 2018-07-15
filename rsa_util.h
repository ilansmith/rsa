#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdio.h>
#include "rsa_num.h"

#define MAX_FILE_NAME_LEN 256
#define MAX_LINE_LENGTH 128
#define KEY_DATA_MAX_LEN 16
#define MAX_HIGHLIGHT_STR 128

#define ARRAY_SZ(arr) (sizeof(arr) / sizeof(arr[0]))
#define IS_WHITESPACE(c) ((c) == ' ' || (c) == '\t')

#define C_GREY "\033[00;37m"
#define C_NORMAL "\033[00;00;00m"
#define C_HIGHLIGHT "\033[01m"
#define C_INDENTATION_FMT "\r\E[%dC%%s"

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

typedef enum {
    V_NORMAL = 0,
    V_QUIET,
    V_VERBOSE,
} verbose_t;

typedef enum {
    RSA_ERR_NONE,
    RSA_ERR_ARGREP,
    RSA_ERR_NOACTION,
    RSA_ERR_MULTIACTION,
    RSA_ERR_FNAME_LEN,
    RSA_ERR_FILE_TOO_LARGE,
    RSA_ERR_FILE_NOT_EXIST,
    RSA_ERR_FILE_IS_DIR,
    RSA_ERR_FILE_NOT_REG,
    RSA_ERR_NOFILE,
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
    RSA_ERR_KEY_OPEN,
    RSA_ERR_KEY_TYPE,
    RSA_ERR_LEVEL,
    RSA_ERR_INTERNAL,
} rsa_errno_t;

int code2code(code2code_t *list, int code);
char *code2str(code2str_t *list, int code);

void rsa_error_message(rsa_errno_t err, ...);
void rsa_warning_message(rsa_errno_t err, ...);
int rsa_printf(int is_verbose, int ind, char *fmt, ...);
char *rsa_strcat(char *dest, char *fmt, ...);
char *rsa_vstrcat(char *dest, char *fmt, va_list ap);
int rsa_sprintf_nows(char *str, char *fmt, ...);
int rsa_read_u1024(FILE *file, u1024_t *num);
int rsa_write_u1024(FILE *file, u1024_t *num);
int rsa_read_u1024_full(FILE *file, u1024_t *num);
int rsa_write_u1024_full(FILE *file, u1024_t *num);
int rsa_read_str(FILE *file, char *str, int len);
int rsa_write_str(FILE *file, char *str, int len);
void rsa_verbose_set(verbose_t level);
verbose_t rsa_verbose_get(void);
int is_fwrite_enable(char *name);
char *rsa_highlight_str(char *fmt, ...);
int rsa_timeline_init(int len);
void rsa_timeline(void);
void rsa_timeline_uninit(void);
#endif

