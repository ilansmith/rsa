#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdio.h>
#include "rsa_num.h"

#define MAX_LINE_LENGTH 128
#define KEY_ID_MAX_LEN 16

#define ARRAY_SZ(arr) (sizeof(arr) / sizeof(arr[0]))
#define IS_WHITESPACE(c) ((c) == ' ' || (c) == '\t')

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
    RSA_ERR_NOFILE,
    RSA_ERR_FOPEN,
    RSA_ERR_FILEIO,
    RSA_ERR_OPTARG,
    RSA_ERR_KEYPATH,
    RSA_ERR_KEYNAME,
    RSA_ERR_KEYGEN,
    RSA_ERR_LEVEL,
    RSA_ERR_INTERNAL
} rsa_errno_t;

int code2code(code2code_t *list, int code);
char *code2str(code2str_t *list, int code);

void output_error_message(rsa_errno_t err);
int rsa_printf(int is_verbose, int ind, char *fmt, ...);
char *rsa_strcat(char *dest, char *fmt, ...);
int rsa_sprintf_nows(char *str, char *fmt, ...);
int rsa_read_u1024(FILE *file, u1024_t *num);
int rsa_write_u1024(FILE *file, u1024_t *num);
void rsa_verbose_set(verbose_t level);
#endif

