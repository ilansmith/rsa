#include <string.h>
#include <stdarg.h>
#include "rsa_util.h"

static verbose_t is_cprintf;
typedef int (* io_func_t)(void *ptr, int size, int nmemb, FILE *stream);

int code2code(code2code_t *list, int code)
{
    for (; list->code != -1 && list->code != code; list++);

    return list->code == -1 ? -1 : list->val;
}

char *code2str(code2str_t *list, int code)
{
    for (; list->code != -1 && list->code != code; list++);

    return list->code == -1 ? "" : list->str;
}

int rsa_printf(int is_verbose, int ind, char *fmt, ...)
{
    va_list ap;
    int ret = 0;
    char fmt_eol[MAX_LINE_LENGTH];

    if (is_cprintf == V_QUIET || (is_verbose && is_cprintf == V_NORMAL))
	goto Exit;

    if (ind + strlen(fmt) + 1 >= MAX_LINE_LENGTH)
    {
	ret = -1;
	goto Exit;
    }

    snprintf(fmt_eol, MAX_LINE_LENGTH, "%*s%s%s%s\n", 2*ind, "", 
	is_verbose  ? C_GREY : C_NORMAL, fmt, C_NORMAL);
    va_start(ap, fmt);
    ret = vprintf(fmt_eol, ap);
    fflush(stdout);
    va_end(ap);

Exit:
    return ret;
}

char *rsa_strcat(char *dest, char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vsprintf(dest + strlen(dest), fmt, ap);
    va_end(ap);

    return dest;
}

char *rsa_vstrcat(char *dest, char *fmt, va_list ap)
{
    vsprintf(dest + strlen(dest), fmt, ap);

    return dest;
}

int rsa_sprintf_nows(char *str, char *fmt, ...)
{
    va_list ap;
    int ret;

    va_start(ap, fmt);
    ret = vsprintf(str, fmt, ap);
    va_end(ap);

    for ( ; *str; str++)
    {
	if (IS_WHITESPACE(*str))
	    *str = '_';
    }
    return ret;
}

static void rsa_message(int is_error, rsa_errno_t err, va_list ap)
{
    char msg[MAX_LINE_LENGTH];

    sprintf(msg, "%s: ", is_error ? "error" : "warning");
    switch (err)
    {
    case RSA_ERR_ARGREP:
	rsa_vstrcat(msg, "option repeated", ap);
	break;
    case RSA_ERR_NOACTION:
	rsa_strcat(msg, "no RSA action specified");
	break;
    case RSA_ERR_MULTIACTION:
	rsa_strcat(msg, "too many RSA actions");
	break;
    case RSA_ERR_NOFILE:
	rsa_strcat(msg, "no input file specified");
	break;
    case RSA_ERR_FOPEN:
	rsa_vstrcat(msg, "could not open file %s", ap);
	break;
    case RSA_ERR_FILEIO:
	rsa_strcat(msg, "reading/writing file");
	break;
    case RSA_ERR_KEYPATH:
	rsa_vstrcat(msg, "cannot open RSA key directory %s", ap);
	break;
    case RSA_ERR_KEYNAME:
	rsa_vstrcat(msg, "key name is too long (max %d characters)", ap);
	break;
    case RSA_ERR_KEYGEN:
	rsa_strcat(msg, "key may cause loss of information, regenerating...");
	break;
    case RSA_ERR_KEYNOTEXIST:
	rsa_vstrcat(msg, "key %s%s%s does not exist in the key directory", ap);
	break;
    case RSA_ERR_KEYMULTIENTRIES:
	rsa_vstrcat(msg, "multiple entries for %s key %s%s%s - not setting", 
	    ap);
	break;
    case RSA_ERR_LEVEL:
	rsa_strcat(msg, "invalid encryption level - %s", optarg);
	break;
    case RSA_ERR_INTERNAL:
	rsa_vstrcat(msg, "internal", ap);
	break;
    case RSA_ERR_OPTARG:
    default:
	return;
    }
    rsa_strcat (msg, "\n");
    printf("%s", msg);
}

void rsa_error_message(rsa_errno_t err, ...)
{
    va_list ap;

    va_start(ap, err);
    rsa_message(1, err, ap);
    va_end(ap);
}

void rsa_warning_message(rsa_errno_t err, ...)
{
    va_list ap;

    va_start(ap, err);
    rsa_message(0, err, ap);
    va_end(ap);
}

static int rsa_io_u1024(FILE *file, u1024_t *num, int is_full, int is_read)
{
    int ret;
    io_func_t io = is_read ? (io_func_t)fread : (io_func_t)fwrite;

    ret = io(num->arr, sizeof(u64), block_sz_u1024 + (is_full ? 1 : 0), file);
    if (is_full)
	ret += io(&num->top, sizeof(int), 1, file);
    else if (is_read)
	number_top_set(num)

    if (ret != (block_sz_u1024 + (is_full ? 2 : 0)) && ret != EOF)
    {
	rsa_error_message(RSA_ERR_FILEIO);
	return -1;
    }

    return 0;
}

int rsa_read_u1024(FILE *file, u1024_t *num)
{
    return rsa_io_u1024(file, num, 0, 1);
}

int rsa_write_u1024(FILE *file, u1024_t *num)
{
    return rsa_io_u1024(file, num, 0, 0);
}

int rsa_read_u1024_full(FILE *file, u1024_t *num)
{
    return rsa_io_u1024(file, num, 1, 1);
}

int rsa_write_u1024_full(FILE *file, u1024_t *num)
{
    return rsa_io_u1024(file, num, 1, 0);
}

static int rsa_io_str(FILE *file, char *str, int len, int is_read)
{
    int ret;
    io_func_t io = is_read ? (io_func_t)fread : (io_func_t)fwrite;

    ret = io(str, sizeof(char), len, file);
    if (ret != len && ret != EOF)
    {
	rsa_error_message(RSA_ERR_FILEIO);
	return -1;
    }
    return 0;
}

int rsa_read_str(FILE *file, char *str, int len)
{
    return rsa_io_str(file, str, len, 1);
}

int rsa_write_str(FILE *file, char *str, int len)
{
    return rsa_io_str(file, str, len, 0);
}

void rsa_verbose_set(verbose_t level)
{
    is_cprintf = level;
}

