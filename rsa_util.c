#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "rsa_util.h"

#define RSA_TIMELINE_LEN 80

typedef int (* io_func_t)(void *ptr, int size, int nmemb, FILE *stream);

static verbose_t rsa_verbose;
static double timeline_inc;

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

    if (rsa_verbose == V_QUIET || (is_verbose && rsa_verbose == V_NORMAL))
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
    case RSA_ERR_FNAME_LEN:
	rsa_strcat(msg, "file name %s is too long", ap);
	break;
    case RSA_ERR_FILE_NOT_EXIST:
	rsa_vstrcat(msg, "file %s does not exist", ap);
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
	rsa_vstrcat(msg, "key %s does not exist in the key directory", ap);
	break;
    case RSA_ERR_KEYMULTIENTRIES:
	rsa_vstrcat(msg, "multiple entries for %s key %s - not setting", ap);
	break;
    case RSA_ERR_KEY_STAT:
	rsa_vstrcat(msg, "could not find RSA key %s, please varify that it is "
	    "set", ap);
	break;
    case RSA_ERR_KEY_CORRUPT:
	rsa_vstrcat(msg, "RSA key %s is corrupt", ap);
	break;
    case RSA_ERR_KEY_OPEN:
	rsa_vstrcat(msg, "unable to open %s", ap);
	break;
    case RSA_ERR_KEY_TYPE:
	rsa_vstrcat(msg, "%s is linked to a %s key while a %s key is required", 
	    ap);
	break;
    case RSA_ERR_KEY_MISMATCH:
	rsa_vstrcat(msg, "the file %s was not encrypted by public key: %s", ap);
	break;
    case RSA_ERR_LEVEL:
	rsa_vstrcat(msg, "invalid encryption level - %s", ap);
	break;
    case RSA_ERR_INTERNAL:
	rsa_vstrcat(msg, "internal error in %s: %s(), line: %d", ap);
	break;
    case RSA_ERR_OPTARG:
	/* fall through - error message provided by getopt_long() */
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
    rsa_verbose = level;
}

verbose_t rsa_verbose_get(void)
{
    return rsa_verbose;
}

int is_fwrite_enable(char *name)
{
    char path[MAX_FILE_NAME_LEN], input[4];
    struct stat st;
    int ret;

    if (!getcwd(path, MAX_FILE_NAME_LEN))
	return 0;
    rsa_strcat(path, "/%s", name);
    if (stat(path, &st))
	return 1; /* file does not exist - no problem */

    printf("the file %s exists, do you want to overwrite it? [y/n]... ", name);
    scanf("%s", input);
    input[3] = 0;

    if (!(ret = !strncasecmp("yes", input, strlen(input))))
	rsa_printf(0, 0, "aborting...");
    return ret;
}

char *rsa_highlight_str(char *fmt, ...)
{
    va_list ap;
    static char highlight[MAX_HIGHLIGHT_STR] = C_HIGHLIGHT;
    char *ret = highlight;

    va_start(ap, fmt);
    if (vsnprintf(highlight + strlen(C_HIGHLIGHT), MAX_HIGHLIGHT_STR, fmt, 
	ap) > MAX_HIGHLIGHT_STR - strlen(C_NORMAL))
    {
	rsa_error_message(RSA_ERR_INTERNAL, __FILE__, __FUNCTION__, __LINE__);
	ret = "";
    }
    else
	strcat(highlight, C_NORMAL);
    va_end(ap);

    return ret;
}

int rsa_timeline_init(int len)
{
    char fmt[20];
    int block_num = (len-1)/(block_sz_u1024*sizeof(u64)) + 1;

    if (rsa_verbose == V_QUIET || block_num < 2)
	return 0;

    timeline_inc = (double)block_num/RSA_TIMELINE_LEN;
    sprintf(fmt, "[%%-%ds]\r[", RSA_TIMELINE_LEN);

    printf(fmt, "");
    fflush(stdout);

    return 1;
}

void rsa_timeline(void)
{
    static int blocks, dots;
    static double timeline;

    if (!timeline_inc || ++blocks < timeline)
	return;

    while (timeline < blocks && dots < RSA_TIMELINE_LEN)
    {
	dots++;
	timeline += timeline_inc;
	printf(".");
    }
    fflush(stdout);
}

void rsa_timeline_uninit(void)
{
    if (!timeline_inc)
	return;
    printf("\n");
    fflush(stdout);
}
