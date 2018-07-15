#include "rsa.h"
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

#define OPTSTR_MAX_LEN 10

#define RSA_OPT_CODE(X) (options[X].code)
#define RSA_OPT_SHORT(X) (options[X].short_opt)
#define RSA_OPT_LONG(X) (options[X].long_opt)
#define RSA_OPT_DESC(X) (options[X].description)

#define RSA_OPT_ERROR 0x0
#define RSA_OPT_HELP 0x1
#if RSA_MASTER || RSA_ENCRYPTER
#define RSA_OPT_ENCRYPT 0x2
#endif
#if RSA_MASTER || RSA_DECRYPTER
#define RSA_OPT_DECRYPT 0x4
#define RSA_OPT_GENERATE_KEY 0x8
#endif
#if !RSA_MASTER
#define RSA_OPT_VENDOR 0xa
#endif

typedef struct opt_t {
    int code;
    char short_opt;
    char *long_opt;
    char *description;
} opt_t;

static opt_t options[] = {
    {RSA_OPT_HELP, 'h', "help", "print this message and exit"},
#if RSA_MASTER || RSA_ENCRYPTER
    {RSA_OPT_ENCRYPT, 'e', "encrypt", "encrypt a message"},
#endif
#if RSA_MASTER || RSA_DECRYPTER
    {RSA_OPT_DECRYPT, 'd', "decrypt", "decrypt a message"},
    {RSA_OPT_GENERATE_KEY, 'k', "generate-key", "generate RSA public and "
	"private keys"},
#endif
#if !RSA_MASTER
    {RSA_OPT_VENDOR, 'v', "vendor", "vendor owning the keys"},
#endif
};

static int opt_idx_by_code(int opt)
{
    int idx;

    for (idx = 0; idx < ARRAY_SZ(options); idx++)
    {
	if (opt == RSA_OPT_CODE(idx))
	    return idx;
    }

    return -1;
}

static int opt_short2code(int opt)
{
    int idx;

    for (idx = 0; idx < ARRAY_SZ(options); idx++)
    {
	if (opt == RSA_OPT_SHORT(idx))
	    return RSA_OPT_CODE(idx);
    }

    return RSA_OPT_ERROR;
}

static void optstring_init(char *str, ...)
{
    va_list ap;
    char cstr[2] = {0, 0};

    bzero(str, sizeof(str));
    va_start(ap, str);
    while ((cstr[0] = va_arg(ap, int)))
	strcat(str, cstr);
    va_end(ap);
}

static int parse_args(int argc, char *argv[])
{
    int opt, rsa_opt = 0;
    char optstring[OPTSTR_MAX_LEN];
    struct option longopts[] = {
	{RSA_OPT_LONG(opt_idx_by_code(RSA_OPT_HELP)), no_argument, NULL, 
	    RSA_OPT_SHORT(opt_idx_by_code(RSA_OPT_HELP))},
#if RSA_MASTER || RSA_ENCRYPTER
	{RSA_OPT_LONG(opt_idx_by_code(RSA_OPT_ENCRYPT)), no_argument, NULL, 
	    RSA_OPT_SHORT(opt_idx_by_code(RSA_OPT_ENCRYPT))},
#endif
#if RSA_MASTER || RSA_DECRYPTER
	{RSA_OPT_LONG(opt_idx_by_code(RSA_OPT_DECRYPT)), no_argument, NULL, 
	    RSA_OPT_SHORT(opt_idx_by_code(RSA_OPT_DECRYPT))},
	{RSA_OPT_LONG(opt_idx_by_code(RSA_OPT_GENERATE_KEY)), no_argument, 
	    NULL, RSA_OPT_SHORT(opt_idx_by_code(RSA_OPT_GENERATE_KEY))},
#endif
#if !RSA_MASTER
	{RSA_OPT_LONG(opt_idx_by_code(RSA_OPT_VENDOR)), no_argument, NULL, 
	    RSA_OPT_SHORT(opt_idx_by_code(RSA_OPT_VENDOR))},
#endif
	{0, 0, 0, 0}
    };

    optstring_init(optstring, 
	    RSA_OPT_SHORT(opt_idx_by_code(RSA_OPT_HELP)),
#if RSA_MASTER || RSA_ENCRYPTER
	    RSA_OPT_SHORT(opt_idx_by_code(RSA_OPT_ENCRYPT)),
#endif
#if RSA_MASTER || RSA_DECRYPTER
	    RSA_OPT_SHORT(opt_idx_by_code(RSA_OPT_DECRYPT)),
	    RSA_OPT_SHORT(opt_idx_by_code(RSA_OPT_GENERATE_KEY)),
#endif
#if !RSA_MASTER
	    RSA_OPT_SHORT(opt_idx_by_code(RSA_OPT_VENDOR)),
#endif
	    NULL);

    while ((opt = getopt_long_only(argc, argv, optstring, longopts, NULL)) != 
	-1)
    {
	switch (opt_short2code(opt))
	{
	case RSA_OPT_HELP:
	    rsa_opt |= RSA_OPT_HELP;
	    break;
#if RSA_MASTER || RSA_ENCRYPTER
	case RSA_OPT_ENCRYPT:
	    rsa_opt |= RSA_OPT_ENCRYPT;
	    break;
#endif
#if RSA_MASTER || RSA_DECRYPTER
	case RSA_OPT_DECRYPT:
	    rsa_opt |= RSA_OPT_DECRYPT;
	    break;
	case RSA_OPT_GENERATE_KEY:
	    rsa_opt |= RSA_OPT_GENERATE_KEY;
	    break;
#endif
#if !RSA_MASTER
	case RSA_OPT_VENDOR:
	    rsa_opt |= RSA_OPT_VENDOR;
	    break;
#endif
	default:
	    rsa_opt = RSA_OPT_ERROR;
	    goto Exit;
	}
    }

Exit:
    return rsa_opt;
}

static char *app_name(char *path)
{
#define MAX_APP_NAME_LEN 10

    int path_len = strlen(path);
    char *ptr = NULL;
    static char name[MAX_APP_NAME_LEN];

    for (ptr = path + path_len - 1; ptr >= path; ptr--)
    {
	if (*ptr == '/')
	{
	    ptr++;
	    break;
	}
    }
    snprintf(name, MAX_APP_NAME_LEN, "%s", ptr);
    return name;
}

static void output_error_combination(void)
{
    printf("bad option combination\n\n");
}

static void output_usage(char *path)
{
    printf("usage: %s [ OPTIONS ]\n\n", app_name(path));

}

static void output_error(void)
{
    printf("Try `rsa --help' for more options.\n");
}

static void output_options(void)
{
#define OPTION_GAP 20
#define POPTION(S, L, DESC) printf("  -%c, --%-*s %s\n", S, OPTION_GAP, L, DESC)

    int i;

    printf("where:\n");
    for (i = 0; i < ARRAY_SZ(options); i++)
    {
	if (!RSA_OPT_DESC(i))
	    continue;

	POPTION(RSA_OPT_SHORT(i), RSA_OPT_LONG(i), RSA_OPT_DESC(i));
    }
}

#if !RSA_MASTER
static void rsa_vendor(void)
{
    printf("rsa vendor: %s\n", SIG);
}
#endif

static void output_help(char *path)
{
#define CHAR_COPYRIGHT 169

    printf("RSA ");
#if RSA_MASTER || RSA_ENCRYPTER
    printf("encrypter");
#endif
#if RSA_MASTER
    printf("/");
#endif
#if RSA_MASTER || RSA_DECRYPTER
    printf("decrypter");
#endif
    printf("\n");
    output_usage(path);
    output_options();

    printf("\n%c IAS software, April 2005\n", CHAR_COPYRIGHT);
}

int main(int argc, char *argv[])
{
    if (rsa_io_init())
	return -1;

    switch (parse_args(argc, argv))
    {
    case RSA_OPT_HELP:
	output_help(argv[0]);
	break;
#if RSA_MASTER || RSA_ENCRYPTER
    case RSA_OPT_ENCRYPT:
	break;
#endif
#if RSA_MASTER || RSA_DECRYPTER
    case RSA_OPT_DECRYPT:
	break;
    case RSA_OPT_GENERATE_KEY:
	rsa_key_generate();
	break;
#endif
#if !RSA_MASTER
    case RSA_OPT_VENDOR:
	rsa_vendor();
	break;
#endif
    case RSA_OPT_ERROR:
	output_usage(argv[0]);
	output_error();
	break;
    default:
	output_error_combination();
	output_error();
	break;
    }

    return 0;
}
