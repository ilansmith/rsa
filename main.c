#include "rsa.h"
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

#define OPTSTR_MAX_LEN 10
#define RSA_OPT_SHORT(X) (options[X].short_opt)
#define RSA_OPT_LONG(X) (options[X].long_opt)
#define RSA_OPT_DESC(X) (options[X].description)

#define RSA_OPT_ERROR -1

#if RSA_MASTER || RSA_ENCRYPTER
#define RSA_OPT_ENCRYPT_SHORT 'e'
#define RSA_OPT_ENCRYPT_LONG "encrypt"
#endif

#if RSA_MASTER || RSA_DECRYPTER
#define RSA_OPT_DECRYPT_SHORT 'd'
#define RSA_OPT_DECRYPT_LONG "decrypt"
#define RSA_OPT_GENERATE_KEY_SHORT 'k'
#define RSA_OPT_GENERATE_KEY_LONG "generate-key"
#endif

#if !RSA_MASTER
#define RSA_OPT_VENDOR_SHORT 'v'
#define RSA_OPT_VENDOR_LONG "vendor"
#endif

#define RSA_OPT_HELP_SHORT 'h'
#define RSA_OPT_HELP_LONG "help"

typedef struct opt_t {
    char short_opt;
    char *long_opt;
    char *description;
} opt_t;

static opt_t options[] = {
#if RSA_MASTER || RSA_ENCRYPTER
    {RSA_OPT_ENCRYPT_SHORT, RSA_OPT_ENCRYPT_LONG, "encrypt a message"},
#endif
#if RSA_MASTER || RSA_DECRYPTER
    {RSA_OPT_DECRYPT_SHORT, RSA_OPT_DECRYPT_LONG, "decrypt a message"},
    {RSA_OPT_GENERATE_KEY_SHORT, RSA_OPT_GENERATE_KEY_LONG, "generate RSA "
	"public and private keys"},
#endif
#if !RSA_MASTER
    {RSA_OPT_VENDOR_SHORT, RSA_OPT_VENDOR_LONG, "vendor owning the keys"},
#endif
    {RSA_OPT_HELP_SHORT, RSA_OPT_HELP_LONG, "print this message and exit"},
};

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
    int opt;
    char optstring[OPTSTR_MAX_LEN];
    struct option longopts[] = {
#if RSA_MASTER || RSA_ENCRYPTER
	{RSA_OPT_ENCRYPT_LONG, no_argument, NULL, RSA_OPT_ENCRYPT_SHORT},
#endif
#if RSA_MASTER || RSA_DECRYPTER
	{RSA_OPT_DECRYPT_LONG, no_argument, NULL, RSA_OPT_DECRYPT_SHORT},
	{RSA_OPT_GENERATE_KEY_LONG, no_argument, NULL, 
	    RSA_OPT_GENERATE_KEY_SHORT},
#endif
#if !RSA_MASTER
	{RSA_OPT_VENDOR_LONG, no_argument, NULL, RSA_OPT_VENDOR_SHORT},
#endif
	{RSA_OPT_HELP_LONG, no_argument, NULL, RSA_OPT_HELP_SHORT},
	{0, 0, 0, 0}
    };

    optstring_init(optstring, 
#if RSA_MASTER || RSA_ENCRYPTER
	    RSA_OPT_ENCRYPT_SHORT,
#endif
#if RSA_MASTER || RSA_DECRYPTER
	    RSA_OPT_DECRYPT_SHORT,
	    RSA_OPT_GENERATE_KEY_SHORT,
#endif
#if !RSA_MASTER
	    RSA_OPT_VENDOR_SHORT,
#endif
	    RSA_OPT_HELP_SHORT,
	    NULL);

    while ((opt = getopt_long_only(argc, argv, optstring, longopts, NULL)) != 
	-1)
    {
	switch (opt)
	{
#if RSA_MASTER || RSA_ENCRYPTER
	case RSA_OPT_ENCRYPT_SHORT:
#endif
#if RSA_MASTER || RSA_DECRYPTER
	case RSA_OPT_DECRYPT_SHORT:
	case RSA_OPT_GENERATE_KEY_SHORT:
#endif
#if !RSA_MASTER
	case RSA_OPT_VENDOR_SHORT:
#endif
	case RSA_OPT_HELP_SHORT:
	    return opt;
	default:
	    break;
	}
    }

    return RSA_OPT_ERROR;
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
#if RSA_MASTER || RSA_ENCRYPTER
    case RSA_OPT_ENCRYPT_SHORT:
	break;
#endif
#if RSA_MASTER || RSA_DECRYPTER
    case RSA_OPT_DECRYPT_SHORT:
	break;
    case RSA_OPT_GENERATE_KEY_SHORT:
	rsa_key_generate();
	break;
#endif
#if !RSA_MASTER
    case RSA_OPT_VENDOR_SHORT:
	rsa_vendor();
	break;
#endif
    case RSA_OPT_HELP_SHORT:
	output_help(argv[0]);
	break;
    case RSA_OPT_ERROR:
	output_usage(argv[0]);
	output_error();
    default:
	break;
    }

    return 0;
}
