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
#define RSA_OPT_AMBIGUOUS '?'

#define RSA_OPT_HELP 0
#define RSA_OPT_HELP_SHORT 'h'
#define RSA_OPT_HELP_LONG "help"

#define RSA_OPT_GENERATE_KEY 1
#define RSA_OPT_GENERATE_KEY_SHORT 'k'
#define RSA_OPT_GENERATE_KEY_LONG "generate-key"

typedef struct opt_t {
    char short_opt;
    char *long_opt;
    char *description;
} opt_t;

static opt_t options[] = {
    [ RSA_OPT_HELP ] = {RSA_OPT_HELP_SHORT, RSA_OPT_HELP_LONG, "print this "
	"message and exit"},
    [ RSA_OPT_GENERATE_KEY ] = {RSA_OPT_GENERATE_KEY_SHORT , 
	RSA_OPT_GENERATE_KEY_LONG, "generate RSA public and private keys"},
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
	{RSA_OPT_LONG(RSA_OPT_HELP), no_argument, NULL, 
	    RSA_OPT_SHORT(RSA_OPT_HELP)},
	{RSA_OPT_LONG(RSA_OPT_GENERATE_KEY), no_argument, NULL, 
	    RSA_OPT_SHORT(RSA_OPT_GENERATE_KEY)},
	{0, 0, 0, 0}
    };

    optstring_init(optstring, 
	    RSA_OPT_SHORT(RSA_OPT_HELP),
	    RSA_OPT_SHORT(RSA_OPT_GENERATE_KEY),
	    NULL);

    while ((opt = getopt_long(argc, argv, optstring, longopts, NULL)) != 
	-1)
    {
	switch (opt)
	{
	case RSA_OPT_HELP_SHORT:
	    return RSA_OPT_HELP;
	case RSA_OPT_GENERATE_KEY_SHORT:
	    return RSA_OPT_GENERATE_KEY;
	case RSA_OPT_AMBIGUOUS:
	    return RSA_OPT_AMBIGUOUS;
	default:
	    break;
	}
    }

    return RSA_OPT_ERROR;
}

static void output_ambiguous(void)
{
    printf("the options you have entered are ambiguous\n");
}

static void output_usage(void)
{
    printf("usage: rsa [ OPTIONS ]\n\n");
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

static void output_help(void)
{
#define CHAR_COPYRIGHT 169

    printf("RSA encoder/decoder\n");
    output_usage();
    output_options();
    printf("\n%c IAS software, April 2005\n", CHAR_COPYRIGHT);
}

int main(int argc, char *argv[])
{
    switch (parse_args(argc, argv))
    {
    case RSA_OPT_HELP:
	output_help();
	break;
    case RSA_OPT_GENERATE_KEY:
	rsa_key();
	break;
    case RSA_OPT_AMBIGUOUS:
	output_ambiguous();
    case RSA_OPT_ERROR:
	output_usage();
	output_error();
    default:
	break;
    }

    return 0;
}
