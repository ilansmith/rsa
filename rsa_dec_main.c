#include <unistd.h>
#include <getopt.h>
#include "rsa_util.h"
#include "rsa_dec.h"
#include "rsa.h"

static opt_t options_decrypter[] = {
    {RSA_OPT_FILE, 'f', "file", required_argument, "arg is the input file to "
	"decrypt"},
    {RSA_OPT_KEYGEN, 'k', "keygen", required_argument, "generate an RSA public/"
	"private key pair. arg is its name"},
    { RSA_OPT_MAX }
};

/* either encryption or decryption task are to be performed */
static int parse_args_finalize_decrypter(int *flags, int actions)
{
    if (!actions && !(*flags & OPT_FLAG(RSA_OPT_KEYGEN)))
	*flags |= OPT_FLAG(RSA_OPT_DECRYPT);

    /* test for non compatable options with encrypt/decrypt */
    if ((*flags & OPT_FLAG(RSA_OPT_DECRYPT)) 
	&& !(*flags & OPT_FLAG(RSA_OPT_FILE)))
    {
	rsa_error_message(RSA_ERR_NOFILE);
	return -1;
    }

    return 0;
}

static int parse_args_decrypter(int opt, int *flags)
{
    switch (opt_short2code(options_decrypter, opt))
    {
    case RSA_OPT_FILE:
	OPT_ADD(flags, RSA_OPT_FILE);
	if (rsa_set_file_name(optarg))
	    return -1;
	break;
    case RSA_OPT_KEYGEN:
	OPT_ADD(flags, RSA_OPT_KEYGEN);
	if (rsa_set_key_data(optarg))
	    return -1;
	break;
    default:
	rsa_error_message(RSA_ERR_OPTARG);
	return -1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    int ret, action, flags = 0;
    rsa_handler_t decrypter_handler = {
	.keytype = RSA_KEY_TYPE_PRIVATE,
	.options = options_decrypter,
	.ops_handler = parse_args_decrypter,
	.ops_handler_finalize = parse_args_finalize_decrypter,
    };

    if (parse_args(argc, argv, &flags, &decrypter_handler))
	return rsa_error(argv[0]);

    action = rsa_action_get(flags, RSA_OPT_DECRYPT, RSA_OPT_KEYGEN, NULL);
    switch (action)
    {
    case OPT_FLAG(RSA_OPT_KEYGEN):
	ret = rsa_keygen();
	break;
    case OPT_FLAG(RSA_OPT_DECRYPT):
	ret = rsa_decrypt();
	break;
    default:
	ret = rsa_action_handle_common(action, argv[0], &decrypter_handler);
	break;
    }

    return ret;
}

