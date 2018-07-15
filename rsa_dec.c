#include "rsa.h"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>

#ifndef RSA_MASTER
static opt_t options_decrypter[] = {
    {RSA_OPT_FILE, 'f', "file", required_argument, "input file to decrypt"},
    {RSA_OPT_KEYGEN, 'k', "keygen", no_argument, "generate RSA public "
	"and private keys"},
    { RSA_OPT_MAX }
};

/* either encryption or decryption task are to be performed */
static rsa_errno_t parse_args_finalize_decrypter(int *flags, int actions)
{
    if (!actions)
	*flags |= OPT_FLAG(RSA_OPT_DECRYPT);

    /* test for non compatable options with encrypt/decrypt */
    if ((*flags & OPT_FLAG(RSA_OPT_DECRYPT)) 
	&& !(*flags & OPT_FLAG(RSA_OPT_FILE)))
    {
	return RSA_ERR_NOFILE;
    }

    return RSA_ERR_NONE;
}

static rsa_errno_t parse_args_decrypter(int opt, int *flags)
{
    switch (opt_short2code(options_decrypter, opt))
    {
    case RSA_OPT_FILE:
	OPT_ADD(flags, RSA_OPT_FILE, rsa_set_file_name(optarg));
	break;
    case RSA_OPT_KEYGEN:
	OPT_ADD(flags, RSA_OPT_KEYGEN);
	break;
    default:
	return RSA_ERR_OPTARG;
    }

    return RSA_ERR_NONE;
}

int main(int argc, char *argv[])
{
    int err, action, flags = 0;
    rsa_handler_t decrypter_handler = {
	.options = options_decrypter,
	.ops_handler = parse_args_decrypter,
	.ops_handler_finalize = parse_args_finalize_decrypter,
    };

    if ((err = parse_args(argc, argv, &flags, &decrypter_handler)) != 
	RSA_ERR_NONE)
    {
	return rsa_error(argv[0], err);
    }

    action = rsa_action_get(flags, RSA_OPT_DECRYPT, NULL);
    switch (action)
    {
    case OPT_FLAG(RSA_OPT_DECRYPT):
	RSA_TBD("handle RSA_OPT_DECRYPT");
	//rsa_proccess(input_file_name, 1);
	break;
    case OPT_FLAG(RSA_OPT_KEYGEN):
	RSA_TBD("handle RSA_OPT_KEYGEN");
	//rsa_key_generate();
	break;
    default:
	return rsa_action_handle_common(action, argv[0], options_decrypter);
    }

    return 0;
}
#endif

