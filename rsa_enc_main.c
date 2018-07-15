#include <unistd.h>
#include <getopt.h>
#include "rsa_util.h"
#include "rsa_enc.h"
#include "rsa.h"

static opt_t options_encrypter[] = {
    {RSA_OPT_FILE, 'f', "file", required_argument, ARG " is the input file to "
	"encrypt"},
    {RSA_OPT_LEVEL, 'l', "level", required_argument, "set encryption level to "
	"128(default), 256, 512 or 1024."},
    {RSA_OPT_RSAENC, 'r', "rsa", no_argument, "full RSA encryption. if this "
	"flag is not set, encryption will be done using a symmetric "
	"key and only it will be RSA encrypted"},
    {RSA_OPT_KEY_SET_DYNAMIC, 'k', "key", required_argument, "set the RSA key "
	"to be used for the current encryption. this options overrides the "
	"default key if it has been set"},
    {RSA_OPT_ORIG_FILE, 'o', "original", no_argument, "keep the original file. "
	"if this option is not set the file will be deleted after it has been "
	"encrypted"},
    { RSA_OPT_MAX }
};

/* encryption task is to be performed */
static int parse_args_finalize_encrypter(int *flags, int actions)
{
    if (!actions)
	*flags |= OPT_FLAG(RSA_OPT_ENCRYPT);

    /* test for non compatible options with encrypt */
    if ((*flags & OPT_FLAG(RSA_OPT_ENCRYPT)) && 
	!(*flags & OPT_FLAG(RSA_OPT_FILE)))
    {
	rsa_error_message(RSA_ERR_NOFILE);
	return -1;
    }

    return 0;
}

static int parse_args_encrypter(int opt, int *flags)
{
    switch (opt_short2code(options_encrypter, opt))
    {
    case RSA_OPT_FILE:
	OPT_ADD(flags, RSA_OPT_FILE);
	if (rsa_set_file_name(optarg))
	    return -1;
	break;
    case RSA_OPT_LEVEL:
	OPT_ADD(flags, RSA_OPT_LEVEL);
	if (rsa_encryption_level_set(optarg))
	    return -1;
	break;
    case RSA_OPT_RSAENC:
	OPT_ADD(flags, RSA_OPT_RSAENC);
	break;
    case RSA_OPT_KEY_SET_DYNAMIC:
	OPT_ADD(flags, RSA_OPT_KEY_SET_DYNAMIC);
	if (optarg && rsa_set_key_name(optarg))
	    return -1;
	break;
    case RSA_OPT_ORIG_FILE:
	OPT_ADD(flags, RSA_OPT_ORIG_FILE);
	keep_orig_file = 1;
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
    rsa_handler_t encrypter_handler = {
	.keytype = RSA_KEY_TYPE_PUBLIC,
	.options = options_encrypter,
	.ops_handler = parse_args_encrypter,
	.ops_handler_finalize = parse_args_finalize_encrypter,
    };

    if (parse_args(argc, argv, &flags, &encrypter_handler))
	return rsa_error(argv[0]);

    action = rsa_action_get(flags, RSA_OPT_ENCRYPT, NULL);
    switch (action)
    {
    case OPT_FLAG(RSA_OPT_ENCRYPT):
    {
	if (!(flags & OPT_FLAG(RSA_OPT_LEVEL)))
	    rsa_encryption_level_set(NULL);

	ret = flags & OPT_FLAG(RSA_OPT_RSAENC) ? 
	    rsa_encrypt_full() : rsa_encrypt_quick();
	break;
    }
    default:
	ret = rsa_action_handle_common(action, argv[0], &encrypter_handler);
	break;
    }

    return ret;
}

