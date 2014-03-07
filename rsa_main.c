#include <unistd.h>
#include <getopt.h>
#include "rsa_util.h"
#include "rsa_enc.h"
#include "rsa_dec.h"
#include "rsa.h"

static opt_t options_master[] = {
    {RSA_OPT_FILE, 'f', "file", required_argument, "input file to "
	"encrypt/decrypt"},
    {RSA_OPT_ENCRYPT, 'e', "encrypt", no_argument, "encrypt input file"},
    {RSA_OPT_LEVEL, 'l', "level", required_argument, "set encryption level to "
	"128, 256, 512 or 1024 (default), (implies encryption)"},
    {RSA_OPT_RSAENC, 'r', "rsa", no_argument, "full RSA encryption. if this "
	"flag is not set, encryption/decryption will be done using a symmetric "
	"key and only it will be RSA encrypted/decrypted (implies encryption)"},
    {RSA_OPT_DECRYPT, 'd', "decrypt", no_argument, "decrypt ciphertext"},
    {RSA_OPT_KEYGEN, 'k', "keygen", required_argument, "generate RSA public "
	"and private keys"},
    { RSA_OPT_MAX }
};

/* either encryption or decryption task are to be performed */
static int parse_args_finalize_master(int *flags, int actions)
{
    /* RSA_OPT_LEVEL and RSA_OPT_RSAENC imply RSA_OPT_ENCRYPT */
    if (*flags & (OPT_FLAG(RSA_OPT_LEVEL) | OPT_FLAG(RSA_OPT_RSAENC)))
	*flags |= OPT_FLAG(RSA_OPT_ENCRYPT);

    if (*flags & OPT_FLAG(RSA_OPT_ENCRYPT))
	actions++;
    if (*flags & OPT_FLAG(RSA_OPT_DECRYPT))
	actions++;
    if (*flags & OPT_FLAG(RSA_OPT_KEYGEN))
	actions++;

    /* test for a single action option */
    if (actions != 1)
    {
	rsa_error_message(actions ? RSA_ERR_MULTIACTION : RSA_ERR_NOACTION);
	return -1;
    }
    /* test for non compatable options with encrypt/decrypt */
    else if ((*flags & (OPT_FLAG(RSA_OPT_ENCRYPT) | OPT_FLAG(RSA_OPT_DECRYPT))) 
	&& !(*flags & OPT_FLAG(RSA_OPT_FILE)))
    {
	rsa_error_message(RSA_ERR_NOFILE);
	return -1;
    }

    return 0;
}

static int parse_args_master(int opt, int *flags)
{
    switch (opt_short2code(options_master, opt))
    {
    case RSA_OPT_FILE:
	OPT_ADD(flags, RSA_OPT_FILE);
	if (rsa_set_file_name(optarg))
	{
	    rsa_error_message(RSA_ERR_FNAME_LEN, optarg);
	    return -1;
	}
	break;
    case RSA_OPT_ENCRYPT:
	OPT_ADD(flags, RSA_OPT_ENCRYPT);
	break;
    case RSA_OPT_LEVEL:
	OPT_ADD(flags, RSA_OPT_LEVEL);
	if (rsa_encryption_level_set(optarg))
	{
	    rsa_error_message(RSA_ERR_LEVEL, optarg);
	    return -1;
	}
	break;
    case RSA_OPT_RSAENC:
	OPT_ADD(flags, RSA_OPT_RSAENC);
	break;
    case RSA_OPT_DECRYPT:
	OPT_ADD(flags, RSA_OPT_DECRYPT);
	break;
    case RSA_OPT_KEYGEN:
	OPT_ADD(flags, RSA_OPT_KEYGEN);
	if (rsa_set_key_id(optarg))
	{
	    rsa_error_message(RSA_ERR_KEYNAME, KEY_ID_MAX_LEN - 1);
	    return -1;
	}
	break;
    default:
	rsa_error_message(RSA_ERR_OPTARG);
	return -1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    int action, flags = 0;
    rsa_handler_t master_handler = {
	.keytype = RSA_KEY_TYPE_PUBLIC | RSA_KEY_TYPE_PRIVATE,
	.options = options_master,
	.ops_handler = parse_args_master,
	.ops_handler_finalize = parse_args_finalize_master,
    };

    if (parse_args(argc, argv, &flags, &master_handler))
	return rsa_error(argv[0]);

    action = rsa_action_get(flags, RSA_OPT_ENCRYPT, RSA_OPT_DECRYPT, 
	RSA_OPT_KEYGEN, NULL);
    switch (action)
    {
    case OPT_FLAG(RSA_OPT_ENCRYPT):
    {
	if (flags & OPT_FLAG(RSA_OPT_LEVEL))
	    RSA_TBD("handle RSA_OPT_LEVEL");
	if (flags & OPT_FLAG(RSA_OPT_RSAENC))
	    RSA_TBD("handle RSA_OPT_RSAENC");

	RSA_TBD("handle RSA_OPT_ENCRYPT");
	break;
    }
    case OPT_FLAG(RSA_OPT_DECRYPT):
	RSA_TBD("handle RSA_OPT_DECRYPT");
	break;
    case OPT_FLAG(RSA_OPT_KEYGEN):
	return rsa_keygen();
    default:
	return rsa_action_handle_common(action, argv[0], &master_handler);
    }

    return 0;
}

