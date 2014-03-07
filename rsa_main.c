#include <unistd.h>
#include <getopt.h>
#include "rsa_util.h"
#include "rsa_enc.h"
#include "rsa_dec.h"
#include "rsa.h"

static opt_t options_master[] = {
    {RSA_OPT_FILE, 'f', "file", required_argument, ARG " is the input file to "
	"encrypt/decrypt"},
    {RSA_OPT_ENCRYPT, 'e', "encrypt", no_argument, "encrypt the data file "
	"stated by --file"},
    {RSA_OPT_LEVEL, 'l', "level", required_argument, "set encryption level to "
	"128, 256, 512 or 1024(default). this  switch implies encryption"},
    {RSA_OPT_RSAENC, 'r', "rsa", no_argument, "full RSA encryption. if this "
	"flag is not set, encryption/decryption will be done using a symmetric "
	"key and only it will be RSA encrypted/decrypted. this switch implies "
	"encryption"},
    {RSA_OPT_KEY_SET_DYNAMIC, 'k', "key", required_argument, "set the RSA key "
	"to be used for the current encryption. this options overides the "
	"default key if it has been set. this switch implies encryption"},
    {RSA_OPT_DECRYPT, 'd', "decrypt", no_argument, "decrypt the ciphertext "
	"stated by --file"},
    {RSA_OPT_KEYGEN, 'g', "generate", required_argument, "generate an RSA "
	"public/private key pair. " ARG " is its name"},
    { RSA_OPT_MAX }
};

/* either encryption or decryption task are to be performed */
static int parse_args_finalize_master(int *flags, int actions)
{
    /* RSA_OPT_LEVEL, RSA_OPT_RSAENC and RSA_OPT_KEY_SET_DYNAMIC imply 
     * RSA_OPT_ENCRYPT */
    if (*flags & (OPT_FLAG(RSA_OPT_LEVEL) | OPT_FLAG(RSA_OPT_RSAENC) | 
	OPT_FLAG(RSA_OPT_KEY_SET_DYNAMIC)))
    {
	*flags |= OPT_FLAG(RSA_OPT_ENCRYPT);
    }

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
	    return -1;
	break;
    case RSA_OPT_ENCRYPT:
	OPT_ADD(flags, RSA_OPT_ENCRYPT);
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
    case RSA_OPT_DECRYPT:
	OPT_ADD(flags, RSA_OPT_DECRYPT);
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
	if (!(flags & OPT_FLAG(RSA_OPT_LEVEL)))
	    rsa_encryption_level_set(NULL);

	ret = flags & OPT_FLAG(RSA_OPT_RSAENC) ? 
	    rsa_encrypt_full() : rsa_encrypt_quick();
	break;
    }
    case OPT_FLAG(RSA_OPT_KEYGEN):
	ret = rsa_keygen();
	break;
    case OPT_FLAG(RSA_OPT_DECRYPT):
	ret = rsa_decrypt();
	break;
    default:
	ret = rsa_action_handle_common(action, argv[0], &master_handler);
	break;
    }

    return ret;
}

