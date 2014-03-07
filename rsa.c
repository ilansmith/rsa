#include "rsa_util.h"
#include "rsa_num.h"
#include "rsa.h"
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

#define OPTSTR_MAX_LEN 10
#define  MIN(x, y) ((x) < (y) ? (x) : (y))
#define IS_WHITESPACE(c) ((c) == ' ' || (c) == '\t')

static char optstring[3 * RSA_OPT_MAX];
static struct option longopts[RSA_OPT_MAX];
static char input_file_name[256];

static opt_t options_common[] = {
    {RSA_OPT_HELP, 'h', "help", no_argument, "print this message and exit"},
    {RSA_OPT_VENDOR, 'v', "vendor", no_argument, "vendor owning the rsa "
	"utility"},
    {RSA_OPT_SCANKEY, 's', "scankeys", no_argument, "scan available keys"},
    {RSA_OPT_SETKEY, 'x', "setkey", required_argument, "set rsa key"},
#if 0
    {RSA_OPT_PATH, 'p', "path", no_argument, "specify key directory"},
    {RSA_OPT_STDIN , 'i', "stdin", required_argument, "recieve input from "
	"standard input rather than a file"},
#endif
    { RSA_OPT_MAX }
};

int opt_short2code(opt_t *options, int opt)
{
    for ( ; options->code != RSA_OPT_MAX && options->short_opt != opt; 
	options++);
    return options->code;
}

static int optlong_register_array(opt_t *ops_arr)
{
    opt_t *cur;
    struct option *ptr, *max = longopts + ARRAY_SZ(longopts);

    for (ptr = longopts; ptr->name; ptr++);
    for (cur = ops_arr; ptr < max && cur->code != RSA_OPT_MAX; cur++, ptr++)
    {
	ptr->name = cur->long_opt;
	ptr->has_arg = cur->arg_requirement;
	ptr->flag = NULL;
	ptr->val = cur->short_opt;
    }

    /* ops_arr has a dummy terminator */
    return cur->code == RSA_OPT_MAX ? 0 : -1;
}

static int optlong_register(opt_t *options_private)
{
    memset(longopts, 0, ARRAY_SZ(longopts));
    return optlong_register_array(options_common) || 
	optlong_register_array(options_private);
}

static char *optstring_register_array_single(char *str, opt_t *cur)
{
    code2str_t arg_requirements[] = {
	{no_argument, ""},
	{required_argument, ":"},
	{optional_argument, "::"},
	{-1}
    };

    *str = cur->short_opt;
    strcat(str, code2str(arg_requirements, cur->arg_requirement));
    return str + strlen(str);
}

static int optstring_register_array(opt_t *ops_arr)
{
    opt_t *cur;
    char *str, *max = optstring + ARRAY_SZ(optstring);

    str = optstring + strlen(optstring);
    for (cur = ops_arr; str < max && cur->code != RSA_OPT_MAX; cur++)
    {
	if (!(str = optstring_register_array_single(str, cur)))
	    return -1;
    }

    /* ops_arr has a dummy terminator */
    return cur->code == RSA_OPT_MAX ? 0 : -1;

}

static int optstring_register(opt_t *options_private)
{
    memset(optstring, 0, ARRAY_SZ(optstring));
    return optstring_register_array(options_common) ||
	optstring_register_array(options_private);
}

static int optargs_init(opt_t *options_private)
{
    return optlong_register(options_private) || 
	optstring_register(options_private);
}

static int rsa_set_key_name(char *key)
{
    /* XXX */
    return 0;
}

int rsa_set_file_name(char *name)
{
    if (strlen(name) >= sizeof(input_file_name))
	return -1;

    sprintf(input_file_name, "%s", optarg);
    return 0;
}

static rsa_errno_t parse_args_finalize(int *flags, rsa_handler_t *handler)
{
    int act_help, act_vendor, act_scankey, act_setkey, actions;

    act_help = *flags & OPT_FLAG(RSA_OPT_HELP) ? 1 : 0;
    act_vendor = *flags & OPT_FLAG(RSA_OPT_VENDOR) ? 1 : 0;
    act_scankey = *flags & OPT_FLAG(RSA_OPT_SCANKEY) ? 1 : 0;
    act_setkey = *flags & OPT_FLAG(RSA_OPT_SETKEY) ? 1 : 0;

    /* test for a single action option */
    if ((actions = act_help + act_vendor + act_scankey + act_setkey) > 1)
	return RSA_ERR_MULTIACTION;

    return handler->ops_handler_finalize(flags, actions);
}

rsa_errno_t parse_args(int argc, char *argv[], int *flags, 
    rsa_handler_t *handler)
{
    int opt, code;

    optargs_init(handler->options);
    while ((opt = getopt_long_only(argc, argv, optstring, longopts, NULL)) 
	!= -1)
    {
	switch (code = opt_short2code(options_common, opt))
	{
	case RSA_OPT_HELP:
	case RSA_OPT_VENDOR:
	case RSA_OPT_SCANKEY:
	case RSA_OPT_SETKEY:
	    OPT_ADD(flags, code)
	    if (code == RSA_OPT_SETKEY)
		rsa_set_key_name(optarg);
	    break;
	default:
	    {
		rsa_errno_t err;

		if ((err = handler->ops_handler(opt, flags)) != RSA_ERR_NONE)
		    return err;
	    }
	    break;
	}
    }

    return parse_args_finalize(flags, handler);
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

static void output_error_message(rsa_errno_t err)
{
    char msg[128] = "error: ";

    switch (err)
    {
    case RSA_ERR_ARGREP:
	strcat(msg, "option repeated");
	break;
    case RSA_ERR_NOACTION:
	strcat(msg, "must specify RSA action");
	break;
    case RSA_ERR_MULTIACTION:
	strcat(msg, "too many RSA actions");
	break;
    case RSA_ERR_NOFILE:
	strcat(msg, "no input file specified");
	break;
    case RSA_ERR_INTERNAL:
	strcat(msg, "internal");
	break;
    case RSA_ERR_OPTARG:
    default:
	return;
    }

    strcat (msg, "\n");
    printf("%s", msg);
}

static void output_usage(char *path)
{
    printf("usage: %s [ OPTIONS ]\n\n", app_name(path));

}

int rsa_error(char *app, rsa_errno_t err)
{
    output_error_message(err);
    output_usage(app);
    printf("Try `rsa --help' for more options.\n");
    return -1;
}

static void option_print_desc(char *desc)
{
#define OPTION_DESC_COLUMN "20"
#define OPTION_DESC_LINE_SZ 65
    char buf[OPTION_DESC_LINE_SZ + 1];
    int cnt, remain = strlen(desc);

    do {
	cnt = MIN(snprintf(buf, OPTION_DESC_LINE_SZ, "%s", desc), 
	    OPTION_DESC_LINE_SZ - 1);
	if (remain - cnt)
	{
	    int orig_cnt = cnt;

	    while (cnt > 0 && !IS_WHITESPACE(buf[cnt]))
		cnt--;
	    if (!cnt)
		cnt = orig_cnt;
	    else
		buf[cnt++] = 0;
	}
	desc += cnt;
	remain -= cnt;
	printf("%s%s\n", "\E[" OPTION_DESC_COLUMN "C", buf);
    }
    while (remain);
}

static void output_option_array(opt_t *arr)
{
    for ( ; arr->code != RSA_OPT_MAX; arr++)
    {
	if (!arr->description)
	    continue;
	printf("  -%c, --%s\r", arr->short_opt, arr->long_opt);
	option_print_desc(arr->description);
    }
}

static void output_options(opt_t *options_private)
{
    printf("where:\n");
    output_option_array(options_common);
    output_option_array(options_private);
}

static void rsa_vendor(void)
{
    printf("rsa vendor: %s\n", VENDOR);
}

static void output_help(char *path, opt_t *options_private)
{
#define CHAR_COPYRIGHT 169

    output_usage(path);
    output_options(options_private);

    printf("\n%c IAS software, April 2005\n", CHAR_COPYRIGHT);
}

rsa_opt_t rsa_action_get(int flags, ...)
{
    va_list va;
    rsa_opt_t new;
    int actions = OPT_FLAG(RSA_OPT_HELP) | OPT_FLAG(RSA_OPT_VENDOR) | 
	OPT_FLAG(RSA_OPT_SCANKEY) | OPT_FLAG(RSA_OPT_SETKEY);

    va_start(va, flags);
    while ((new = va_arg(va, rsa_opt_t)))
	actions |= OPT_FLAG(new);
    va_end(va);

    return flags & actions;
}

int rsa_action_handle_common(rsa_opt_t action, char *app, 
    opt_t *options_private)
{
    switch (action)
    {
    case OPT_FLAG(RSA_OPT_HELP):
	output_help(app, options_private);
	break;
    case OPT_FLAG(RSA_OPT_VENDOR):
	rsa_vendor();
	break;
    case OPT_FLAG(RSA_OPT_SCANKEY):
	RSA_TBD("handle RSA_OPT_SCANKEY");
	break;
    case OPT_FLAG(RSA_OPT_SETKEY):
	RSA_TBD("handle RSA_OPT_SETKEY");
	break;
    default:
	return rsa_error(app, RSA_ERR_INTERNAL);
    }

    return 0;
}

#ifdef RSA_MASTER
static opt_t options_master[] = {
    {RSA_OPT_FILE, 'f', "file", required_argument, "input file to "
	"encrypt/decrypt"},
    {RSA_OPT_ENCRYPT, 'e', "encrypt", required_argument, "encrypt input file"},
    {RSA_OPT_LEVEL, 'l', "level", required_argument, "set encryption level to "
	"128, 256, 512 or 1024 (default), (implies encryption)"},
    {RSA_OPT_RSAENC, 'r', "rsa", no_argument, "full RSA encryption. if this "
	"flag is not set, encryption/decryption will be done using a symmetric "
	"key and only it will be RSA encrypted/decrypted (implies encryption)"},
    {RSA_OPT_DECRYPT, 'd', "decrypt", no_argument, "decrypt ciphertext"},
    {RSA_OPT_KEYGEN, 'k', "keygen", no_argument, "generate RSA public "
	"and private keys"},
    { RSA_OPT_MAX }
};

/* either encryption or decryption task are to be performed */
static rsa_errno_t parse_args_finalize_master(int *flags, int actions)
{
    int act_encrypt, act_decrypt, act_keygen;

    /* RSA_OPT_LEVEL and RSA_OPT_RSAENC imply RSA_OPT_ENCRYPT */
    if (*flags & (OPT_FLAG(RSA_OPT_LEVEL) | OPT_FLAG(RSA_OPT_RSAENC)))
	*flags |= OPT_FLAG(RSA_OPT_ENCRYPT);

    act_encrypt = *flags & OPT_FLAG(RSA_OPT_ENCRYPT) ? 1 : 0;
    act_decrypt = *flags & OPT_FLAG(RSA_OPT_DECRYPT) ? 1 : 0;
    act_keygen = *flags & OPT_FLAG(RSA_OPT_KEYGEN) ? 1 : 0;

    /* test for a single action option */
    if ((actions += act_encrypt + act_decrypt + act_keygen) != 1)
	return actions ? RSA_ERR_MULTIACTION : RSA_ERR_NOACTION;
    /* test for non compatable options with encrypt/decrypt */
    else if ((*flags & (OPT_FLAG(RSA_OPT_ENCRYPT) | OPT_FLAG(RSA_OPT_DECRYPT))) 
	&& !(*flags & OPT_FLAG(RSA_OPT_FILE)))
    {
	return RSA_ERR_NOFILE;
    }

    return RSA_ERR_NONE;
}

static rsa_errno_t parse_args_master(int opt, int *flags)
{
    switch (opt_short2code(options_master, opt))
    {
    case RSA_OPT_FILE:
	OPT_ADD(flags, RSA_OPT_FILE, rsa_set_file_name(optarg));
	break;
    case RSA_OPT_ENCRYPT:
	OPT_ADD(flags, RSA_OPT_ENCRYPT);
	break;
    case RSA_OPT_LEVEL:
	OPT_ADD(flags, RSA_OPT_LEVEL);
	break;
    case RSA_OPT_RSAENC:
	OPT_ADD(flags, RSA_OPT_RSAENC);
	break;
    case RSA_OPT_DECRYPT:
	OPT_ADD(flags, RSA_OPT_DECRYPT);
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
    rsa_handler_t master_handler = {
	.options = options_master,
	.ops_handler = parse_args_master,
	.ops_handler_finalize = parse_args_finalize_master,
    };

    if ((err = parse_args(argc, argv, &flags, &master_handler)) != RSA_ERR_NONE)
	return rsa_error(argv[0], err);

    action = rsa_action_get(flags, RSA_OPT_ENCRYPT, RSA_OPT_DECRYPT, NULL);
    switch (action)
    {
    case OPT_FLAG(RSA_OPT_ENCRYPT):
    {
	if (flags & OPT_FLAG(RSA_OPT_LEVEL))
	    RSA_TBD("handle RSA_OPT_LEVEL");
	if (flags & OPT_FLAG(RSA_OPT_RSAENC))
	    RSA_TBD("handle RSA_OPT_RSAENC");

	RSA_TBD("handle RSA_OPT_ENCRYPT");
	//rsa_proccess(input_file_name, 0);
	break;
    }
    case OPT_FLAG(RSA_OPT_DECRYPT):
	RSA_TBD("handle RSA_OPT_DECRYPT");
	//rsa_proccess(input_file_name, 1);
	break;
    case OPT_FLAG(RSA_OPT_KEYGEN):
	RSA_TBD("handle RSA_OPT_KEYGEN");
	//rsa_key_generate();
	break;
    default:
	return rsa_action_handle_common(action, argv[0], options_master);
    }

    return 0;
}
#endif
