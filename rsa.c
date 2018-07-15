#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#if RSA_MASTER
#include "rsa_enc.h"
#include "rsa_dec.h"
#endif
#include "rsa.h"

#define OPTSTR_MAX_LEN 10
#define RSA_KEYPATH "RSA_KEYPATH"

#define  MIN(x, y) ((x) < (y) ? (x) : (y))

typedef struct keyname_t {
    struct keyname_t *next;
    char keyname[KEY_ID_MAX_LEN];
    char file[2][MAX_FILE_NAME_LEN]; /* [PRIVATE][PUBLIC] */
    int is_ambiguous[2];
} keyname_t;

static char optstring[3 * RSA_OPT_MAX];
static struct option longopts[RSA_OPT_MAX];
static char file_name[MAX_FILE_NAME_LEN];

char key_id[KEY_ID_MAX_LEN];

static opt_t options_common[] = {
    {RSA_OPT_HELP, 'h', "help", no_argument, "print this message and exit"},
    {RSA_OPT_SCANKEYS, 's', "scankeys", no_argument, "scan available keys"},
    {RSA_OPT_SETKEY, 'x', "setkey", required_argument, "set rsa key"},
    {RSA_OPT_PATH, 'p', "path", no_argument, "specify the key search "
	"directory. the key directory can be set by the RSA_KEYPATH "
	"environment variable. if it is not set, the current working directory "
	"is assumed"},
    {RSA_OPT_QUITE, 'q', "quite", no_argument, "set quite output"},
    {RSA_OPT_VERBOSE, 'v', "verbose", no_argument, "set verbose output"},
#if 0
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
    rsa_strcat(str, code2str(arg_requirements, cur->arg_requirement));
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
    if (strlen(key) >= KEY_ID_MAX_LEN - 2)
	return -1;
    sprintf(key_id, "%s", key);
    return 0;
}

int rsa_set_file_name(char *name)
{
    if (strlen(name) >= sizeof(file_name))
	return -1;

    sprintf(file_name, "%s", optarg);
    return 0;
}

static rsa_errno_t parse_args_finalize(int *flags, rsa_handler_t *handler)
{
    int actions = 0;

    if (*flags & OPT_FLAG(RSA_OPT_HELP))
	actions++;
    if (*flags & OPT_FLAG(RSA_OPT_SCANKEYS))
	actions++;
    if (*flags & OPT_FLAG(RSA_OPT_SETKEY))
	actions++;
    if (*flags & OPT_FLAG(RSA_OPT_PATH))
	actions++;

    /* test for a single action option */
    if (actions > 1)
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
	case RSA_OPT_SCANKEYS:
	case RSA_OPT_PATH:
	    OPT_ADD(flags, code)
	    break;
	case RSA_OPT_SETKEY:
	    OPT_ADD(flags, RSA_OPT_SETKEY)
	    rsa_set_key_name(optarg);
	    break;
	case RSA_OPT_QUITE:
	case RSA_OPT_VERBOSE:
	    OPT_ADD(flags, code)
	    rsa_verbose_set(code == RSA_OPT_VERBOSE ? V_VERBOSE : V_QUIET);
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

static void rsa_usage(char *path)
{
    printf("usage: %s [ OPTIONS ]\n\n", app_name(path));

}

int rsa_error(char *app, rsa_errno_t err)
{
    rsa_error_message(err);
    rsa_usage(app);
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

static void rsa_options(opt_t *options_private)
{
    printf("where:\n");
    output_option_array(options_common);
    output_option_array(options_private);
}

static void rsa_help(char *path, opt_t *options_private)
{
#define CHAR_COPYRIGHT 169

    rsa_usage(path);
    rsa_options(options_private);

    printf("\n%c IAS software, April 2005\n", CHAR_COPYRIGHT);
}

static int rsa_set_key_param(char *str, char *param, int len, char *fmt, ...)
{
    va_list ap;

    if (strlen(param) > len)
	return -1;
    va_start(ap, fmt);
    vsprintf(str, fmt, ap);
    va_end(ap);
    return 0;
}

int rsa_set_key_id(char *id)
{
    /* key_id[0] is reserved for the e and d characters marking the key as
     * public or private respectively */
    return rsa_set_key_param(key_id, id, KEY_ID_MAX_LEN - 2, "%c%s", '*', id);
}

char *key_path_get(void)
{
    static char key_path[MAX_FILE_NAME_LEN], *ptr;

    if ((ptr = getenv(RSA_KEYPATH)))
	snprintf(key_path, MAX_FILE_NAME_LEN, ptr);
    else
	getcwd(key_path, MAX_FILE_NAME_LEN);

    return key_path;
}

int rsa_encryption_level_set(char *optarg)
{
    char *err;
    int level;

    level = strtol(optarg, &err, 10);
    return (*err) ? -1 : number_enclevl_set(level);
}

static int rsa_key_size(void)
{
#define LEN(X) (((X)+64)/sizeof(u64) + sizeof(int))

    int *level, accum = 0;

    for (level = encryption_levels; *level; level++)
	accum+=LEN(*level);

    return strlen(RSA_SIGNITURE) + LEN(encryption_levels[0]) + 3*accum;
}

static FILE *rsa_dirent2file(struct dirent *ent)
{
    struct stat st;
    int siglen = strlen(RSA_SIGNITURE);
    char signiture[siglen], *path = key_path_get(), *fname;
    FILE *f = NULL;

    if (!(fname = malloc(strlen(path) + 1 + strlen(ent->d_name) + 1)))
	return NULL;

    if (!strcmp(ent->d_name, RSA_KEYLINK_PREFIX ".prv") || !strcmp(ent->d_name, 
	RSA_KEYLINK_PREFIX ".pub"))
    {
	goto Exit;
    }

    sprintf(fname, "%s/%s", path, ent->d_name);
    if (stat(fname, &st) || st.st_size != rsa_key_size() || 
	!(f = fopen(fname, "r")))
    {
	goto Exit;
    }

    if (rsa_read_str(f, signiture, siglen) || 
	memcmp(RSA_SIGNITURE, signiture, siglen))
    {
	fclose(f);
	f = NULL;
    }

Exit:
    free(fname);
    return f;
}

static int keyname_insert(keyname_t **base, char *keyname, char *fname, 
    char keytype)
{
    /* search keyname list for the opposite type of key */
    for ( ; *base && strcmp((*base)->keyname, keyname); base = &(*base)->next);

    if (!*base && !(*base = calloc(1, sizeof(keyname_t))))
	return -1;

    if (!*(*base)->keyname)
	sprintf((*base)->keyname, "%s", keyname);
    if (!*(*base)->file[keytype==RSA_KEY_TYPE_PUBLIC])
	sprintf((*base)->file[keytype == RSA_KEY_TYPE_PUBLIC], "%s", fname);
    else
	(*base)->is_ambiguous[keytype == RSA_KEY_TYPE_PUBLIC] = 1;
    return 0;
}

static void rsa_keyname(FILE *key, keyname_t **keynames, char *fname, 
    char accept)
{
    u1024_t scrambled_id, id, exp, n, montgomery_factor;
    char keytype;

    number_enclevl_set(encryption_levels[0]);
    rsa_read_u1024_full(key, &scrambled_id);
    rsa_read_u1024_full(key, &n);
    rsa_read_u1024_full(key, &exp);
    rsa_read_u1024_full(key, &montgomery_factor);
    number_montgomery_factor_set(&n, &montgomery_factor);

    rsa_decode(&id, &scrambled_id, &exp, &n);
    keytype = *(char*)id.arr;
    if (!(keytype & accept))
	return;
    keyname_insert(keynames, (char*)id.arr + 1, fname, keytype);
}

static keyname_t *keynames_gen(char keytype)
{
    DIR *dir;
    struct dirent *ent;
    keyname_t *keynames = NULL;
    char *path = key_path_get();

    if (!(dir = opendir(path)))
    {
	rsa_error_message(RSA_ERR_KEYPATH, path);
	return NULL;
    }

    while ((ent = readdir(dir)))
    {
	FILE *key;
	
	if (!(key = rsa_dirent2file(ent)))
	    continue;
	rsa_keyname(key, &keynames, ent->d_name, keytype);
	fclose(key);
    }

    closedir(dir);
    return keynames;
}

static char *keyname_display_init(char *fmt, char *key, char *path, int idx)
{
    char lnk[MAX_FILE_NAME_LEN], *ptr;
    struct stat st;
    sprintf(lnk, "%s/%s", path, 
	idx ? RSA_KEYLINK_PREFIX ".pub" : RSA_KEYLINK_PREFIX ".prv");
    memset(key, 0, MAX_FILE_NAME_LEN);
    ptr = !lstat(lnk, &st) && (readlink(lnk, key, MAX_FILE_NAME_LEN) != -1) ? 
	key + strlen(path) + 1 :"";
    printf(fmt, C_NORMAL, idx ? "public keys" : "private keys", C_NORMAL);
    return ptr;
}

static int keyname_display_single(char *fmt, keyname_t *key, 
    char *lnkname, int idx, int is_keytype_other)
{
    int do_print;

    if (key->is_ambiguous[idx] || !*key->file[idx])
    {
	if (is_keytype_other && !key->is_ambiguous[1 - idx])
	    printf(fmt, C_NORMAL, "", C_NORMAL);
	do_print = 0;
    }
    else
    {
	printf(fmt, !strcmp(key->file[idx], lnkname) ? C_HIGHLIGHT : C_NORMAL, 
	    key->keyname, C_NORMAL);
	do_print = 1;
    }

    return do_print;
}

static void keyname_display(keyname_t *base, char keytype)
{
    char fmt[20], *path, *pprv, *ppub;
    char prv[MAX_FILE_NAME_LEN], pub[MAX_FILE_NAME_LEN];
    keyname_t *ambiguous = NULL;

    path = key_path_get();
    sprintf(fmt, "%%s%%-%ds%%s", KEY_ID_MAX_LEN);
    if (keytype & RSA_KEY_TYPE_PRIVATE)
	pprv = keyname_display_init(fmt, prv, path, 0);
    if (keytype & RSA_KEY_TYPE_PUBLIC)
	ppub = keyname_display_init(fmt, pub, path, 1);
    printf("\n");
    while (base)
    {
	int do_print = 0;
	keyname_t *cur = base;

	base = base->next;
	if (keytype & RSA_KEY_TYPE_PRIVATE)
	{
	    do_print += keyname_display_single(fmt, cur, pprv, 0,
		keytype & RSA_KEY_TYPE_PUBLIC);
	}
	if (keytype & RSA_KEY_TYPE_PUBLIC)
	{
	    do_print += keyname_display_single(fmt, cur, ppub, 1,
		keytype & RSA_KEY_TYPE_PRIVATE);
	}
	if (do_print)
	    printf("\n");
	if (cur->is_ambiguous[0] || cur->is_ambiguous[1])
	{
	    cur->next = ambiguous;
	    ambiguous = cur;
	    continue;
	}
	free(cur);
    }

    if (!ambiguous)
	return;

    printf("\nthe following keys have multiple entires\n");
    while (ambiguous)
    {
	keyname_t *cur = ambiguous;
	ambiguous = ambiguous->next;

	if (keytype & RSA_KEY_TYPE_PRIVATE)
	    printf(fmt, "", cur->is_ambiguous[0] ? cur->keyname : "", "");
	if (keytype & RSA_KEY_TYPE_PUBLIC)
	    printf(fmt, "", cur->is_ambiguous[1] ? cur->keyname : "", "");
	printf("\n");
	free(cur);
    }
}

static void rsa_scankeys(char keytype)
{
    keyname_display(keynames_gen(keytype), keytype);
}

static void rsa_setkey_symlink_set(char *lnkname, char *keyname, char *path, 
    keyname_t *key, int idx)
{
    sprintf(keyname, "%s/%s", path, key->file[idx]);
    sprintf(lnkname, "%s/%s", path, idx ? RSA_KEYLINK_PREFIX ".pub" : 
	RSA_KEYLINK_PREFIX ".prv");
    if (key->is_ambiguous[idx])
    {
	rsa_warning_message(RSA_ERR_KEYMULTIENTRIES, idx ? "public" : "private",
	    C_HIGHLIGHT, key_id, C_NORMAL);
    }
    else if (*key->file[idx])
    {
	remove(lnkname);
	symlink(keyname, lnkname);
	printf("%s key set to: %s%s%s\n", idx ? "public" : "private", 
	    C_HIGHLIGHT, key_id, C_NORMAL);
    }
}

static int rsa_setkey_links(keyname_t *keynames, char keytype)
{
    keyname_t *key = NULL;
    char keyname[MAX_FILE_NAME_LEN], lnkname[MAX_FILE_NAME_LEN], *path;
    int ret;

    while (keynames)
    {
	keyname_t *tmp = keynames;

	keynames = keynames->next;
	if (!key && !strcmp(tmp->keyname, key_id))
	    key = tmp;
	else
	    free(tmp);
    }
    if (!key)
    {
	rsa_error_message(RSA_ERR_KEYNOTEXIST, C_HIGHLIGHT, key_id, C_NORMAL);
	return -1;
    }

    path = key_path_get();
    if (keytype & RSA_KEY_TYPE_PRIVATE)
	rsa_setkey_symlink_set(lnkname, keyname, path, key, 0);
    if (keytype & RSA_KEY_TYPE_PUBLIC)
	rsa_setkey_symlink_set(lnkname, keyname, path, key, 1);

    ret = key->is_ambiguous[0] || key->is_ambiguous[1];
    free(key);

    return ret;
}

static void rsa_setkey(char keytype)
{
    rsa_setkey_links(keynames_gen(keytype), keytype);
}

static void rsa_show_path(void)
{
    if (!getenv(RSA_KEYPATH))
	printf("current working directory\n");
    else
	printf("%s/\n", key_path_get());
}

rsa_opt_t rsa_action_get(int flags, ...)
{
    va_list va;
    rsa_opt_t new;
    int actions = OPT_FLAG(RSA_OPT_HELP) | OPT_FLAG(RSA_OPT_SCANKEYS) | 
	OPT_FLAG(RSA_OPT_SETKEY) | OPT_FLAG(RSA_OPT_PATH);

    va_start(va, flags);
    while ((new = va_arg(va, rsa_opt_t)))
	actions |= OPT_FLAG(new);
    va_end(va);

    return flags & actions;
}

int rsa_action_handle_common(rsa_opt_t action, char *app, 
    rsa_handler_t *handler)
{
    switch (action)
    {
    case OPT_FLAG(RSA_OPT_HELP):
	rsa_help(app, handler->options);
	break;
    case OPT_FLAG(RSA_OPT_SCANKEYS):
	rsa_scankeys(handler->keytype);
	break;
    case OPT_FLAG(RSA_OPT_SETKEY):
	rsa_setkey(handler->keytype);
	break;
    case OPT_FLAG(RSA_OPT_PATH):
	rsa_show_path();
	break;
    default:
	return rsa_error(app, RSA_ERR_INTERNAL);
    }

    return 0;
}

void rsa_encode(u1024_t *res, u1024_t *data, u1024_t *exp, u1024_t *n)
{
    u64 q;
    u1024_t r;

    if (!number_is_greater_or_equal(data, n))
    {
	number_assign(r, *data);
	q = (u64)0;
    }
    else
    {
	u1024_t num_q;

	number_dev(&num_q, &r, data, n);
	q = *(u64*)&num_q;
    }

    number_modular_exponentiation_montgomery(res, &r, exp, n);
    res->arr[block_sz_u1024] = q;
}

void rsa_decode(u1024_t *res, u1024_t *data, u1024_t *exp, u1024_t *n)
{
    u64 q;
    u1024_t r;

    q = data->arr[block_sz_u1024];
    number_assign(r, *data);
    r.arr[block_sz_u1024] = 0;
    number_modular_exponentiation_montgomery(res, &r, exp, n);

    if (q)
    {
	u1024_t num_q;

	number_small_dec2num(&num_q, q);
	number_mul(&num_q, &num_q, n);
	number_add(res, res, &num_q);
    }
}

