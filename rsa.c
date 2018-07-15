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
#include <errno.h>
#if RSA_MASTER
#include "rsa_enc.h"
#include "rsa_dec.h"
#endif
#include "mt19937_64.h"
#include "rsa.h"

#define OPTSTR_MAX_LEN 10
#define RSA_KEYPATH "RSA_KEYPATH"
#define MULTIPLE_ENTRIES_STR "the following keys have multiple entries\n"
#define KEY_DISPLAY_DEFAULT "(d)"
#define KEY_DISPLAY_WIDTH (KEY_DATA_MAX_LEN + \
    strlen(" " KEY_DISPLAY_DEFAULT) + 1)

typedef struct rsa_keyring_t {
    struct rsa_keyring_t *next;
    char *name;
    rsa_key_t *keys[2]; /* [PRIVATE][PUBLIC] */
    int is_ambiguous[2];
} rsa_keyring_t;

static char optstring[3 * RSA_OPT_MAX];
static struct option longopts[RSA_OPT_MAX];
char file_name[MAX_FILE_NAME_LEN];
char newfile_name[MAX_FILE_NAME_LEN + 4];
char key_data[KEY_DATA_MAX_LEN];
int rsa_encryption_level;
int is_encryption_info_only;
int file_size;
int keep_orig_file;

static opt_t options_common[] = {
    {RSA_OPT_HELP, 'h', "help", no_argument, "print this message and exit"},
    {RSA_OPT_KEY_SCAN, 's', "scan", no_argument, "scan and display all "
	"available RSA keys. the default key, if set, is marked by " 
	KEY_DISPLAY_DEFAULT},
    {RSA_OPT_KEY_SET_DEFAULT, 'x', "default", optional_argument, "If " ARG" is "
	"provided, set it as the default RSA key, otherwise, set no default "
	"RSA key"},
    {RSA_OPT_PATH, 'p', "path", no_argument, "output the key search "
	"directory. the key directory can be set by the RSA_KEYPATH "
	"environment variable. if it is not set, the current working directory "
	"is assumed"},
    {RSA_OPT_QUITE, 'q', "quite", no_argument, "set quite output"},
    {RSA_OPT_VERBOSE, 'v', "verbose", no_argument, "set verbose output"},
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
	ptr->has_arg = cur->arg_required;
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
    rsa_strcat(str, code2str(arg_requirements, cur->arg_required));
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

int rsa_set_key_name(char *name)
{
    if (strlen(name) >= KEY_DATA_MAX_LEN)
    {
	rsa_error_message(RSA_ERR_KEYNAME, KEY_DATA_MAX_LEN - 1);
	return -1;
    }
    sprintf(key_data, "%s", name);
    return 0;
}

int rsa_set_file_name(char *name)
{
    struct stat st;
    int ret = -1;

    if (strlen(name) >= sizeof(file_name))
    {
	rsa_error_message(RSA_ERR_FNAME_LEN, name);
	goto Exit;
    }
    if (stat(name, &st))
    {
	if (errno == EOVERFLOW)
	    rsa_error_message(RSA_ERR_FILE_TOO_LARGE, name, "to open");
	else
	    rsa_error_message(RSA_ERR_FILE_NOT_EXIST, name);
	goto Exit;
    }
    if (S_ISDIR(st.st_mode))
    {
	rsa_error_message(RSA_ERR_FILE_IS_DIR, name);
	goto Exit;
    }
    if (!S_ISREG(st.st_mode))
    {
	rsa_error_message(RSA_ERR_FILE_NOT_REG, name);
	goto Exit;
    }
    file_size = st.st_size;
    sprintf(file_name, "%s", name);
    ret = 0;

Exit:
    return ret;
}

static int parse_args_finalize(int *flags, rsa_handler_t *handler)
{
    int actions = 0;

    if (*flags & OPT_FLAG(RSA_OPT_HELP))
	actions++;
    if (*flags & OPT_FLAG(RSA_OPT_KEY_SCAN))
	actions++;
    if (*flags & OPT_FLAG(RSA_OPT_KEY_SET_DEFAULT))
	actions++;
    if (*flags & OPT_FLAG(RSA_OPT_PATH))
	actions++;

    /* test for a single action option */
    if (actions > 1)
    {
	rsa_error_message(RSA_ERR_MULTIACTION);
	return -1;
    }

    return handler->ops_handler_finalize(flags, actions);
}

int parse_args(int argc, char *argv[], int *flags, 
    rsa_handler_t *handler)
{
    int opt, code;

    optargs_init(handler->options);
    while ((opt = getopt_long(argc, argv, optstring, longopts, NULL)) != -1)
    {
	switch (code = opt_short2code(options_common, opt))
	{
	case RSA_OPT_HELP:
	case RSA_OPT_KEY_SCAN:
	case RSA_OPT_PATH:
	    OPT_ADD(flags, code);
	    break;
	case RSA_OPT_KEY_SET_DEFAULT:
	    OPT_ADD(flags, RSA_OPT_KEY_SET_DEFAULT);
	    if (optarg && rsa_set_key_name(optarg))
		return -1;
	    break;
	case RSA_OPT_QUITE:
	case RSA_OPT_VERBOSE:
	    OPT_ADD(flags, code);
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

static void rsa_usage(char *path)
{
    char *ptr;

    for (ptr = path + strlen(path) - 1; ptr >= path && *ptr != '/'; ptr--);
    printf("usage: %s [ OPTIONS ]\n\n", ++ptr);
}

int rsa_error(char *app)
{
    rsa_usage(app);
    printf("Try `rsa --help' for more options.\n");
    return -1;
}

static void option_print_desc(char *desc)
{
#define OPTION_DESC_COLUMN 7
#define OPTION_DESC_LINE_SZ 73
    char fmt[20], buf[OPTION_DESC_LINE_SZ + 1];
    int cnt, remain = strlen(desc);

    sprintf(fmt, C_INDENTATION_FMT "\n", OPTION_DESC_COLUMN);
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
	printf(fmt, buf);
    }
    while (remain);
}

static void output_option_array(opt_t *arr)
{
    char fmt[100];
    char *args[3][2] = {
	[ no_argument ] = {"", ""},
	[ optional_argument] = {"[" ARG "]", "[=" ARG "]"},
	[ required_argument ] = {" " ARG, "=" ARG}
    };

    sprintf(fmt, "  -%%c%%s, --%%s%%s\n");
    for ( ; arr->code != RSA_OPT_MAX; arr++)
    {
	if (!arr->description)
	    continue;

	printf(rsa_highlight_str(fmt, arr->short_opt, 
	    args[arr->arg_required][0], arr->long_opt, 
	    args[arr->arg_required][1]));
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

    printf("\n%c IAS, February 2007\n", CHAR_COPYRIGHT);
}

int rsa_set_key_data(char *name)
{
    int name_len = strlen(name);

    if (name_len > KEY_DATA_MAX_LEN - 1)
    {
	rsa_error_message(RSA_ERR_KEYNAME, KEY_DATA_MAX_LEN - 1);
	return -1;
    }

    /* key_data[0] is reserved for key data (encryption type and level) */
    memcpy(key_data + 1, name, name_len);
    return 0;
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

int rsa_encryption_level_set(char *arg)
{
    if (!arg)
	rsa_encryption_level = RSA_ENCRYPTION_LEVEL_DEFAULT;
    else
    {
	char *err;
	rsa_encryption_level = strtol(arg , &err, 10);

	if (*err)
	    goto Error;
    }

    if (!number_enclevl_set(rsa_encryption_level))
	return 0;

Error:
    rsa_error_message(RSA_ERR_LEVEL, optarg);
    return -1;
}

static int rsa_key_size(void)
{
    int *level, accum = 0;

    for (level = encryption_levels; *level; level++)
	accum += number_size(*level);

    return strlen(RSA_SIGNITURE) + number_size(encryption_levels[0]) + 3*accum;
}

static rsa_key_t *rsa_key_alloc(char type, char *name, char *path, FILE *file)
{
    rsa_key_t *key;

    if (!(key = calloc(1, sizeof(rsa_key_t))))
	return NULL;

    key->type = type;
    snprintf(key->name, KEY_DATA_MAX_LEN, name);
    sprintf(key->path, path);
    key->file = file;

    return key;
}

void rsa_key_close(rsa_key_t *key)
{
    fclose(key->file);
    free(key);
}

static rsa_keyring_t *rsa_keyring_alloc(rsa_key_t *key)
{
    rsa_keyring_t *kr;

    if (!(kr = calloc(1, sizeof(rsa_keyring_t))))
	return NULL;

    kr->name = key->name;
    kr->keys[key->type==RSA_KEY_TYPE_PUBLIC] = key;

    return kr;
}

static void rsa_keyring_insert(rsa_keyring_t *kr, rsa_key_t *key)
{
    rsa_key_t **keyp;
    int idx = (key->type == RSA_KEY_TYPE_PUBLIC);

    kr->is_ambiguous[idx] = kr->keys[idx] ? 1 : 0;
    for (keyp = &kr->keys[idx]; *keyp; keyp = &(*keyp)->next);
    *keyp = key;
}

static void rsa_keyring_free(rsa_keyring_t *kr)
{
    rsa_key_t *prv, *pub, *tmp;

    prv = kr->keys[0];
    pub = kr->keys[1];

    while (prv)
    {
	tmp = prv;
	prv = prv->next;
	rsa_key_close(tmp);
    }
    while (pub)
    {
	tmp = pub;
	pub = pub->next;
	rsa_key_close(tmp);
    }

    free(kr);
}

static char *keydata_extract(FILE *f)
{
    static u1024_t data;
    u1024_t scrambled_data, exp, n, montgomery_factor;

    number_enclevl_set(encryption_levels[0]);
    rsa_read_u1024_full(f, &scrambled_data);
    rsa_read_u1024_full(f, &exp);
    rsa_read_u1024_full(f, &n);
    rsa_read_u1024_full(f, &montgomery_factor);
    number_montgomery_factor_set(&n, &montgomery_factor);

    rsa_decode(&data, &scrambled_data, &exp, &n);
    if (rsa_encryption_level)
	number_enclevl_set(rsa_encryption_level);
    return (char*)data.arr;
}

static rsa_key_t *rsa_key_open_gen(char *path, char accept, int is_expect_key)
{
    int siglen = strlen(RSA_SIGNITURE);
    char signiture[siglen], *data, keytype;
    char *types[2] = { "private", "public" };
    struct stat st;
    FILE *f;

    if (stat(path, &st))
	return NULL;

    if (st.st_size != rsa_key_size())
    {
	if (is_expect_key)
	    rsa_error_message(RSA_ERR_KEY_CORRUPT, path);
	return NULL;
    }
    if (!(f = fopen(path, "r")))
    {
	if (is_expect_key)
	    rsa_error_message(RSA_ERR_KEY_OPEN, path);
	return NULL;
    }
    if (rsa_read_str(f, signiture, siglen) || 
	memcmp(RSA_SIGNITURE, signiture, siglen))
    {
	if (is_expect_key)
	    rsa_error_message(RSA_ERR_KEY_CORRUPT, path);
	fclose(f);
	return NULL;
    }

    data = keydata_extract(f);
    keytype = *data;
    if (!(keytype & accept))
    {
	if (is_expect_key)
	{
	    rsa_error_message(RSA_ERR_KEY_TYPE, path, types[(keytype + 1) % 2], 
		types[keytype % 2]);
	}
	fclose(f);
	return NULL;
    }
    
    return rsa_key_alloc(keytype, data + 1, path, f);
}

static rsa_key_t *rsa_key_open_try(char *path, char accept)
{
    return rsa_key_open_gen(path, accept, 0);
}

static rsa_key_t *rsa_dirent2key(struct dirent *ent, char accept)
{
    char *path = key_path_get(), *fname;
    rsa_key_t *key = NULL;

    if (!(fname = malloc(strlen(path) + 1 + strlen(ent->d_name) + 1)))
	return NULL;

    if (!strcmp(ent->d_name, RSA_KEYLINK_PREFIX ".prv") || !strcmp(ent->d_name, 
	RSA_KEYLINK_PREFIX ".pub"))
    {
	goto Exit;
    }

    sprintf(fname, "%s/%s", path, ent->d_name);
    key = rsa_key_open_try(fname, accept);

Exit:
    free(fname);
    return key;
}

static int keyname_insert(rsa_keyring_t **keyring, rsa_key_t *key)
{
    /* search keyring for the opposite type of key */
    for ( ; *keyring && strcmp((*keyring)->name, key->name); 
	keyring = &(*keyring)->next);

    if (!*keyring)
	return (*keyring = rsa_keyring_alloc(key)) ? 0 : -1;

    rsa_keyring_insert(*keyring, key);
    return 0;
}

static rsa_keyring_t *keyring_gen(char accept)
{
    DIR *dir;
    struct dirent *ent;
    rsa_keyring_t *keyring = NULL;
    char *path = key_path_get();

    if (!(dir = opendir(path)))
    {
	rsa_error_message(RSA_ERR_KEYPATH, path);
	return NULL;
    }

    while ((ent = readdir(dir)))
    {
	rsa_key_t *key;

	if (!(key = rsa_dirent2key(ent, accept)))
	    continue;
	keyname_insert(&keyring, key);
    }

    closedir(dir);
    return keyring;
}

static rsa_key_t *rsa_key_open_dyn(char accept)
{
    rsa_keyring_t *keyring;
    rsa_key_t *key = NULL;
    int idx;
    u1024_t data;

    if (!(keyring = keyring_gen(accept)))
	goto Exit;

    /* if decrypting - get the encrypted file's key data */
    if (!(idx = (accept == RSA_KEY_TYPE_PUBLIC)))
    {
	FILE *f;

	if (!(f = fopen(file_name, "r")))
	    goto Exit;

	number_enclevl_set(encryption_levels[0]);
	rsa_read_u1024_full(f, &data);
	fclose(f);
    }

    while (keyring)
    {
	rsa_keyring_t *tmp;

	/* if encrypting and public key found */
	if (accept == RSA_KEY_TYPE_PUBLIC && !strcmp(key_data, keyring->name))
	    break;

	/* if decrypting */
	if (accept == RSA_KEY_TYPE_PRIVATE)
	{
	    u1024_t buf;

	    /* since we're searching all keys we don't mind about ambiguity */
	    keyring->is_ambiguous[idx] = 0;
	    rsa_key_enclev_set(keyring->keys[idx], encryption_levels[0]);
	    rsa_decode(&buf, &data, &keyring->keys[idx]->exp, 
		&keyring->keys[idx]->n);

	    /* exhaust the list of keys sprouting form the current link in the
	     * keyring and see if any of them can correctly decrypt the key name
	     */
	    if (!memcmp((char *)buf.arr + 1, keyring->keys[idx]->name, 
		strlen(keyring->keys[idx]->name)))
	    {
		break;
	    }
	    else if (keyring->keys[idx]->next)
	    {
		rsa_key_t *tmp;

		tmp = keyring->keys[idx];
		keyring->keys[idx] = keyring->keys[idx]->next;
		rsa_key_close(tmp);
		continue;
	    }
	}

	/* get next link in the keyring */
	tmp = keyring;
	keyring = keyring->next;
	rsa_keyring_free(tmp);
    }

    /* did not find a key with the name we're looking for */
    if (!keyring)
	goto Exit;

    /* there are multiple keys with the name we're looking for - ambiguous */
    if (keyring->is_ambiguous[idx])
    {
	rsa_error_message(RSA_ERR_KEYMULTIENTRIES, idx ? "private" : "public", 
	    rsa_highlight_str(key_data));
	goto Exit;
    }

    /* this is the key we're looking for! */
    key = keyring->keys[idx];
    keyring->keys[idx] = keyring->keys[idx]->next;

Exit:
    while (keyring)
    {
	rsa_keyring_t *tmp;

	tmp = keyring;
	keyring = keyring->next;
	rsa_keyring_free(tmp);
    }

    return key;
}

static rsa_key_t *rsa_key_open_default(char accept)
{
    char path[MAX_FILE_NAME_LEN], *ext[2] = { "pub", "prv" };

    sprintf(path, "%s/" RSA_KEYLINK_PREFIX ".%s", key_path_get(), 
	ext[(accept) % 2]);
    return rsa_key_open_gen(path, accept, 1);
}

rsa_key_t *rsa_key_open(char accept)
{
    rsa_key_t *key;
    int is_public = accept == RSA_KEY_TYPE_PUBLIC;

    if (is_public && *key_data)
	return rsa_key_open_dyn(RSA_KEY_TYPE_PUBLIC);

    key = is_encryption_info_only ? NULL : rsa_key_open_default(accept);

    if (!is_public && !key)
	key = rsa_key_open_dyn(RSA_KEY_TYPE_PRIVATE);

    if (!key)
    {
	if (is_public)
	    rsa_error_message(RSA_ERR_KEY_STAT_PUB_DEF);
	else
	    rsa_error_message(RSA_ERR_KEY_STAT_PRV_DYN, file_name);
    }

    return key;
}

int rsa_key_enclev_set(rsa_key_t *key, int new_level)
{
    int offset, *level, ret;
    u1024_t montgomery_factor;

    /* rsa signature */
    offset = strlen(RSA_SIGNITURE);

    /* rsa key data */
    offset += number_size(encryption_levels[0]);

    /* rsa key sets */
    for (level = encryption_levels; *level && *level != new_level; level++)
	offset += 3*number_size(*level);

    if (!*level || fseek(key->file, offset, SEEK_SET))
    {
	rsa_error_message(RSA_ERR_INTERNAL, __FILE__, __FUNCTION__, __LINE__);
	return -1;
    }

    number_enclevl_set(new_level);
    ret = rsa_read_u1024_full(key->file, &key->exp) ||
	rsa_read_u1024_full(key->file, &key->n) || 
	rsa_read_u1024_full(key->file, &montgomery_factor) ? -1 : 0;
    if (!ret)
	number_montgomery_factor_set(&key->n, &montgomery_factor);
    return ret;
}

static void keyname_display_init(char *key, int idx)
{

    char fmt[20], lnk[MAX_FILE_NAME_LEN];
    struct stat st;

    sprintf(lnk, "%s/%s.%s", key_path_get(), RSA_KEYLINK_PREFIX, 
	idx ? "pub" : "prv");
    memset(key, 0, MAX_FILE_NAME_LEN);
    if (lstat(lnk, &st) || (readlink(lnk, key, MAX_FILE_NAME_LEN) == -1))
	*key = 0;
    sprintf(fmt, "%%-%ds", KEY_DISPLAY_WIDTH);
    printf(fmt, idx ? "public keys" : "private keys");
}

static int keyname_display_single_verbose(rsa_keyring_t *kr, 
    char *lnkname, int idx, int is_ambiguous)
{
    char fmt[20];
    rsa_key_t *key;

    if (!kr->keys[idx])
	return 0;

    if ((!is_ambiguous && kr->is_ambiguous[idx]) || 
	(is_ambiguous && !kr->is_ambiguous[idx]))
    {
	return 1;
    }

    sprintf(fmt, " %%s");
    printf(fmt, !strcmp(kr->keys[idx]->path, lnkname) ? 
	rsa_highlight_str("%s %s", kr->name, KEY_DISPLAY_DEFAULT) : kr->name);
    sprintf(fmt, C_INDENTATION_FMT, KEY_DISPLAY_WIDTH);
    for (key = kr->keys[idx]; key; key = key->next)
	rsa_printf(1, 1, fmt, key->path);

    return 0;
}

static void keyname_display_verbose_idx(rsa_keyring_t *keyring, int idx)
{
    char lnk[MAX_FILE_NAME_LEN];
    rsa_keyring_t *ring_ptr;
    int is_ambiguous = 0;

    keyname_display_init(lnk, idx);
    printf("files\n");

    for (ring_ptr = keyring; ring_ptr; ring_ptr = ring_ptr->next)
	is_ambiguous += keyname_display_single_verbose(ring_ptr, lnk, idx, 0);

    if (!is_ambiguous)
	return;

    printf(MULTIPLE_ENTRIES_STR);
    for (ring_ptr = keyring; ring_ptr; ring_ptr = ring_ptr->next)
	keyname_display_single_verbose(ring_ptr, lnk, idx, 1);
}

static void keyname_display_verbose(rsa_keyring_t *keyring, char keytype)
{
    if (keytype & RSA_KEY_TYPE_PRIVATE)
	keyname_display_verbose_idx(keyring, 0);
    if ((keytype & RSA_KEY_TYPE_PRIVATE) && (keytype & RSA_KEY_TYPE_PUBLIC))
	printf("\n");
    if (keytype & RSA_KEY_TYPE_PUBLIC)
	keyname_display_verbose_idx(keyring, 1);

    while (keyring)
    {
	rsa_keyring_t *ring_ptr;

	ring_ptr = keyring;
	keyring = keyring->next;
	rsa_keyring_free(ring_ptr);
    }
}

static int keyname_display_single(char *fmt, rsa_keyring_t *kr, 
    char *lnkname, int idx, int is_keytype_other)
{
    int do_print;

    if (kr->is_ambiguous[idx] || !kr->keys[idx])
    {
	if (is_keytype_other && !kr->is_ambiguous[1 - idx])
	    printf(fmt, "");
	do_print = 0;
    }
    else
    {
	char name[MAX_HIGHLIGHT_STR + 1];

	sprintf(name, " %s", kr->name);
	if (!strcmp(kr->keys[idx]->path, lnkname))
	{
	    strcat(name, " " KEY_DISPLAY_DEFAULT);
	    printf(rsa_highlight_str(fmt, name));
	}
	else
	    printf(fmt, name);
	do_print = 1;
    }

    return do_print;
}

static void keyname_display(rsa_keyring_t *keyring, char keytype)
{
    char fmt[20];
    char prv[MAX_FILE_NAME_LEN], pub[MAX_FILE_NAME_LEN];
    rsa_keyring_t *ambiguous = NULL;

    if (keytype & RSA_KEY_TYPE_PRIVATE)
	keyname_display_init(prv, 0);
    if (keytype & RSA_KEY_TYPE_PUBLIC)
	keyname_display_init(pub, 1);
    printf("\n");

    sprintf(fmt, "%%-%ds", KEY_DISPLAY_WIDTH);
    while (keyring)
    {
	int do_print = 0;
	rsa_keyring_t *cur = keyring;

	keyring = keyring->next;

	if (keytype & RSA_KEY_TYPE_PRIVATE)
	{
	    do_print += keyname_display_single(fmt, cur, prv, 0,
		keytype & RSA_KEY_TYPE_PUBLIC);
	}
	if (keytype & RSA_KEY_TYPE_PUBLIC)
	{
	    do_print += keyname_display_single(fmt, cur, pub, 1,
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
	rsa_keyring_free(cur);
    }

    if (!ambiguous)
	return;

    printf(MULTIPLE_ENTRIES_STR);
    while (ambiguous)
    {
	char name[MAX_FILE_NAME_LEN + 1];
	rsa_keyring_t *cur = ambiguous;

	ambiguous = ambiguous->next;

	sprintf(name, " %s", cur->name);
	if (keytype & RSA_KEY_TYPE_PRIVATE)
	    printf(fmt, cur->is_ambiguous[0] ? name : "");
	if (keytype & RSA_KEY_TYPE_PUBLIC)
	    printf(fmt, cur->is_ambiguous[1] ? name : "");
	printf("\n");
	rsa_keyring_free(cur);
    }
}

static void rsa_scankeys(char keytype)
{
    rsa_keyring_t *keyring;
    
    if (!(keyring = keyring_gen(keytype)))
	return;

    if (rsa_verbose_get() == V_VERBOSE)
	keyname_display_verbose(keyring, keytype);
    else
	keyname_display(keyring, keytype);
}

static void key_set_display(char *type)
{
    rsa_printf(0, 0, "default %s key: %s", type, *key_data ? 
	rsa_highlight_str(key_data) : "not set");
}

static void rsa_setkey_symlink_set(rsa_keyring_t *kr, int idx)
{
    char lnkname[MAX_FILE_NAME_LEN]; 

    sprintf(lnkname, "%s/%s.%s", key_path_get(), RSA_KEYLINK_PREFIX, 
	idx ? "pub" : "prv");
    if (kr->is_ambiguous[idx])
    {
	rsa_warning_message(RSA_ERR_KEYMULTIENTRIES, idx ? "public" : "private",
	    rsa_highlight_str(key_data));
    }
    else if (kr->keys[idx])
    {
	remove(lnkname);
	symlink(kr->keys[idx]->path, lnkname);
	key_set_display(idx ? "public" : "private");
    }

    if (rsa_verbose_get() == V_VERBOSE)
    {
	rsa_key_t *key;

	for (key = kr->keys[idx]; key; key = key->next)
	    rsa_printf(1, 1, "%s", key->path);
    }
}

static void rsa_delkey_links(char keytype)
{
    char lnkname[MAX_FILE_NAME_LEN]; 

    if (keytype & RSA_KEY_TYPE_PRIVATE)
    {
	key_set_display("private");
	sprintf(lnkname, "%s/%s", key_path_get(), RSA_KEYLINK_PREFIX ".prv");
	remove(lnkname);
    }
    if (keytype & RSA_KEY_TYPE_PUBLIC)
    {
	key_set_display("public");
	sprintf(lnkname, "%s/%s", key_path_get(), RSA_KEYLINK_PREFIX ".pub");
	remove(lnkname);
    }
}

static int rsa_setkey_links(rsa_keyring_t *keyring, char keytype)
{
    rsa_keyring_t *kr = NULL;
    int ret;

    while (keyring)
    {
	rsa_keyring_t *tmp = keyring;

	keyring = keyring->next;
	if (!kr && !strcmp(tmp->name, key_data))
	    kr = tmp;
	else
	    rsa_keyring_free(tmp);
    }
    if (!kr)
    {
	rsa_error_message(RSA_ERR_KEYNOTEXIST, rsa_highlight_str(key_data));
	return -1;
    }

    if (keytype & RSA_KEY_TYPE_PRIVATE)
	rsa_setkey_symlink_set(kr, 0);
    if (keytype & RSA_KEY_TYPE_PUBLIC)
	rsa_setkey_symlink_set(kr, 1);

    ret = kr->is_ambiguous[0] || kr->is_ambiguous[1];
    rsa_keyring_free(kr);

    return ret;
}

static void rsa_setkey(char keytype)
{
    rsa_keyring_t *keyring;

    if (!*key_data)
	rsa_delkey_links(keytype);
    else if ((keyring = keyring_gen(keytype)))
	rsa_setkey_links(keyring, keytype);
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
    int actions = OPT_FLAG(RSA_OPT_HELP) | OPT_FLAG(RSA_OPT_KEY_SCAN) | 
	OPT_FLAG(RSA_OPT_KEY_SET_DEFAULT) | OPT_FLAG(RSA_OPT_PATH);

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
    case OPT_FLAG(RSA_OPT_KEY_SCAN):
	rsa_scankeys(handler->keytype);
	break;
    case OPT_FLAG(RSA_OPT_KEY_SET_DEFAULT):
	rsa_setkey(handler->keytype);
	break;
    case OPT_FLAG(RSA_OPT_PATH):
	rsa_show_path();
	break;
    default:
	return rsa_error(app);
    }

    return 0;
}

static void rsa_zero_one(u1024_t *res, u1024_t *data)
{
    int i;

    number_assign(*res, *data);
    for (i = 0; i < block_sz_u1024; i++)
	res->arr[i] ^= RSA_RANDOM();
    res->top = -1;
}

void rsa_encode(u1024_t *res, u1024_t *data, u1024_t *exp, u1024_t *n)
{
    u64 q;
    u1024_t r;

    if (number_is_greater_or_equal(data, n))
    {
	u1024_t num_q;

	number_dev(&num_q, &r, data, n);
	q = *(u64*)&num_q;
    }
    else
    {
	number_assign(r, *data);
	q = (u64)0;
    }

    if (number_is_equal(&r, &NUM_0) || number_is_equal(&r, &NUM_1))
    {
	rsa_zero_one(res, data);
	return;
    }

    number_modular_exponentiation_montgomery(res, &r, exp, n);
    res->arr[block_sz_u1024] = q;
}

void rsa_decode(u1024_t *res, u1024_t *data, u1024_t *exp, u1024_t *n)
{
    u64 q;
    u1024_t r;

    if (data->top == -1)
    {
	rsa_zero_one(res, data);
	return;
    }

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

