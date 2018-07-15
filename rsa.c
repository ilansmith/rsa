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
#define MULTIPLE_ENTRIES_STR "the following keys have multiple entries\n"

#define  MIN(x, y) ((x) < (y) ? (x) : (y))

typedef struct rsa_key_link_t {
    struct rsa_key_link_t *next;
    char *name;
    rsa_key_t *keys[2]; /* [PRIVATE][PUBLIC] */
    int is_ambiguous[2];
} rsa_key_link_t;

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
    if (strlen(key) >= KEY_ID_MAX_LEN)
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

static int parse_args_finalize(int *flags, rsa_handler_t *handler)
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
    while ((opt = getopt_long(argc, argv, optstring, longopts, NULL)) 
	!= -1)
    {
	switch (code = opt_short2code(options_common, opt))
	{
	case RSA_OPT_HELP:
	case RSA_OPT_SCANKEYS:
	case RSA_OPT_PATH:
	    OPT_ADD(flags, code);
	    break;
	case RSA_OPT_SETKEY:
	    OPT_ADD(flags, RSA_OPT_SETKEY);
	    if (rsa_set_key_name(optarg))
	    {
		rsa_error_message(RSA_ERR_KEYNAME, KEY_ID_MAX_LEN - 1);
		return -1;
	    }
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

int rsa_error(char *app)
{
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

int rsa_set_key_id(char *name)
{
    int name_len = strlen(name);

    if (name_len > KEY_ID_MAX_LEN - 1)
	return -1;

    /* key_id[0] is reserved for key data (encryption type and level) */
    memcpy(key_id + 1, name, name_len);
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
    char *err;
    int level;

    level = strtol(arg, &err, 10);
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

static rsa_key_t *rsa_key_alloc(char type, char *name, char *path, FILE *file, 
    int level)
{
    rsa_key_t *key;

    if (!(key = calloc(1, sizeof(rsa_key_t))))
	return NULL;

    key->type = type;
    snprintf(key->name, KEY_ID_MAX_LEN, name);
    sprintf(key->path, path);
    key->file = file;
    key->level = level;

    return key;
}

void rsa_key_close(rsa_key_t *key)
{
    fclose(key->file);
    free(key);
}

static rsa_key_link_t *rsa_key_link_alloc(rsa_key_t *key)
{
    rsa_key_link_t *link;

    if (!(link = calloc(1, sizeof(rsa_key_link_t))))
	return NULL;

    link->name = key->name;
    link->keys[key->type==RSA_KEY_TYPE_PUBLIC] = key;

    return link;
}

static void rsa_key_link_insert(rsa_key_link_t *link, rsa_key_t *key)
{
    rsa_key_t **keyp;
    int idx = (key->type == RSA_KEY_TYPE_PUBLIC);

    link->is_ambiguous[idx] = link->keys[idx] ? 1 : 0;
    for (keyp = &link->keys[idx]; *keyp; keyp = &(*keyp)->next);
    *keyp = key;
}

static void rsa_key_link_free(rsa_key_link_t *link)
{
    rsa_key_t *prv, *pub, *tmp;

    prv = link->keys[0];
    pub = link->keys[1];

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

    free(link);
}

static rsa_key_t *rsa_key_open_gen(char *path, char accept, int is_expect_key)
{
    int siglen = strlen(RSA_SIGNITURE);
    char signiture[siglen], *data, keytype;
    char *types[2] = { "private", "public" };
    struct stat st;
    FILE *f;

    if (stat(path, &st))
    {
	if (is_expect_key)
	    rsa_error_message(RSA_ERR_KEY_STAT, path);
	return NULL;
    }

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
    
    return rsa_key_alloc(keytype, data + 1, path, f, encryption_levels[1]);
}

static rsa_key_t *rsa_key_open_try(char *path, char accept)
{
    return rsa_key_open_gen(path, accept, 0);
}

rsa_key_t *rsa_key_open(char *path, char accept)
{
    return rsa_key_open_gen(path, accept, 1);
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

static int keyname_insert(rsa_key_link_t **list, rsa_key_t *key)
{
    /* search keyname list for the opposite type of key */
    for ( ; *list && strcmp((*list)->name, key->name); 
	list = &(*list)->next);

    if (!*list)
	return (*list = rsa_key_link_alloc(key)) ? 0 : -1;

    rsa_key_link_insert(*list, key);
    return 0;
}

char *keydata_extract(FILE *f)
{
    static u1024_t id;
    u1024_t scrambled_id, exp, n, montgomery_factor;

    number_enclevl_set(encryption_levels[0]);
    rsa_read_u1024_full(f, &scrambled_id);
    rsa_read_u1024_full(f, &n);
    rsa_read_u1024_full(f, &exp);
    rsa_read_u1024_full(f, &montgomery_factor);
    number_montgomery_factor_set(&n, &montgomery_factor);

    rsa_decode(&id, &scrambled_id, &exp, &n);
    return (char*)id.arr;
}

static rsa_key_link_t *keylist_gen(char accept)
{
    DIR *dir;
    struct dirent *ent;
    rsa_key_link_t *list = NULL;
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
	keyname_insert(&list, key);
    }

    closedir(dir);
    return list;
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
    sprintf(fmt, "%%-%ds", KEY_ID_MAX_LEN + 1);
    printf(fmt, idx ? "public keys" : "private keys");
}

static int keyname_display_single_verbose(rsa_key_link_t *link, 
    char *lnkname, int idx, int is_ambiguous)
{
    char fmt[20];
    rsa_key_t *key;

    if (!link->keys[idx])
	return 0;

    if ((!is_ambiguous && link->is_ambiguous[idx]) || 
	(is_ambiguous && !link->is_ambiguous[idx]))
    {
	return 1;
    }

    sprintf(fmt, " %%s%%s%%s");
    printf(fmt, !strcmp(link->keys[idx]->path, lnkname) ? 
	C_HIGHLIGHT : C_NORMAL, link->name, C_NORMAL);
    sprintf(fmt, "\r\E[%dC%%s", KEY_ID_MAX_LEN + 1);
    for (key = link->keys[idx]; key; key = key->next)
	rsa_printf(1, 1, fmt, key->path);

    return 0;
}

static void keyname_display_verbose_idx(rsa_key_link_t *list, int idx)
{
    char lnk[MAX_FILE_NAME_LEN];
    rsa_key_link_t *plist;
    int is_ambiguous = 0;

    keyname_display_init(lnk, idx);
    printf("\n");

    for (plist = list; plist; plist = plist->next)
	is_ambiguous += keyname_display_single_verbose(plist, lnk, idx, 0);

    if (!is_ambiguous)
	return;

    printf(MULTIPLE_ENTRIES_STR);
    for (plist = list; plist; plist = plist->next)
	keyname_display_single_verbose(plist, lnk, idx, 1);
}

static void keyname_display_verbose(rsa_key_link_t *list, char keytype)
{
    if (keytype & RSA_KEY_TYPE_PRIVATE)
	keyname_display_verbose_idx(list, 0);
    if ((keytype & RSA_KEY_TYPE_PRIVATE) && (keytype & RSA_KEY_TYPE_PUBLIC))
	printf("\n");
    if (keytype & RSA_KEY_TYPE_PUBLIC)
	keyname_display_verbose_idx(list, 1);

    while (list)
    {
	rsa_key_link_t *plist;

	plist = list;
	list = list->next;
	rsa_key_link_free(plist);
    }
}

static int keyname_display_single(char *fmt, rsa_key_link_t *link, 
    char *lnkname, int idx, int is_keytype_other)
{
    int do_print;

    if (link->is_ambiguous[idx] || !link->keys[idx])
    {
	if (is_keytype_other && !link->is_ambiguous[1 - idx])
	    printf(fmt, C_NORMAL, "", C_NORMAL);
	do_print = 0;
    }
    else
    {
	char name[MAX_FILE_NAME_LEN + 1];

	sprintf(name, " %s", link->name);
	printf(fmt, !strcmp(link->keys[idx]->path, lnkname) ? 
	    C_HIGHLIGHT : C_NORMAL, name, C_NORMAL);
	do_print = 1;
    }

    return do_print;
}

static void keyname_display(rsa_key_link_t *list, char keytype)
{
    char fmt[20];
    char prv[MAX_FILE_NAME_LEN], pub[MAX_FILE_NAME_LEN];
    rsa_key_link_t *ambiguous = NULL;

    if (keytype & RSA_KEY_TYPE_PRIVATE)
	keyname_display_init(prv, 0);
    if (keytype & RSA_KEY_TYPE_PUBLIC)
	keyname_display_init(pub, 1);
    printf("\n");

    sprintf(fmt, "%%s%%-%ds%%s", KEY_ID_MAX_LEN + 1);
    while (list)
    {
	int do_print = 0;
	rsa_key_link_t *cur = list;

	list = list->next;

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
	rsa_key_link_free(cur);
    }

    if (!ambiguous)
	return;

    sprintf(fmt, "%%-%ds", KEY_ID_MAX_LEN + 1);
    printf(MULTIPLE_ENTRIES_STR);
    while (ambiguous)
    {
	char name[MAX_FILE_NAME_LEN + 1];
	rsa_key_link_t *cur = ambiguous;

	ambiguous = ambiguous->next;

	sprintf(name, " %s", cur->name);
	if (keytype & RSA_KEY_TYPE_PRIVATE)
	    printf(fmt, cur->is_ambiguous[0] ? name : "");
	if (keytype & RSA_KEY_TYPE_PUBLIC)
	    printf(fmt, cur->is_ambiguous[1] ? name : "");
	printf("\n");
	rsa_key_link_free(cur);
    }
}

static void rsa_scankeys(char keytype)
{
    rsa_key_link_t *list = keylist_gen(keytype);

    if (rsa_verbose_get() == V_VERBOSE)
	keyname_display_verbose(list, keytype);
    else
	keyname_display(list, keytype);
}

static void rsa_setkey_symlink_set(rsa_key_link_t *link, int idx)
{
    char lnkname[MAX_FILE_NAME_LEN]; 

    sprintf(lnkname, "%s/%s.%s", key_path_get(), RSA_KEYLINK_PREFIX, 
	idx ? "pub" : "prv");
    if (link->is_ambiguous[idx])
    {
	rsa_warning_message(RSA_ERR_KEYMULTIENTRIES, idx ? "public" : "private",
	    C_HIGHLIGHT, key_id, C_NORMAL);
    }
    else if (link->keys[idx])
    {
	unlink(lnkname);
	symlink(link->keys[idx]->path, lnkname);
	printf("%s key set to: %s%s%s\n", idx ? "public" : "private", 
	    C_HIGHLIGHT, key_id, C_NORMAL);
    }

    if (rsa_verbose_get() == V_VERBOSE)
    {
	rsa_key_t *key;

	for (key = link->keys[idx]; key; key = key->next)
	    rsa_printf(1, 1, "%s", key->path);
    }
}

static int rsa_setkey_links(rsa_key_link_t *list, char keytype)
{
    rsa_key_link_t *link = NULL;
    int ret;

    while (list)
    {
	rsa_key_link_t *tmp = list;

	list = list->next;
	if (!link && !strcmp(tmp->name, key_id))
	    link = tmp;
	else
	    rsa_key_link_free(tmp);
    }
    if (!link)
    {
	rsa_error_message(RSA_ERR_KEYNOTEXIST, C_HIGHLIGHT, key_id, C_NORMAL);
	return -1;
    }

    if (keytype & RSA_KEY_TYPE_PRIVATE)
	rsa_setkey_symlink_set(link, 0);
    if (keytype & RSA_KEY_TYPE_PUBLIC)
	rsa_setkey_symlink_set(link, 1);

    ret = link->is_ambiguous[0] || link->is_ambiguous[1];
    rsa_key_link_free(link);

    return ret;
}

static void rsa_setkey(char keytype)
{
    rsa_setkey_links(keylist_gen(keytype), keytype);
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
	return rsa_error(app);
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

