#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef __linux__
#include <unistd.h>
#endif
#include "rsa_util.h"
#include "rsa_stream.h"

#define RSA_TIMELINE_LEN 80
#define MAX_OUTPUT_LEN 100

#define RSA_SIGNATURE "IASRSA"
#define RSA_SIGNATURE_LEN 6

#ifdef __linux__
#define STRDUP strdup
#else
#define STRDUP _strdup
#endif

typedef int (*io_func_t)(void *ptr, int size, int nmemb, rsa_stream_t *s);

int rsa_encryption_level;

static verbose_t rsa_verbose;
static double timeline_inc;

int code2code(code2code_t *list, int code)
{
	for ( ; list->code != -1 && list->code != code; list++);

	return list->code == -1 ? -1 : list->val;
}

char *code2str(code2str_t *list, int code)
{
	for ( ; list->code != -1 && list->code != code; list++);

	return list->code == -1 ? "" : list->str;
}

int rsa_printf(int is_verbose, int ind, char *fmt, ...)
{
	va_list ap;
	int ret = 0;
	char fmt_eol[MAX_LINE_LENGTH];

	if (rsa_verbose == V_QUIET || (is_verbose && rsa_verbose == V_NORMAL))
		goto Exit;

	if (ind + strlen(fmt) + 1 >= MAX_LINE_LENGTH) {
		ret = -1;
		goto Exit;
	}

	snprintf(fmt_eol, MAX_LINE_LENGTH, "%*s%s%s%s\n", 2*ind, "",
		is_verbose ? C_GREY : C_NORMAL, fmt, C_NORMAL);
	va_start(ap, fmt);
	ret = vprintf(fmt_eol, ap);
	fflush(stdout);
	va_end(ap);

Exit:
	return ret;
}

char *rsa_strcat(char *dest, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(dest + strlen(dest), MAX_OUTPUT_LEN , fmt, ap);
	va_end(ap);

	return dest;
}

char *rsa_vstrcat(char *dest, char *fmt, va_list ap)
{
	vsnprintf(dest + strlen(dest), MAX_OUTPUT_LEN, fmt, ap);

	return dest;
}

int rsa_sprintf_nows(char *str, char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = vsnprintf(str, MAX_OUTPUT_LEN, fmt, ap);
	va_end(ap);

	for ( ; *str; str++) {
		if (IS_WHITESPACE(*str))
			*str = '_';
	}
	return ret;
}

static void rsa_message(int is_error, rsa_errno_t err, va_list ap)
{
	char msg[MAX_LINE_LENGTH];

	snprintf(msg, MAX_OUTPUT_LEN, "%s: ", is_error ? "error" : "warning");
	switch (err)
	{
	case RSA_ERR_ARGREP:
		rsa_vstrcat(msg, "option repeated", ap);
		break;
	case RSA_ERR_ARGNAN:
		rsa_vstrcat(msg, "input not a number: %s", ap);
		break;
	case RSA_ERR_ARGCONFLICT:
		rsa_strcat(msg, "conflicting input switches");
		break;
	case RSA_ERR_NOACTION:
		rsa_strcat(msg, "no RSA action specified");
		break;
	case RSA_ERR_MULTIACTION:
		rsa_strcat(msg, "too many RSA actions");
		break;
	case RSA_ERR_FNAME_LEN:
		rsa_strcat(msg, "file name %s is too long", ap);
		break;
	case RSA_ERR_FILE_TOO_LARGE:
		rsa_vstrcat(msg, "LFS not supported, file %s is too large %s",
			ap);
		break;
	case RSA_ERR_FILE_NOT_EXIST:
		rsa_vstrcat(msg, "file %s does not exist", ap);
		break;
	case RSA_ERR_FILE_IS_DIR:
		rsa_vstrcat(msg, "%s is a directory", ap);
		break;
	case RSA_ERR_FILE_NOT_REG:
		rsa_vstrcat(msg, "%s is not a regular file", ap);
		break;
	case RSA_ERR_FOPEN:
		rsa_vstrcat(msg, "could not open file %s", ap);
		break;
	case RSA_ERR_FILEIO:
		rsa_strcat(msg, "reading/writing file");
		break;
	case RSA_ERR_KEYPATH:
		rsa_vstrcat(msg, "cannot open RSA key directory %s", ap);
		break;
	case RSA_ERR_KEYNAME:
		rsa_vstrcat(msg, "key name is too long (max %d characters)",
			ap);
		break;
	case RSA_ERR_KEYGEN:
		rsa_strcat(msg, "key may cause loss of information, "
			"regenerating...");
		break;
	case RSA_ERR_KEYNOTEXIST:
		rsa_vstrcat(msg, "key %s does not exist in the key directory",
			ap);
		break;
	case RSA_ERR_KEYMULTIENTRIES:
		rsa_vstrcat(msg, "multiple entries for %s key %s - "
			"aborting...", ap);
		break;
	case RSA_ERR_KEY_STAT_PUB_DEF:
		rsa_strcat(msg, "no default RSA public key is set, please "
			"either set one or state the key to be used");
		break;
	case RSA_ERR_KEY_STAT_PRV_DEF:
		rsa_vstrcat(msg, "%s was not encrypted by the default key's "
			"(%s) corresponding public key", ap);
		break;
	case RSA_ERR_KEY_STAT_PRV_DYN:
		rsa_vstrcat(msg, "could not find a private key with which to "
			"decrypt %s", ap);
		break;
	case RSA_ERR_KEY_CORRUPT:
		rsa_vstrcat(msg, "RSA key %s is corrupt", ap);
		break;
	case RSA_ERR_KEY_CORRUPT_BUF:
		rsa_vstrcat(msg, "RSA key %p is corrupt", ap);
		break;
	case RSA_ERR_KEY_OPEN:
		rsa_vstrcat(msg, "unable to open %s", ap);
		break;
	case RSA_ERR_KEY_OPEN_BUF:
		rsa_vstrcat(msg, "unable to open %p", ap);
		break;
	case RSA_ERR_KEY_TYPE:
		rsa_vstrcat(msg, "%s is linked to a %s key while a %s key is "
			"required", ap);
		break;
	case RSA_ERR_KEY_TYPE_BUF:
		rsa_vstrcat(msg, "%p is a %s key while a %s key is required",
			ap);
		break;
	case RSA_ERR_BUFFER_NULL:
		rsa_vstrcat(msg, "initialization buffer is NULL: %p", ap);
		break;
	case RSA_ERR_STREAM_TYPE_UNKNOWN:
		rsa_vstrcat(msg, "stream type unknown: %d", ap);
		break;
	case RSA_ERR_LEVEL:
		rsa_vstrcat(msg, "invalid encryption level - %s", ap);
		break;
	case RSA_ERR_INTERNAL:
		rsa_vstrcat(msg, "internal error in %s: %s(), line: %d", ap);
		break;
	case RSA_ERR_OPTARG:
		/* fall through - error message provided by getopt_long() */
	default:
		return;
	}
	rsa_strcat (msg, "\n");
	printf("%s", msg);
}

void rsa_error_message(rsa_errno_t err, ...)
{
	va_list ap;

	va_start(ap, err);
	rsa_message(1, err, ap);
	va_end(ap);
}

void rsa_warning_message(rsa_errno_t err, ...)
{
	va_list ap;

	va_start(ap, err);
	rsa_message(0, err, ap);
	va_end(ap);
}

static int rsa_io_u1024(rsa_stream_t *s, u1024_t *num, int is_full,
		int is_read)
{
	int ret;
	io_func_t io = is_read ? (io_func_t)rread : (io_func_t)rwrite;

	ret = io(num->arr, sizeof(u64), block_sz_u1024 + (is_full ? 1 : 0),
		s);
	if (is_full)
		ret += io(&num->top, sizeof(int), 1, s);
	else if (is_read)
		number_top_set(num);

	if (ret != (block_sz_u1024 + (is_full ? 2 : 0)) && ret != EOS) {
		rsa_error_message(RSA_ERR_FILEIO);
		return -1;
	}

	return 0;
}

int rsa_read_u1024(rsa_stream_t *s, u1024_t *num)
{
	return rsa_io_u1024(s, num, 0, 1);
}

int rsa_write_u1024(rsa_stream_t *s, u1024_t *num)
{
	return rsa_io_u1024(s, num, 0, 0);
}

int rsa_read_u1024_full(rsa_stream_t *s, u1024_t *num)
{
	return rsa_io_u1024(s, num, 1, 1);
}

int rsa_write_u1024_full(rsa_stream_t *s, u1024_t *num)
{
	return rsa_io_u1024(s, num, 1, 0);
}

static int rsa_io_str(rsa_stream_t *s, char *str, int len, int is_read)
{
	int ret;
	io_func_t io = is_read ? (io_func_t)rread : (io_func_t)rwrite;

	ret = io(str, sizeof(char), len, s);
	if (ret != len && ret != EOF) {
		rsa_error_message(RSA_ERR_FILEIO);
		return -1;
	}
	return 0;
}

int rsa_read_str(rsa_stream_t *s, char *str, int len)
{
	return rsa_io_str(s, str, len, 1);
}

int rsa_write_str(rsa_stream_t *s, char *str, int len)
{
	return rsa_io_str(s, str, len, 0);
}

void rsa_verbose_set(verbose_t level)
{
	rsa_verbose = level;
}

verbose_t rsa_verbose_get(void)
{
	return rsa_verbose;
}

#if defined(__linux__)
int is_fwrite_enable(char *name)
{
	char path[MAX_FILE_NAME_LEN], input[4];
	struct stat st;
	int ret;

	if (!getcwd(path, MAX_FILE_NAME_LEN))
		return 0;
	rsa_strcat(path, "/%s", name);
	if (stat(path, &st))
		return 1; /* file does not exist - no problem */

	printf("the file %s exists, do you want to overwrite it? [y/n]... ",
		name);
	if (scanf("%3s", input) == EOF) {
		rsa_printf(0, 0, "did not receive input, aborting...");
		ret = -1;
		goto Exit;
	}
	input[3] = 0;

	if (!(ret = !strncasecmp("yes", input, strlen(input))))
		rsa_printf(0, 0, "aborting...");

Exit:
	return ret;
}
#endif

char *rsa_highlight_str(char *fmt, ...)
{
	va_list ap;
	static char highlight[MAX_HIGHLIGHT_STR] = C_HIGHLIGHT;
	char *ret = highlight;
	int len = (int)strlen(C_HIGHLIGHT);

	va_start(ap, fmt);
	if ((unsigned int)vsnprintf(highlight + len, MAX_HIGHLIGHT_STR - len, fmt, ap) >
		MAX_HIGHLIGHT_STR - strlen(C_NORMAL)) {
		rsa_error_message(RSA_ERR_INTERNAL, __FILE__, __FUNCTION__,
			__LINE__);
		ret = "";
	} else {
		strncat(highlight, C_NORMAL, strlen(C_NORMAL));
	}
	va_end(ap);

	return ret;
}

int rsa_timeline_init(int len, int block_sz)
{
	char fmt[20];
	int block_num = (len-1)/block_sz + 1;

	if (rsa_verbose == V_QUIET || block_num < 1)
		return 0;

	timeline_inc = (double)block_num/RSA_TIMELINE_LEN;
	snprintf(fmt, ARRAY_SZ(fmt), "[%%-%ds]\r[", RSA_TIMELINE_LEN);

	printf(fmt, "");
	fflush(stdout);

	return 1;
}

void rsa_timeline_update(void)
{
	static int blocks, dots;
	static double timeline;

	if (!timeline_inc || ++blocks < timeline)
		return;

	while (timeline < blocks && dots < RSA_TIMELINE_LEN) {
		dots++;
		timeline += timeline_inc;
		printf(".");
	}
	fflush(stdout);
}

void rsa_timeline_uninit(void)
{
	if (!timeline_inc)
		return;
	printf("\n");
	fflush(stdout);
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

	if (number_is_greater_or_equal(data, n)) {
		u1024_t num_q;

		number_dev(&num_q, &r, data, n);
		q = *(u64*)&num_q;
	} else {
		number_assign(r, *data);
		q = (u64)0;
	}

	if (number_is_equal(&r, &NUM_0) || number_is_equal(&r, &NUM_1)) {
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

	if (data->top == -1) {
		rsa_zero_one(res, data);
		return;
	}

	q = data->arr[block_sz_u1024];
	number_assign(r, *data);
	r.arr[block_sz_u1024] = 0;
	number_modular_exponentiation_montgomery(res, &r, exp, n);

	if (q) {
		u1024_t num_q;

		number_small_dec2num(&num_q, q);
		number_mul(&num_q, &num_q, n);
		number_add(res, res, &num_q);
	}
}

static int rsa_key_size(void)
{
	int *level, accum = 0;

	for (level = encryption_levels; *level; level++)
		accum += number_size(*level);

	return RSA_SIGNATURE_LEN + number_size(encryption_levels[0]) +
		3 * accum;
}

static char *key_info_extract(rsa_stream_t *s)
{
	static u1024_t info_num;
	u1024_t scrambled_info, exp, n, montgomery_factor;

	number_enclevl_set(encryption_levels[0]);
	rsa_read_u1024_full(s, &scrambled_info);
	rsa_read_u1024_full(s, &exp);
	rsa_read_u1024_full(s, &n);
	rsa_read_u1024_full(s, &montgomery_factor);
	number_montgomery_factor_set(&n, &montgomery_factor);

	rsa_decode(&info_num, &scrambled_info, &exp, &n);
	if (rsa_encryption_level)
		number_enclevl_set(rsa_encryption_level);
	return (char*)info_num.arr;
}

static int rsa_stream_init_dup(struct rsa_stream_init *to,
	struct rsa_stream_init *from)
{
	switch (from->type) {
	case RSA_STREAM_TYPE_FILE:
		to->params.file.path = STRDUP(from->params.file.path);
		if (!to->params.file.path)
			return -1;
		to->params.file.mode = from->params.file.mode;
		break;
	case RSA_STREAM_TYPE_MEMORY:
		to->params.memory.buf =
			(unsigned char*)calloc(from->params.memory.len,
				sizeof(char));
		if (!to->params.memory.buf)
			return -1;
		to->params.memory.len= from->params.memory.len;
		break;
	case RSA_STREAM_TYPE_NONE:
	default:
		break;
	}

	to->type = from->type;
	return 0;
}

static void rsa_stream_init_free(struct rsa_stream_init *init)
{
	switch (init->type) {
	case RSA_STREAM_TYPE_FILE:
		free(init->params.file.path);
		break;
	case RSA_STREAM_TYPE_MEMORY:
		free(init->params.memory.buf);
		break;
	case RSA_STREAM_TYPE_NONE:
	default:
		break;
	}
}

static rsa_key_t *rsa_key_alloc(char type, char *name,
		struct rsa_stream_init *init, rsa_stream_t *s)
{
	rsa_key_t *key;

	if (!(key = (rsa_key_t*)calloc(1, sizeof(rsa_key_t))))
		return NULL;

	if (rsa_stream_init_dup(&key->stream_init, init)) {
		free(key);
		return NULL;
	}
	key->type = type;
	snprintf(key->name, KEY_DATA_MAX_LEN, "%s", name);
	key->stream = s;

	return key;
}

rsa_key_t *rsa_key_open(struct rsa_stream_init *init, char accept,
		int is_expect_key)
{
	char signature[RSA_SIGNATURE_LEN], *info, keytype;
	char *key_pair[2] = { "private", "public" };
	struct stat st;
	rsa_stream_t *s;
	rsa_key_t *key;

	switch (init->type) {
	case RSA_STREAM_TYPE_FILE:
		if (stat(init->params.file.path, &st))
			return NULL;

		if (st.st_size != rsa_key_size()) {
			if (is_expect_key) {
				rsa_error_message(RSA_ERR_KEY_CORRUPT,
					init->params.file.path);
			}
			return NULL;
		}
		break;
	case RSA_STREAM_TYPE_MEMORY:
		if (!init->params.memory.buf)
			return NULL;
		if (init->params.memory.len != rsa_key_size()) {
			if (is_expect_key) {
				rsa_error_message(RSA_ERR_BUFFER_NULL,
					init->params.memory.buf);
			}
			return NULL;
		}
		break;
	case RSA_STREAM_TYPE_NONE:
	default:
		rsa_error_message(RSA_ERR_STREAM_TYPE_UNKNOWN, init->type);
		return NULL;
	}

	if (!(s = ropen(init))) {
		if (is_expect_key) {
			switch (init->type) {
			case RSA_STREAM_TYPE_FILE:
				rsa_error_message(RSA_ERR_KEY_OPEN,
					init->params.file.path);
				break;
			case RSA_STREAM_TYPE_MEMORY:
				rsa_error_message(RSA_ERR_KEY_OPEN_BUF,
					init->params.memory.buf);
				break;
			case RSA_STREAM_TYPE_NONE:
			default:
				break;
			}
		}

		return NULL;
	}

	if (rsa_read_str(s, signature, RSA_SIGNATURE_LEN) || 
			memcmp(RSA_SIGNATURE, signature, RSA_SIGNATURE_LEN)) {
		if (is_expect_key) {
			switch (init->type) {
			case RSA_STREAM_TYPE_FILE:
				rsa_error_message(RSA_ERR_KEY_CORRUPT,
					init->params.file.path);
				break;
			case RSA_STREAM_TYPE_MEMORY:
				rsa_error_message(RSA_ERR_KEY_CORRUPT_BUF,
					init->params.memory.buf);
				break;
			case RSA_STREAM_TYPE_NONE:
			default:
				break;
			}
		}

		rclose(s);
		return NULL;
	}

	info = key_info_extract(s);
	keytype = *info;
	if (!(keytype & accept)) {
		if (is_expect_key) {
			switch (init->type) {
			case RSA_STREAM_TYPE_FILE:
				rsa_error_message(RSA_ERR_KEY_TYPE,
					init->params.file.path,
					key_pair[(keytype + 1) % 2],
					key_pair[keytype % 2]);
				break;
			case RSA_STREAM_TYPE_MEMORY:
				rsa_error_message(RSA_ERR_KEY_TYPE_BUF,
					init->params.memory.buf,
					key_pair[(keytype + 1) % 2],
					key_pair[keytype % 2]);
				break;
			case RSA_STREAM_TYPE_NONE:
			default:
				break;
			}
		}
		rclose(s);
		return NULL;
	}

	key = rsa_key_alloc(keytype, info + 1, init, s);
	if (!key) {
		rsa_error_message(RSA_ERR_INTERNAL, __FILE__, __FUNCTION__,
			__LINE__);
	}

	return key;
}

void rsa_key_close(rsa_key_t *key)
{
	if (!key)
		return;

	rclose(key->stream);
	rsa_stream_init_free(&key->stream_init);
	free(key);
}

int rsa_key_enclev_set(rsa_key_t *key, int new_level)
{
	int offset, *level, ret;
	u1024_t montgomery_factor;

	/* rsa signature */
	offset = (int)strlen(RSA_SIGNATURE);

	/* rsa key data */
	offset += number_size(encryption_levels[0]);

	/* rsa key sets */
	for (level = encryption_levels; *level && *level != new_level; level++)
		offset += 3*number_size(*level);

	if (!*level || rseek(key->stream, offset, SEEK_SET)) {
		rsa_error_message(RSA_ERR_INTERNAL, __FILE__, __FUNCTION__,
			__LINE__);
		return -1;
	}

	number_enclevl_set(new_level);
	ret = rsa_read_u1024_full(key->stream, &key->exp) ||
		rsa_read_u1024_full(key->stream, &key->n) || 
		rsa_read_u1024_full(key->stream, &montgomery_factor) ? -1 : 0;
	if (!ret)
		number_montgomery_factor_set(&key->n, &montgomery_factor);
	return ret;
}

int rsa_encrypt_seed(rsa_key_t *key, rsa_stream_t *ciphertext)
{
	u1024_t seed;

	if (rsa_key_enclev_set(key, rsa_encryption_level) || 
		number_seed_set_random(&seed)) {
		return -1;
	}
	rsa_encode(&seed, &seed, &key->exp, &key->n);
	return rsa_write_u1024_full(ciphertext, &seed);
}

