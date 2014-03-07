#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "rsa.h"
#include "mt19937_64.h"
#include "rsa_util.h"
#include "rsa_num.h"

static int key_files_generate(char *private_name, FILE **private_key, 
    char *public_name, FILE **public_key, int len)
{
    char prefix[KEY_DATA_MAX_LEN], *path, *pprv, *ppub; 
    int i, total_len, path_len;
    struct stat st;

    path = key_path_get();
    path_len = strlen(path);

    memset(private_name, 0, len);
    sprintf(private_name, "%s/" , path);
    pprv = private_name + path_len + 1;

    memset(public_name, 0, len);
    sprintf(public_name, "%s/" , path);
    ppub = public_name + path_len + 1;

    rsa_sprintf_nows(prefix, "%s%s", !strcmp(key_data + 1, RSA_KEYLINK_PREFIX) ?
	"_" : "", key_data + 1);
    total_len = path_len + 1 + strlen(prefix) + 4;

    for (i = 0; !stat(private_name, &st) || !stat(public_name, &st); i++)
    {
	if (i)
	{
	    sprintf(pprv++, "_");
	    sprintf(ppub++, "_");
	}

	if (total_len + i == len)
	{
	    char name[MAX_FILE_NAME_LEN];

	    snprintf(name, MAX_FILE_NAME_LEN, "%s.pxx", private_name);
	    rsa_error_message(RSA_ERR_FNAME_LEN, name);
	    return -1;
	}

	rsa_strcat(private_name, "%s.prv", prefix);
	rsa_strcat(public_name, "%s.pub", prefix);
    }

    if (!(*private_key = fopen(private_name, "w")))
    {
	rsa_error_message(RSA_ERR_FOPEN, private_name);
	return -1;
    }
    if (!(*public_key = fopen(public_name, "w")))
    {
	fclose(*private_key);
	rsa_error_message(RSA_ERR_FOPEN, public_name);
	return -1;
    }

    return 0;
}

static int rsa_sign(FILE *key, char keytype, u1024_t *exp, u1024_t *n)
{
    u1024_t signiture, id;

    *key_data = keytype;
    if (number_str2num(&id, key_data))
	return -1;

    rsa_encode(&signiture, &id, exp, n);
    if (rsa_write_str(key, RSA_SIGNITURE, strlen(RSA_SIGNITURE)) || 
	rsa_write_u1024_full(key, &signiture))
    {
	return -1;
    }

    return 0;
}

static int insert_key(FILE *key, u1024_t *exp, u1024_t *n)
{
    u1024_t montgomery_factor;

    number_montgomery_factor_set(n, NULL);
    number_montgomery_factor_get(&montgomery_factor);
    return rsa_write_u1024_full(key, exp) || rsa_write_u1024_full(key, n) || 
	rsa_write_u1024_full(key, &montgomery_factor);
}

/* rsa requires that the value of a given u1024, r, must be less than n to
 * qualify for encryption using n. if r is greater than n then upon decryption 
 * of enc(r) what is calculated is r mod(n), which does not equal r.
 * when encrypting data we can easily come across u1024's with values r > n.
 * to overcome the problem, we calculate x and y such that x*n + y = r and 
 * y < n. we encrypt y, and store x in enc(y)'s u64 buffer. upon decryption, we
 * regenerate r by decrypting enc(y) and adding x*n to the result. this,
 * however, places a restriction on the minimal possible value of n as we must 
 * assert that x can be represented by a single u64. 
 * for any u1024, r, we have: r <= MAX(u1024) and for any u64, x, we have: 
 * x <= MAX(u64). we thus calculate inf (infimum):
 *   inf > MAX(u1024)/MAX(u64)
 * we then require that for any generated n, n >= inf and then for any 
 * r <= MAX(u1024): x = r/n <= MAX(u1024)/inf < MAX(u64).
 */
static void rsa_infimum(u1024_t *inf)
{
    u64 *ptr;

    number_reset(inf);
    for (ptr = (u64*)inf; ptr < (u64*)inf + block_sz_u1024; *ptr++ = (u64)1);
    number_top_set(inf);
    inf->top = block_sz_u1024 - 1;
}

static void rsa_key_generator(u1024_t *n, u1024_t *e, u1024_t *d)
{
    u1024_t p1, p2, p1_sub1, p2_sub1, phi, inf;
    int is_first = 1;

    rsa_infimum(&inf);
    do
    {
	if (is_first)
	    is_first = 0;
	else
	    rsa_error_message(RSA_ERR_KEYGEN);

	rsa_printf(1, 1, "finding first large prime: p1...");
	number_find_prime(&p1);
	rsa_printf(1, 1, "finding second large prime: p2...");
	number_find_prime(&p2);
	rsa_printf(1, 1, "calculating product: n=p1*p2...");
	number_mul(n, &p1, &p2);
    }
    while (!number_is_greater_or_equal(n, &inf));

    number_assign(p1_sub1, p1);
    number_assign(p2_sub1, p2);
    number_sub1(&p1_sub1);
    number_sub1(&p2_sub1);
    rsa_printf(1, 1, 
	"calculating Euler phi function for n: phi=(p1-1)*(p2-1)...");
    number_mul(&phi, &p1_sub1, &p2_sub1);

    rsa_printf(1, 1, "generating public key: (e, n), where e is co prime with "
	"phi...");
    number_init_random_coprime(e, &phi);
    rsa_printf(1, 1, "calculating private key: (d, n), where d is the "
	"multiplicative inverse of e modulo phi...");
    number_modular_multiplicative_inverse(d, e, &phi);
}

int rsa_keygen(void)
{
    int ret, *level, is_first = 1;
    char private_name[MAX_FILE_NAME_LEN], public_name[MAX_FILE_NAME_LEN];
    FILE *private_key, *public_key;

    if (key_files_generate(private_name, &private_key, public_name, &public_key,
	MAX_FILE_NAME_LEN))
    {
	return -1;
    }

    rsa_printf(0, 0, "generating key: %s (this will take a few minutes)", 
	rsa_highlight_str(key_data + 1));
    for (level = encryption_levels; *level; level++)
    {
	u1024_t n, e, d;

	rsa_printf(0, 0, "generating private and public keys: %d bits", *level);
	number_enclevl_set(*level);
	rsa_key_generator(&n, &e, &d);

	rsa_printf(1, 1, "writing %d bit keys...", *level);
	if (is_first)
	{
	    if (rsa_sign(private_key, RSA_KEY_TYPE_PRIVATE, &e, &n) || 
		rsa_sign(public_key, RSA_KEY_TYPE_PUBLIC, &d, &n))
	    {
		ret = -1;
		goto Exit;
	    }

	    is_first = 0;
	}
	if (insert_key(private_key, &d, &n) || insert_key(public_key, &e, &n))
	{
	    ret = -1;
	    goto Exit;
	}
    }
    ret = 0;

Exit:
    fclose(private_key);
    fclose(public_key);

    if (ret)
    {
	remove(private_name);
	remove(public_name);
    }
    else
    {
	printf("private key: %s\n", private_name);
	printf("public key: %s\n", public_name);
    }

    return ret;
}

static void verbose_decryption(int is_full, char *key_name, int level, 
    char *cipher, char *data)
{
    rsa_printf(!is_encryption_info_only, 0, "encryption method: %s", 
	is_full ? "full" : "quick");
    rsa_printf(!is_encryption_info_only, 0, "key: %s", key_name);
    rsa_printf(!is_encryption_info_only, 0, "encryption level: %d", level);
    if (!is_encryption_info_only)
    {
	rsa_printf(1, 0, "decrypting: %s", cipher);
	rsa_printf(1, 0, "data file: %s", data);
    }
    fflush(stdout);
}

static int rsa_decrypte_header_common(rsa_key_t *key, FILE *cipher, 
    int *is_full)
{
    u1024_t numdata, seed;
    char *keydata;
    int i, *level;

    if (rsa_key_enclev_set(key, encryption_levels[0]) || 
	rsa_read_u1024_full(cipher, &numdata))
    {
	return -1;
    }

    rsa_decode(&numdata, &numdata, &key->exp, &key->n);
    keydata = (char *)numdata.arr;

    if (memcmp(key->name, keydata + 1, strlen(key->name)))
    {
	rsa_error_message(RSA_ERR_KEY_STAT_PRV_DEF, file_name, 
	    rsa_highlight_str(key->name));
	return -1;
    }

    for (level = encryption_levels, i = 0; *level && !(*keydata & 1<<i); 
	level++, i++);
    if (!*level)
    {
	rsa_error_message(RSA_ERR_INTERNAL, __FILE__, __FUNCTION__, __LINE__);
	return -1;
    }
    if (*keydata & RSA_KEY_DATA_QUICK)
	*is_full = 0;
    else if (*keydata & RSA_KEY_DATA_FULL)
	*is_full = 1;
    else
    {
	rsa_error_message(RSA_ERR_INTERNAL, __FILE__, __FUNCTION__, __LINE__);
	return -1;
    }

    rsa_encryption_level = *level;
    if (rsa_key_enclev_set(key, rsa_encryption_level) || 
	rsa_read_u1024_full(cipher, &seed))
    {
	return -1;
    }
    rsa_decode(&seed, &seed, &key->exp, &key->n);

    return number_seed_set_fixed(&seed);
}

static int rsa_decrypt_prolog(rsa_key_t **key, FILE **data, FILE **cipher, 
    int *is_full)
{
    int file_name_len, is_enable;

    /* open RSA private key */
    if (!(*key = rsa_key_open(RSA_KEY_TYPE_PRIVATE)))
	return -1;

    /* open file to decrypt */
    if (!(*cipher = fopen(file_name, "r")))
    {
	rsa_key_close(*key);
	rsa_error_message(RSA_ERR_FOPEN, file_name);
	return -1;
    }

    /* decipher common headers */
    if (rsa_decrypte_header_common(*key, *cipher, is_full))
    {
	rsa_key_close(*key);
	fclose(*cipher);
	return -1;
    }

    /* open unencrypted text file */
    if (!is_encryption_info_only)
    {
	file_name_len = strlen(file_name);
	if (file_name_len > 4 && !strcmp(file_name + file_name_len - 4, ".enc"))
	    snprintf(newfile_name, file_name_len - 3, "%s", file_name);
	else
	    sprintf(newfile_name, "%s.dec", file_name);
	if (!(is_enable = is_fwrite_enable(newfile_name)) || 
		!(*data = fopen(newfile_name, "w")))
	{
	    rsa_key_close(*key);
	    fclose(*cipher);
	    if (is_enable)
		rsa_error_message(RSA_ERR_FOPEN, newfile_name);
	    return -1;
	}
    }

    verbose_decryption(*is_full, (*key)->name, rsa_encryption_level, file_name, 
	newfile_name);

    return 0;
}

static void rsa_decrypt_epilog(rsa_key_t *key, FILE *data, FILE *cipher)
{
    rsa_key_close(key);
    fclose(cipher);
    if (is_encryption_info_only)
	return;
    fclose(data);
    if (!keep_orig_file)
	remove(file_name);
}

static int rsa_decrypt_quick(rsa_key_t *key, FILE *cipher, FILE *data)
{
    int len, buf_len;

    buf_len = sizeof(u64) * BUF_LEN_UNIT_QUICK;
    do
    {
	char buf[buf_len];
	u64 *xor_buf = (u64*)buf;
	int i;

	len = fread(buf, sizeof(char), buf_len, cipher);
	for (i = 0; len && i < (len-1)/sizeof(u64) + 1; i++)
	    xor_buf[i] ^= (u64)genrand64_int64();
	fwrite(buf, sizeof(char), len, data);
    }
    while (len == buf_len);
    return 0;
}

static int rsa_decryption_length(rsa_key_t *key ,FILE *cipher)
{
    u1024_t length;

    if (rsa_key_enclev_set(key, encryption_levels[0]) || 
	rsa_read_u1024_full(cipher, &length))
    {
	return -1;
    }
    rsa_decode(&length, &length, &key->exp, &key->n);
    return rsa_key_enclev_set(key, rsa_encryption_level) ? 
	-1 : (int)length.arr[0];
}

static int rsa_decrypt_full(rsa_key_t *key, FILE *cipher, FILE *data)
{
    int len, total_length, data_buf_len, num_buf_len, data_sz, num_sz;

    if ((total_length = rsa_decryption_length(key, cipher)) < 0)
    {
	rsa_error_message(RSA_ERR_INTERNAL, __FILE__, __FUNCTION__, __LINE__);
	return -1;
    }

    data_sz = rsa_encryption_level/sizeof(u64);
    data_buf_len = BUF_LEN_UNIT_FULL * data_sz;
    num_sz = number_size(rsa_encryption_level);
    num_buf_len = BUF_LEN_UNIT_FULL * num_sz;
    len = 0;
    rsa_timeline_init(total_length);
    do
    {
	u1024_t nums[num_buf_len];
	int i;

	for (i = 0; i < num_buf_len && len < total_length; i++)
	{
	    if (rsa_read_u1024_full(cipher, &nums[i]))
		break;
	    rsa_decode(&nums[i], &nums[i], &key->exp, &key->n);
	    len += fwrite(&nums[i].arr, sizeof(char), 
		MIN(data_sz, total_length - len), data);
	    rsa_timeline();
	}
    }
    while (len < total_length);
    rsa_timeline_uninit();
    return 0;
}

int rsa_decrypt(void)
{
    rsa_key_t *key;
    FILE *data, *cipher;
    int ret, is_full;

    if (rsa_decrypt_prolog(&key, &data, &cipher, &is_full))
	return -1;

    if (!is_encryption_info_only)
    {
	ret = is_full ? rsa_decrypt_full(key, cipher, data) : 
	    rsa_decrypt_quick(key, cipher, data);
    }

    rsa_decrypt_epilog(key, data, cipher);
    return ret;
}
