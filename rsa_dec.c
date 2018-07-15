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
	rsa_printf(0, 0, "private key: %s", private_name);
	rsa_printf(0, 0, "public key: %s", public_name);
    }

    return ret;
}

static void verbose_decryption(int is_full, char *key_name, int level, 
    char *ciphertext, char *plaintext)
{
    rsa_printf(!is_encryption_info_only, 0, "encryption method: %s (%s)", 
	is_full ? "full" : "quick", !is_full ? "rng" : 
	cipher_mode == CIPHER_MODE_CBC ? "cbc" : "ecb");
    rsa_printf(!is_encryption_info_only, 0, "key: %s", key_name);
    rsa_printf(!is_encryption_info_only, 0, "encryption level: %d", level);
    if (!is_encryption_info_only)
    {
	rsa_printf(1, 0, "decrypting: %s", ciphertext);
	rsa_printf(1, 0, "plaintext file: %s", plaintext);
    }
    fflush(stdout);
}

static int rsa_decryption_length(rsa_key_t *key ,FILE *ciphertext)
{
    u1024_t length;

    if (rsa_key_enclev_set(key, encryption_levels[0]) || 
	rsa_read_u1024_full(ciphertext, &length))
    {
	return -1;
    }
    rsa_decode(&length, &length, &key->exp, &key->n);
    return rsa_key_enclev_set(key, rsa_encryption_level) ? 
	-1 : (int)length.arr[0];
}

static int rsa_decrypte_header_common(rsa_key_t *key, FILE *ciphertext, 
    int *is_full)
{
    u1024_t numdata, seed;
    char *descriptor;
    int i, *level;

    if (rsa_key_enclev_set(key, encryption_levels[0]) || 
	rsa_read_u1024_full(ciphertext, &numdata))
    {
	return -1;
    }

    rsa_decode(&numdata, &numdata, &key->exp, &key->n);
    descriptor = (char *)numdata.arr;

    if (memcmp(key->name, descriptor + 1, strlen(key->name)))
    {
	rsa_error_message(RSA_ERR_KEY_STAT_PRV_DEF, file_name, 
	    rsa_highlight_str(key->name));
	return -1;
    }

    /* get encryption level */
    for (level = encryption_levels, i = 0; *level && !(*descriptor & 1<<i); 
	level++, i++);
    if (!*level)
    {
	rsa_error_message(RSA_ERR_INTERNAL, __FILE__, __FUNCTION__, __LINE__);
	return -1;
    }

    /* get encryption mode (full/quick) */
    *is_full = (*descriptor & RSA_DESCRIPTOR_FULL_ENC) ? 1 : 0;

    /* get cipher mode (ECB, CBC) */
    switch (*descriptor & RSA_DESCRIPTOR_CIPHER_MODE)
    {
    case RSA_DESCRIPTOR_CIPHER_MODE_CBC:
	cipher_mode = CIPHER_MODE_CBC;
	break;
    case RSA_DESCRIPTOR_CIPHER_MODE_ECB:
    default:
	cipher_mode = CIPHER_MODE_ECB;
	break;
    }

    rsa_encryption_level = *level;
    if (rsa_key_enclev_set(key, rsa_encryption_level) || 
	rsa_read_u1024_full(ciphertext, &seed))
    {
	return -1;
    }
    rsa_decode(&seed, &seed, &key->exp, &key->n);
    if (number_seed_set_fixed(&seed))
	return -1;

    if ((file_size = rsa_decryption_length(key, ciphertext)) < 0)
    {
	rsa_error_message(RSA_ERR_INTERNAL, __FILE__, __FUNCTION__, __LINE__);
	return -1;
    }

    return 0;
}

static int rsa_decrypt_prolog(rsa_key_t **key, FILE **plaintext, 
    FILE **ciphertext, int *is_full)
{
    int file_name_len, is_enable;

    /* open RSA private key */
    if (!(*key = rsa_key_open(RSA_KEY_TYPE_PRIVATE)))
	return -1;

    /* open file to decrypt */
    if (!(*ciphertext = fopen(file_name, "r")))
    {
	rsa_key_close(*key);
	rsa_error_message(RSA_ERR_FOPEN, file_name);
	return -1;
    }

    /* decipher common headers */
    if (rsa_decrypte_header_common(*key, *ciphertext, is_full))
    {
	rsa_key_close(*key);
	fclose(*ciphertext);
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
		!(*plaintext = fopen(newfile_name, "w")))
	{
	    rsa_key_close(*key);
	    fclose(*ciphertext);
	    if (is_enable)
		rsa_error_message(RSA_ERR_FOPEN, newfile_name);
	    return -1;
	}
    }

    verbose_decryption(*is_full, (*key)->name, rsa_encryption_level, file_name, 
	newfile_name);

    return 0;
}

static void rsa_decrypt_epilog(rsa_key_t *key, FILE *plaintext, 
    FILE *ciphertext)
{
    rsa_key_close(key);
    fclose(ciphertext);
    if (is_encryption_info_only)
	return;
    fclose(plaintext);
    if (!keep_orig_file)
	remove(file_name);
}

static int rsa_decrypt_quick(rsa_key_t *key, FILE *ciphertext, FILE *plaintext)
{
    int len, buf_len;

    buf_len = sizeof(u64) * BUF_LEN_UNIT_QUICK;
    rsa_timeline_init(file_size, buf_len);
    do
    {
	char buf[buf_len];
	u64 *xor_buf = (u64*)buf;
	int i;

	len = fread(buf, sizeof(char), buf_len, ciphertext);
	for (i = 0; len && i < (len-1)/sizeof(u64) + 1; i++)
	    xor_buf[i] ^= RSA_RANDOM();
	fwrite(buf, sizeof(char), len, plaintext);
	rsa_timeline_update();
    }
    while (len == buf_len);
    rsa_timeline_uninit();
    return 0;
}

static int rsa_decrypt_full(rsa_key_t *key, FILE *ciphertext, FILE *plaintext)
{
    int len, ct_buf_len, pt_blk_sz, ct_blk_sz;
    u1024_t num_iv, tmp;

    /* determine plaintext block size and ciphertext buffer length */
    pt_blk_sz = rsa_encryption_level/sizeof(u64);
    ct_blk_sz = number_size(rsa_encryption_level);
    ct_buf_len = BLOCKS_PER_DATA_BUF * ct_blk_sz;
    len = 0;

    /* cipher mode initialization */
    switch (cipher_mode)
    {
    case CIPHER_MODE_CBC:
	number_init_random(&num_iv, block_sz_u1024);
	break;
    case CIPHER_MODE_ECB:
    default:
	break;
    }

    rsa_timeline_init(file_size, block_sz_u1024*sizeof(u64));
    do
    {
	u1024_t ct_buf[ct_buf_len];
	int i;

	for (i = 0; i < ct_buf_len && len < file_size; i++)
	{
	    if (rsa_read_u1024_full(ciphertext, &ct_buf[i]))
		break;

	    /* pre decrypting cipher mode handling */
	    switch (cipher_mode)
	    {
	    case CIPHER_MODE_CBC:
		number_assign(tmp, ct_buf[i]);
		break;
	    case CIPHER_MODE_ECB:
	    default:
		break;
	    }

	    rsa_decode(&ct_buf[i], &ct_buf[i], &key->exp, &key->n);

	    /* post decrypting cipher mode handling */
	    switch (cipher_mode)
	    {
	    case CIPHER_MODE_CBC:
		number_xor(&ct_buf[i], &ct_buf[i], &num_iv);
		number_assign(num_iv, tmp);
		num_iv.arr[block_sz_u1024] = 0;
		number_top_set(&num_iv);
		break;
	    case CIPHER_MODE_ECB:
	    default:
		break;
	    }

	    len += fwrite(&ct_buf[i].arr, sizeof(char), 
		MIN(pt_blk_sz, file_size - len), plaintext);
	    rsa_timeline_update();
	}
    }
    while (len < file_size);
    rsa_timeline_uninit();
    return 0;
}

int rsa_decrypt(void)
{
    rsa_key_t *key;
    FILE *plaintext, *ciphertext;
    int ret, is_full;

    if (rsa_decrypt_prolog(&key, &plaintext, &ciphertext, &is_full))
	return -1;

    if (!is_encryption_info_only)
    {
	ret = is_full ? rsa_decrypt_full(key, ciphertext, plaintext) : 
	    rsa_decrypt_quick(key, ciphertext, plaintext);
    }

    rsa_decrypt_epilog(key, plaintext, ciphertext);
    return ret;
}
