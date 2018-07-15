#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include "mt19937_64.h"
#include "rsa.h"
#include "rsa_num.h"

static void verbose_encryption(int is_full, char *key_name, int level, 
    char *plaintext, char *ciphertext)
{
    rsa_printf(1, 0, "encryption method: %s (%s)", is_full ? "full" : "quick", 
	!is_full ? "rng" : cipher_mode == CIPHER_MODE_CBC ? "cbc" : "ecb");
    rsa_printf(1, 0, "key: %s", key_name);
    rsa_printf(1, 0, "encryption level: %d", level);
    rsa_printf(1, 0, "encrypting: %s", plaintext);
    rsa_printf(1, 0, "ciphertext: %s", ciphertext);
    fflush(stdout);
}

static int rsa_encrypt_seed(rsa_key_t *key, FILE *ciphertext)
{
    u1024_t seed;

    if (rsa_key_enclev_set(key, rsa_encryption_level) || 
	number_seed_set_random(&seed))
    {
	return -1;
    }
    rsa_encode(&seed, &seed, &key->exp, &key->n);
    return rsa_write_u1024_full(ciphertext, &seed);
}

static int rsa_encrypt_length(rsa_key_t *key, FILE *ciphertext)
{
    u1024_t length;

    if (rsa_key_enclev_set(key, encryption_levels[0]))
	return -1;

    number_data2num(&length, &file_size, sizeof(file_size));
    rsa_encode(&length, &length, &key->exp, &key->n);
    if (rsa_write_u1024_full(ciphertext, &length))
	return -1;

    return rsa_key_enclev_set(key, rsa_encryption_level);
}

static int rsa_encrypt_header_common(rsa_key_t *key, FILE *ciphertext, 
    int is_full)
{
    u1024_t numdata;
    char descriptor[KEY_DATA_MAX_LEN];
    int i, *level;

    /* set encryption level */
    for (level = encryption_levels, i = 0; *level && 
	*level != rsa_encryption_level; level++, i++);
    if (!*level || rsa_key_enclev_set(key, encryption_levels[0]))
	return -1;

    memset(descriptor, 0, KEY_DATA_MAX_LEN);
    *descriptor = (1<<i);

    /* set encryption mode (full/quick) */
    if (is_full)
	*descriptor |= RSA_DESCRIPTOR_FULL_ENC;

    /* get cipher mode (ECB, CBC) */
    switch (cipher_mode)
    {
    case CIPHER_MODE_CBC:
	*descriptor |= RSA_DESCRIPTOR_CIPHER_MODE_CBC;
	break;
    case CIPHER_MODE_ECB:
    default:
	*descriptor |= RSA_DESCRIPTOR_CIPHER_MODE_ECB;
	break;
    }
    memcpy(descriptor + 1, key->name, strlen(key->name));
    if (number_data2num(&numdata, descriptor, KEY_DATA_MAX_LEN))
	return -1;

    rsa_encode(&numdata, &numdata, &key->exp, &key->n);
    return rsa_write_u1024_full(ciphertext, &numdata) || 
	rsa_encrypt_seed(key, ciphertext) || 
	rsa_encrypt_length(key, ciphertext) ? -1 : 0;
}

/* Large File System (LFS) is not supported */
static int rsa_assert_non_lfs(int is_full)
{
    unsigned int length;

    /* common to full and quick RSA headers: encrypted key data and seed */
    length = number_size(encryption_levels[0]) + number_size(encryption_level);

    if (is_full)
    {
	int arr_sz = rsa_encryption_level/sizeof(u64);

	/* encrypted length of original file and number of RSA u1024_t's */
	length += number_size(encryption_levels[0]) + 
	    ((file_size + arr_sz - 1)/arr_sz) * number_size(encryption_level);
    }
    else
    {
	/* encrypted data has same length as original data */
	length += file_size;
    }

    if (length > INT_MAX)
    {
	char desc[40];

	sprintf(desc, "for %d bit %s RSA encryption", encryption_level, 
	    is_full ? "full" : "quick");
	rsa_error_message(RSA_ERR_FILE_TOO_LARGE, file_name, desc);
	return -1;
    }

    return 0;
}

static int rsa_encrypt_prolog(rsa_key_t **key, FILE **plaintext, 
    FILE **ciphertext, int is_full)
{
    int is_enable;

    /* assert that resulting files will not be LFS and open RSA public key */
    if (rsa_assert_non_lfs(is_full) || 
	!(*key = rsa_key_open(RSA_KEY_TYPE_PUBLIC)))
    {
	return -1;
    }

    /* open file to encrypt */
    if (!(*plaintext = fopen(file_name, "r")))
    {
	rsa_key_close(*key);
	rsa_error_message(RSA_ERR_FOPEN, file_name);
	return -1;
    }

    /* open ciphertext file */
    sprintf(newfile_name, "%s.enc", file_name);
    if (!(is_enable = is_fwrite_enable(newfile_name)) || 
	!(*ciphertext = fopen(newfile_name, "w")))
    {
	rsa_key_close(*key);
	fclose(*plaintext);
	if (is_enable)
	    rsa_error_message(RSA_ERR_FOPEN, newfile_name);
	return -1;
    }

    verbose_encryption(is_full, (*key)->name, rsa_encryption_level, file_name, 
	newfile_name);

    /* write common headers to ciphertext */
    if (rsa_encrypt_header_common(*key, *ciphertext, is_full))
    {
	rsa_key_close(*key);
	fclose(*plaintext);
	fclose(*ciphertext);
	remove(newfile_name);
	return -1;
    }

    return 0;
}

static void rsa_encrypt_epilog(rsa_key_t *key, FILE *plaintext, 
    FILE *ciphertext)
{
    rsa_key_close(key);
    fclose(plaintext);
    fclose(ciphertext);
    if (!keep_orig_file)
	remove(file_name);
}

int rsa_encrypt_quick(void)
{
    rsa_key_t *key;
    FILE *plaintext, *ciphertext;
    int len, buf_len;

    if (rsa_encrypt_prolog(&key, &plaintext, &ciphertext, 0))
	return -1;

    /* quick encryption */
    buf_len = sizeof(u64) * BUF_LEN_UNIT_QUICK;
    rsa_timeline_init(file_size, buf_len);
    do
    {
	char buf[buf_len];
	u64 *xor_buf = (u64*)buf;
	int i;

	len = fread(buf, sizeof(char), buf_len, plaintext);
	for (i = 0; len && i < (len-1)/sizeof(u64) + 1; i++)
	    xor_buf[i] ^= RSA_RANDOM();
	fwrite(buf, sizeof(char), len, ciphertext);
	rsa_timeline_update();
    }
    while (len == buf_len);
    rsa_timeline_uninit();

    rsa_encrypt_epilog(key, plaintext, ciphertext);
    return 0;
}

int rsa_encrypt_full(void)
{
    rsa_key_t *key;
    FILE *plaintext, *ciphertext;
    int len, pt_buf_len, ct_buf_len, pt_blk_sz, ct_blk_sz;
    u1024_t num_iv;

    if (rsa_encrypt_prolog(&key, &plaintext, &ciphertext, 1))
	return -1;

    /* determine plaintext and ciphertext buffer lengths */
    pt_blk_sz = rsa_encryption_level/sizeof(u64);
    pt_buf_len = BLOCKS_PER_DATA_BUF * pt_blk_sz;
    ct_blk_sz = number_size(rsa_encryption_level);
    ct_buf_len = BLOCKS_PER_DATA_BUF * ct_blk_sz;

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
	char pt_buf[pt_buf_len];
	u1024_t ct_buf[ct_buf_len];
	int i;

	len = fread(pt_buf, sizeof(char), pt_buf_len, plaintext);
	for (i = 0; len && i < (len-1)/pt_blk_sz + 1; i++)
	{
	    number_data2num(&ct_buf[i], &pt_buf[i*pt_blk_sz], pt_blk_sz);

	    /* pre encryption cipher mode handling */
	    switch (cipher_mode)
	    {
	    case CIPHER_MODE_CBC:
		number_xor(&ct_buf[i], &ct_buf[i], &num_iv);
		break;
	    case CIPHER_MODE_ECB:
	    default:
		break;
	    }

	    rsa_encode(&ct_buf[i], &ct_buf[i], &key->exp, &key->n);

	    /* post encryption cipher mode handling */
	    switch (cipher_mode)
	    {
	    case CIPHER_MODE_CBC:
		number_assign(num_iv, ct_buf[i]);
		num_iv.arr[block_sz_u1024] = 0;
		number_top_set(&num_iv);
		break;
	    case CIPHER_MODE_ECB:
	    default:
		break;
	    }

	    rsa_write_u1024_full(ciphertext, &ct_buf[i]);
	    rsa_timeline_update();
	}
    }
    while (len == pt_buf_len);
    rsa_timeline_uninit();

    rsa_encrypt_epilog(key, plaintext, ciphertext);
    return 0;
}

