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
    char *data, char *cipher)
{
    rsa_printf(1, 0, "encryption method: %s", is_full ? "full" : "quick");
    rsa_printf(1, 0, "key: %s", key_name);
    rsa_printf(1, 0, "encryption level: %d", level);
    rsa_printf(1, 0, "encrytping: %s", data);
    rsa_printf(1, 0, "ciphertext: %s", cipher);
    fflush(stdout);
}

static int rsa_encrypt_seed(rsa_key_t *key, FILE *f)
{
    u1024_t seed;

    if (rsa_key_enclev_set(key, rsa_encryption_level) || 
	number_seed_set_random(&seed))
    {
	return -1;
    }
    rsa_encode(&seed, &seed, &key->exp, &key->n);
    return rsa_write_u1024_full(f, &seed);
}

static int rsa_encrypt_header_common(rsa_key_t *key, FILE *cipher, int is_full)
{
    u1024_t numdata;
    char keydata[KEY_DATA_MAX_LEN];
    int i, *level;

    for (level = encryption_levels, i = 0; *level && 
	*level != rsa_encryption_level; level++, i++);
    if (!*level || rsa_key_enclev_set(key, encryption_levels[0]))
	return -1;

    memset(keydata, 0, KEY_DATA_MAX_LEN);
    *keydata = (1<<i) | (is_full ? RSA_KEY_DATA_FULL : RSA_KEY_DATA_QUICK);
    memcpy(keydata + 1, key->name, strlen(key->name));
    if (number_data2num(&numdata, keydata, KEY_DATA_MAX_LEN))
	return -1;

    rsa_encode(&numdata, &numdata, &key->exp, &key->n);
    return rsa_write_u1024_full(cipher, &numdata) || 
	rsa_encrypt_seed(key, cipher);
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

static int rsa_encrypt_length(rsa_key_t *key, FILE *cipher)
{
    u1024_t length;

    if (rsa_key_enclev_set(key, encryption_levels[0]))
	return -1;

    number_data2num(&length, &file_size, sizeof(file_size));
    rsa_encode(&length, &length, &key->exp, &key->n);
    if (rsa_write_u1024_full(cipher, &length))
	return -1;

    return rsa_key_enclev_set(key, rsa_encryption_level) ? -1 : file_size;
}

static int rsa_encrypt_prolog(rsa_key_t **key, FILE **data, FILE **cipher, 
    int is_full)
{
    int is_enable;

    /* assert that resulting files will not be LFS and open RSA public key */
    if (rsa_assert_non_lfs(is_full) || 
	!(*key = rsa_key_open(RSA_KEY_TYPE_PUBLIC)))
    {
	return -1;
    }

    /* open file to encrypt */
    if (!(*data = fopen(file_name, "r")))
    {
	rsa_key_close(*key);
	rsa_error_message(RSA_ERR_FOPEN, file_name);
	return -1;
    }

    /* open ciphertext file */
    sprintf(newfile_name, "%s.enc", file_name);
    if (!(is_enable = is_fwrite_enable(newfile_name)) || 
	!(*cipher = fopen(newfile_name, "w")))
    {
	rsa_key_close(*key);
	fclose(*data);
	if (is_enable)
	    rsa_error_message(RSA_ERR_FOPEN, newfile_name);
	return -1;
    }

    verbose_encryption(is_full, (*key)->name, rsa_encryption_level, file_name, 
	newfile_name);

    /* write common headers to cipher */
    if (rsa_encrypt_header_common(*key, *cipher, is_full))
    {
	rsa_key_close(*key);
	fclose(*data);
	fclose(*cipher);
	unlink(newfile_name);
	return -1;
    }

    return 0;
}

static void rsa_encrypt_epilog(rsa_key_t *key, FILE *data, FILE *cipher)
{
    rsa_key_close(key);
    fclose(data);
    fclose(cipher);
}

int rsa_encrypt_quick(void)
{
    rsa_key_t *key;
    FILE *data, *cipher;
    int len, buf_len;

    if (rsa_encrypt_prolog(&key, &data, &cipher, 0))
	return -1;

    /* quick encryption */
    buf_len = sizeof(u64) * BUF_LEN_UNIT_QUICK;
    do
    {
	char buf[buf_len];
	u64 *xor_buf = (u64*)buf;
	int i;

	len = fread(buf, sizeof(char), buf_len, data);
	for (i = 0; len && i < (len-1)/sizeof(u64) + 1; i++)
	    xor_buf[i] ^= (u64)genrand64_int64();
	fwrite(buf, sizeof(char), len, cipher);
    }
    while (len == buf_len);

    rsa_encrypt_epilog(key, data, cipher);
    return 0;
}

int rsa_encrypt_full(void)
{
    rsa_key_t *key;
    FILE *data, *cipher;
    int len, data_buf_len, num_buf_len, arr_sz, num_sz;

    if (rsa_encrypt_prolog(&key, &data, &cipher, 1))
	return -1;
    if ((len = rsa_encrypt_length(key, cipher)) < 0)
    {
	rsa_encrypt_epilog(key, data, cipher);
	unlink(newfile_name);
	return -1;
    }

    /* full encryption */
    arr_sz = rsa_encryption_level/sizeof(u64);
    data_buf_len = BUF_LEN_UNIT_FULL * arr_sz;
    num_sz = number_size(rsa_encryption_level);
    num_buf_len = BUF_LEN_UNIT_FULL * num_sz;
    rsa_timeline_init(len);
    do
    {
	char buf[data_buf_len];
	u1024_t nums[num_buf_len];
	int i;

	len = fread(buf, sizeof(char), data_buf_len, data);
	for (i = 0; len && i < (len-1)/arr_sz + 1; i++)
	{
	    number_data2num(&nums[i], &buf[i*arr_sz], arr_sz);
	    rsa_encode(&nums[i], &nums[i], &key->exp, &key->n);
	    rsa_write_u1024_full(cipher, &nums[i]);
	    rsa_timeline();
	}
    }
    while (len == data_buf_len);
    rsa_timeline_uninit();

    rsa_encrypt_epilog(key, data, cipher);
    return 0;
}

