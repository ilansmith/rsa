#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "rsa.h"
#include "rsa_util.h"
#include "rsa_num.h"

static int key_files_generate(char *private_name, FILE **private_key, 
    char *public_name, FILE **public_key, int len)
{
    char prefix[KEY_ID_MAX_LEN], *path, *pprv, *ppub; 
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

    rsa_sprintf_nows(prefix, "%s%s", !strcmp(key_id + 1, RSA_KEYLINK_PREFIX) ? 
	"_" : "", key_id + 1);
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

    *key_id = keytype;
    if (number_str2num(&id, key_id))
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

    number_montgomery_factor_get(&montgomery_factor);
    return rsa_write_u1024_full(key, n) || rsa_write_u1024_full(key, exp) || 
	rsa_write_u1024_full(key, &montgomery_factor);
}

/* rsa requires that the value of a given u1024, r, must be less than n to
 * quailify for encryption using n. if r is greater than n then upon decryption 
 * of enc(r) what is caculated is r mod(n), which does not equal r.
 * when encrypting data we can easily come across u1024's with values r > n.
 * to overcome the problem, we calculate x and y such that x*n + y = r and 
 * y < n. we encrypt y, and store x in enc(y)'s u64 buffer. upon decryption, we
 * regenerate r by decrypting enc(y) and adding x*n to the result. this,
 * however, places a restriction on the minimal possible value of n as we must 
 * assert that x can be represented by a single u64. 
 * for any u1024, r, we have: r <= MAX(u1024) and for any u64, x, we have: 
 * x <= MAX(u64). we thus calculte inf (infimum):
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
    rsa_printf(1, 1, "calculating Euler phi function for n: phi=(p1-1)*(p2-1)...");
    number_mul(&phi, &p1_sub1, &p2_sub1);

    rsa_printf(1, 1, "generating puglic key: (e, n), where e is coprime with "
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

    rsa_printf(0, 0, "generating key: %s%s%s (this will take a few minutes)", 
	C_HIGHLIGHT, key_id + 1, C_NORMAL);
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

