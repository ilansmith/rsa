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
    char *public_name, FILE **public_key, int name_len)
{
#define FILE_NAME_FOMAT "%s/%s%s.%s"
    char prefix[VENDOR_ID_MAX_LEN + KEY_ID_MAX_LEN]; 
    char *path = key_path_get();
    struct stat buf;
    int i;

    rsa_sprintf_nows(prefix, "%s_%s", VENDOR, key_id + 1);
    sprintf(private_name, FILE_NAME_FOMAT , path, "", prefix, "prv");
    sprintf(public_name, FILE_NAME_FOMAT , path, "", prefix, "pub");

    for (i = 0; !stat(private_name, &buf) || !stat(private_name, &buf); i++)
    {
	if (strlen(private_name) == name_len)
	{
	    output_error_message(RSA_ERR_KEYNAME);
	    return -1;
	}
	sprintf(&private_name[i],FILE_NAME_FOMAT , path, "_", prefix, "prv");
	sprintf(&public_name[i],FILE_NAME_FOMAT , path, "_", prefix, "pub");
    }

    if (!(*private_key = fopen(private_name, "w")))
    {
	output_error_message(RSA_ERR_FOPEN);
	return -1;
    }
    if (!(*public_key = fopen(public_name, "w")))
    {
	fclose(*private_key);
	output_error_message(RSA_ERR_FOPEN);
	return -1;
    }

    return 0;
}

static int rsa_sign(FILE *key, char key_type, u1024_t *exp, u1024_t *n)
{
    u1024_t signiture, vendor, id;

    *key_id = key_type;
    if (number_str2num(&vendor, VENDOR) || number_str2num(&id, key_id))
	return -1;

    rsa_encode(&signiture, &vendor, exp, n);
    if (rsa_write_u1024(key, &signiture))
	return -1;
    rsa_encode(&signiture, &id, exp, n);
    if (rsa_write_u1024(key, &signiture))
	return -1;

    return 0;
}

static int insert_key(FILE *key, u1024_t *exp, u1024_t *n)
{
    u1024_t montgomery_factor;

    number_montgomery_factor_get(&montgomery_factor);
    return rsa_write_u1024(key, n) || rsa_write_u1024(key, exp) || 
	rsa_write_u1024(key, &montgomery_factor);
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
	    output_error_message(RSA_ERR_KEYGEN);

	rsa_printf(1, 2, "finding first large prime: p1...");
	number_find_prime(&p1);
	rsa_printf(1, 2, "finding second large prime: p2...");
	number_find_prime(&p2);
	rsa_printf(1, 2, "calculating product: n=p1*p2...");
	number_mul(n, &p1, &p2);
    }
    while (!number_is_greater_or_equal(n, &inf));

    number_assign(p1_sub1, p1);
    number_assign(p2_sub1, p2);
    number_sub1(&p1_sub1);
    number_sub1(&p2_sub1);
    rsa_printf(1, 2, "calculating Euler phi function for n: phi=(p1-1)*(p2-1)...");
    number_mul(&phi, &p1_sub1, &p2_sub1);

    rsa_printf(1, 2, "generating puglic key: (e, n), where e is coprime with "
	"phi...");
    number_init_random_coprime(e, &phi);
    rsa_printf(1, 2, "calculating private key: (d, n), where d is the "
	"multiplicative inverse of e modulo phi...");
    number_modular_multiplicative_inverse(d, e, &phi);
}

int rsa_keygen(void)
{
    int ret, *level, is_first = 0;
    char private_name[MAX_FILE_NAME_LEN], public_name[MAX_FILE_NAME_LEN];
    FILE *private_key, *public_key;

    if (key_files_generate(private_name, &private_key, public_name, &public_key,
	MAX_FILE_NAME_LEN - 1))
    {
	return -1;
    }

    rsa_printf(0, 0, "generating key %s for vendor %s", key_id + 1, vendor_id);
    for (level = encryption_levels; *level; level++)
    {
	u1024_t n, e, d;

	rsa_printf(0, 1, "generating private and public keys: %d bits", *level);
	number_enclevl_set(*level);
	rsa_key_generator(&n, &e, &d);

	rsa_printf(1, 2, "writing %d bit keys...", *level);
	if (is_first)
	{
	    if (rsa_sign(private_key, DECRYPTER_CHAR, &e, &n) || 
		rsa_sign(public_key, ENCRYPTER_CHAR, &d, &n))
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

#ifndef RSA_MASTER
static opt_t options_decrypter[] = {
    {RSA_OPT_FILE, 'f', "file", required_argument, "input file to decrypt"},
    {RSA_OPT_KEYGEN, 'k', "keygen", required_argument, "generate RSA public "
	"and private keys"},
    { RSA_OPT_MAX }
};

/* either encryption or decryption task are to be performed */
static rsa_errno_t parse_args_finalize_decrypter(int *flags, int actions)
{
    if (!actions && !(*flags & OPT_FLAG(RSA_OPT_KEYGEN)))
	*flags |= OPT_FLAG(RSA_OPT_DECRYPT);

    /* test for non compatable options with encrypt/decrypt */
    if ((*flags & OPT_FLAG(RSA_OPT_DECRYPT)) 
	&& !(*flags & OPT_FLAG(RSA_OPT_FILE)))
    {
	return RSA_ERR_NOFILE;
    }

    return RSA_ERR_NONE;
}

static rsa_errno_t parse_args_decrypter(int opt, int *flags)
{
    switch (opt_short2code(options_decrypter, opt))
    {
    case RSA_OPT_FILE:
	OPT_ADD(flags, RSA_OPT_FILE, rsa_set_file_name(optarg));
	break;
    case RSA_OPT_KEYGEN:
	OPT_ADD(flags, RSA_OPT_KEYGEN);
	if (rsa_set_key_id(optarg))
	    return RSA_ERR_KEYNAME;
	rsa_set_vendor_id(VENDOR);
	break;
    default:
	return RSA_ERR_OPTARG;
    }

    return RSA_ERR_NONE;
}

int main(int argc, char *argv[])
{
    int err, action, flags = 0;
    rsa_handler_t decrypter_handler = {
	.options = options_decrypter,
	.ops_handler = parse_args_decrypter,
	.ops_handler_finalize = parse_args_finalize_decrypter,
    };

    if ((err = parse_args(argc, argv, &flags, &decrypter_handler)) != 
	RSA_ERR_NONE)
    {
	return rsa_error(argv[0], err);
    }

    action = rsa_action_get(flags, RSA_OPT_DECRYPT, RSA_OPT_KEYGEN, NULL);
    switch (action)
    {
    case OPT_FLAG(RSA_OPT_DECRYPT):
	RSA_TBD("handle RSA_OPT_DECRYPT");
	break;
    case OPT_FLAG(RSA_OPT_KEYGEN):
	return rsa_keygen();
    default:
	return rsa_action_handle_common(action, argv[0], options_decrypter);
    }

    return 0;
}
#endif

