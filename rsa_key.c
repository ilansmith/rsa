#include "rsa_num.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#if RSA_MASTER || RSA_DECRYPTER
static void rsa_exp_generate(u1024_t *n, u1024_t *e, u1024_t *d)
{
    u1024_t p1, p2, phi;

    number_find_prime(&p1);
    number_find_prime(&p2);
    number_mul(n, &p1, &p2);

    number_sub1(&p1);
    number_sub1(&p2);
    number_mul(&phi, &p1, &p2);

    number_init_random_coprime(e, &phi);
    number_modular_multiplicative_inverse(d, e, &phi);
}

#if RSA_DECRYPTER
static void rsa_encode_vendor(u1024_t *v, u1024_t *n, u1024_t *exp)
{
    char *sig = calloc(1, BYTES_SZ(u1024_t));

    number_reset(v);
    snprintf(sig, BYTES_SZ(u1024_t) - 1, SIG);
    memcpy(v, sig, BYTES_SZ(u1024_t));
    number_modular_exponentiation_montgomery(v, v, exp, n);
    free(sig);
}
#endif

static int rsa_write_keys(u1024_t *n, u1024_t *exp, u1024_t *montgomery_factor,
    int is_prv, u1024_t *vendor)
{
    FILE *file = NULL;

    if (!(file = is_prv ? rsa_file_create_private() : rsa_file_create_public())
	|| rsa_file_write_u1024(file, n) || rsa_file_write_u1024(file, exp) 
	|| rsa_file_write_u1024(file, montgomery_factor))
    {
	return -1;
    }

#if RSA_DECRYPTER
    rsa_file_write_u1024(file, vendor);
#endif

    rsa_file_close(file);
    return 0;
}

void rsa_key_generate(void)
{
    u1024_t n, e, d, montgomery_factor, vendor, *vptr = NULL;

    number_reset(&vendor);
    RSA_PTASK_START("generating RSA keys");

    RSA_PSUB_TASK("generating big numbers (this will take a few minutes)");
    rsa_exp_generate(&n, &e, &d);
    RSA_PDONE;

    RSA_PSUB_TASK("creating montgomery convertor");
    number_radix(&montgomery_factor, &n);
    RSA_PDONE;

    RSA_PSUB_TASK("creating private key");
#if RSA_DECRYPTER
    rsa_encode_vendor(&vendor, &n, &e);
    vptr = &vendor;
#endif
    rsa_write_keys(&n, &d, &montgomery_factor, 1, vptr);
    RSA_PDONE;

    RSA_PSUB_TASK("creating public key");
#if RSA_DECRYPTER
    rsa_encode_vendor(&vendor, &n, &d);
    vptr = &vendor;
#endif

    rsa_write_keys(&n, &e, &montgomery_factor, 0, vptr);
    RSA_PDONE;

    RSA_PDONE;
    /* ilan: TBD - error handling */
}
#endif

#if RSA_DECRYPTER || RSA_ENCRYPTER
int rsa_validate_key(u1024_t *n, u1024_t *exp, int is_decrypt)
{
    u1024_t vendor;
    char *sig = calloc(1, BYTES_SZ(u1024_t));
    int ret;

    if (rsa_key_get_vendor(&vendor, is_decrypt))
	return -1;

    number_modular_exponentiation_montgomery(&vendor, &vendor, exp, n);
    snprintf(sig, BYTES_SZ(u1024_t) - 1, SIG);
    memcpy(sig, SIG, BYTES_SZ(u1024_t) - 1);

    ret = memcmp(sig, &vendor, BYTES_SZ(u1024_t));
    free(sig);
    return ret;
}
#endif

int rsa_function(char *file_name, int is_decrypt)
{
    FILE *infile, *outfile;
    u1024_t n, exp, montgomery_factor;
    char *preffix = "master";

    if (!file_name)
    {
	infile = stdin;
	outfile = stdout;
    }
#if RSA_MASTER || RSA_DECRYPTER
    else if (is_decrypt && !((infile = fopen(file_name, "r+")) && (outfile = 
	rsa_open_decryption_file("./", file_name))))
    {
	return -1;
    }
#endif
#if RSA_MASTER || RSA_ENCRYPTER
    else if (!is_decrypt && !((infile = fopen(file_name, "r+")) && (outfile = 
	rsa_open_encryption_file("./", file_name))))
    {
	return -1;
    }
#endif

#if RSA_DECRYPTER || RSA_ENCRYPTER
    preffix = SIG;
#endif

    if (rsa_key_get_params(preffix, &n, &exp, &montgomery_factor, is_decrypt))
	return -1;

    number_montgomery_factor_set(&n, &montgomery_factor);

#if RSA_DECRYPTER || RSA_ENCRYPTER
    if (rsa_validate_key(&n, &exp, is_decrypt))
	return -1;
#endif

    printf("rsa %s\n", is_decrypt ? "decrypt" : "encrypt");

    return 0;
}
