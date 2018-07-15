#include "rsa.h"
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
    char *buf = calloc(1, sizeof(u1024_t));

    number_reset(v);
    snprintf(buf, sizeof(u1024_t) - 1, SIG);
    memcpy(v, buf, sizeof(u1024_t));
    number_modular_exponentiation_montgomery(v, v, exp, n);
    free(buf);
}
#endif

static int rsa_write_keys(u1024_t *n, u1024_t *exp, u1024_t *mf, int is_prv, 
    u1024_t *vendor)
{
    FILE *file = NULL;

    if (!(file = is_prv ? rsa_file_create_private() : rsa_file_create_public()))
    {
	return -1;
    }

    fwrite(n, sizeof(u1024_t), 1, file);
    fwrite(exp, sizeof(u1024_t), 1, file);
    fwrite(mf, sizeof(u1024_t), 1, file);

#if RSA_DECRYPTER
    fwrite(vendor, sizeof(u1024_t), 1, file);
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
