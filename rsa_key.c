#include "rsa.h"
#include <stdlib.h>
#include <stdio.h>

static void rsa_key_generate(u1024_t *n, u1024_t *e, u1024_t *d)
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

void rsa_key(void)
{
    u1024_t n, e, d, montgomery_factor;

    RSA_PTASK_START("generating RSA keys");

    RSA_PSUB_TASK("generating big numbers (this will take a few minutes)");
    rsa_key_generate(&n, &e, &d);
    RSA_PDONE;

    RSA_PSUB_TASK("creating montgomery convertor");
    number_radix(&montgomery_factor, &n);
    RSA_PDONE;

    RSA_PSUB_TASK("creating private key");
    RSA_PDONE;

    RSA_PSUB_TASK("creating public key");
    RSA_PDONE;

    RSA_PDONE;
}

