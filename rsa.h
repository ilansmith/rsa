#ifndef _NUMBER_H_
#define _NUMBER_H_

#ifdef DEBUG
#if defined(UCHAR)
#define DEBUG_TYPE unsigned char
#elif defined(USHORT)
#define DEBUG_TYPE unsigned short
#elif defined(ULONG)
#define DEBUG_TYPE unsigned long
#elif defined(ULLONG)
#define DEBUG_TYPE unsigned long long
#endif

typedef DEBUG_TYPE u64;
#define STATIC
#define ENABLED 1
#define DISSABLED 0

#else
typedef unsigned long long u64;
#define STATIC static
#endif

#define RSA_PTASK_START(FMT, ...) printf(FMT ":\n", ##__VA_ARGS__); \
    fflush(stdout)
#define RSA_PSUB_TASK(FMT, ...) printf("  " FMT "... ", ##__VA_ARGS__); \
    fflush(stdout)
#define RSA_PDONE printf("done\n"); fflush(stdout)

typedef struct u1024_t {
    u64 seg_00; /* bits:   0 -   63 */
    u64 seg_01; /* bits:  64 -  127 */
    u64 seg_02; /* bits: 128 -  191 */
    u64 seg_03; /* bits: 192 -  255 */
    u64 seg_04; /* bits: 256 -  319 */
    u64 seg_05; /* bits: 320 -  383 */
    u64 seg_06; /* bits: 384 -  447 */
    u64 seg_07; /* bits: 448 -  511 */
    u64 seg_08; /* bits: 512 -  575 */
    u64 seg_09; /* bits: 576 -  639 */
    u64 seg_10; /* bits: 640 -  703 */
    u64 seg_11; /* bits: 704 -  767 */
    u64 seg_12; /* bits: 768 -  831 */
    u64 seg_13; /* bits: 832 -  895 */
    u64 seg_14; /* bits: 896 -  959 */
    u64 seg_15; /* bits: 960 - 1023 */
} u1024_t;

typedef struct {
    u64 prime_initializer;
    u64 exp_initializer;
    u1024_t prime;
    u1024_t exp;
    u1024_t power_of_prime;
} small_prime_entry_t;

void number_sub1(u1024_t *num);
void number_mul(u1024_t *res, u1024_t *num1, u1024_t *num2);
int number_init_random(u1024_t *num);
void number_init_random_coprime(u1024_t *num, u1024_t *coprime);
void number_find_prime(u1024_t *num);
int number_radix(u1024_t *num_radix, u1024_t *num_n);
void number_modular_multiplicative_inverse(u1024_t *inv, u1024_t *num, 
    u1024_t *mod);

void rsa_key(void);

#ifdef DEBUG
void number_reset(u1024_t *num);
int number_init_str(u1024_t *num, char *init_str);
void number_add(u1024_t *res, u1024_t *num1, u1024_t *num2);
void number_sub(u1024_t *res, u1024_t *num1, u1024_t *num2);
void number_shift_left(u1024_t *num, int n);
void number_shift_right(u1024_t *num, int n);
int number_is_greater(u1024_t *num1, u1024_t *num2);
int number_dec2bin(u1024_t *num_bin, char *str_dec);
void number_dev(u1024_t *num_q, u1024_t *num_r, u1024_t *num_dividend, 
    u1024_t *num_divisor);
void number_mod(u1024_t *r, u1024_t *a, u1024_t *n);
int number_find_most_significant_set_bit(u1024_t *num, u64 **seg, u64 *mask);
void number_modular_exponentiation_naive(u1024_t *res, u1024_t *a, 
    u1024_t *b, u1024_t *n);
void number_modular_exponentiation_montgomery(u1024_t *res, u1024_t *a, 
    u1024_t *b, u1024_t *n);
int number_witness(u1024_t *num_a, u1024_t *num_n);
void number_small_dec2num(u1024_t *num_n, u64 dec);
int number_is_prime(u1024_t *num_s);
void number_find_prime1(u1024_t *num);
void number_modular_multiplication_naive(u1024_t *num_res, 
    u1024_t *num_a, u1024_t *num_b, u1024_t *num_n);
void number_modular_multiplication_montgomery(u1024_t *num_res, 
    u1024_t *num_a, u1024_t *num_b, u1024_t *num_n);
int number_is_equal(u1024_t *a, u1024_t *b);
void number_generate_coprime(u1024_t *num_coprime, 
    u1024_t *num_increment);
void number_exponentiation(u1024_t *res, u1024_t *num_base, 
    u1024_t *num_exp);
void number_extended_euclid_gcd(u1024_t *gcd, u1024_t *x, u1024_t *a, 
    u1024_t *y, u1024_t *b);
void number_absolute_value(u1024_t *abs, u1024_t *num);

#ifdef TIME_FUNCTIONS
void functions_stat_reset(void);
void functions_stat(void);
#endif

#endif

#endif
