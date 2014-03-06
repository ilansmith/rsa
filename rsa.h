#ifndef _NUMBER_H_
#define _NUMBER_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

typedef enum {
    FUNC_NUMBER_INIT_RANDOM,
    FUNC_NUMBER_FIND_MOST_SIGNIFICANT_SET_BIT,
    FUNC_NUMBER_ADD,
    FUNC_NUMBER_SMALL_DEC2NUM,
    FUNC_NUMBER_2COMPLEMENT,
    FUNC_NUMBER_SUB,
    FUNC_NUMBER_MUL,
    FUNC_NUMBER_MODULAR_MULTIPLICATION_NAIVE,
    FUNC_NUMBER_MODULAR_MULTIPLICATION_MONTGOMERY,
    FUNC_NUMBER_ABSOLUTE_VALUE,
    FUNC_NUMBER_DEV,
    FUNC_NUMBER_INIT_RANDOM_STRICT_RANGE,
    FUNC_NUMBER_EXPONENTIATION,
    FUNC_NUMBER_MODULAR_EXPONENTIATION_NAIVE,
    FUNC_NUMBER_MONTGOMERY_FACTOR_SET,
    FUNC_NUMBER_MONTGOMERY_PRODUCT,
    FUNC_NUMBER_MODULAR_EXPONENTIATION_MONTGOMERY,
    FUNC_NUMBER_IS_ODD,
    FUNC_NUMBER_WITNESS_INIT,
    FUNC_NUMBER_WITNESS,
    FUNC_NUMBER_MILLER_RABIN,
    FUNC_NUMBER_IS_PRIME,
    FUNC_NUMBER_IS_PRIME1,
    FUNC_NUMBER_IS_PRIME2,
    FUNC_NUMBER_SMALL_PRIME_INIT,
    FUNC_NUMBER_GENERATE_COPRIME,
    FUNC_NUMBER_EXTENDED_EUCLID_GCD,
    FUNC_NUMBER_EUCLID_GCD,
    FUNC_NUMBER_INIT_RANDOM_COPRIME,
    FUNC_NUMBER_MODULAR_MULTIPLICATIVE_INVERSE,
    FUNC_NUMBER_FIND_PRIME,
    FUNC_NUMBER_SHIFT_LEFT,
    FUNC_NUMBER_SHIFT_RIGHT,
    FUNC_COUNT
} func_cnt_t;

#ifdef TESTS
#if defined(UCHAR)
#define U64_TYPE unsigned char
#elif defined(USHORT)
#define U64_TYPE unsigned short
#elif defined(ULONG)
#define U64_TYPE unsigned long
#elif defined(ULLONG)
#define U64_TYPE unsigned long long
#if !defined(ULLONG)
#define ULLONG
#endif
#endif

typedef U64_TYPE u64;
#define STATIC
#define INLINE

#ifdef TIME_FUNCTIONS
inline void timer_start(func_cnt_t func);
inline void timer_stop(func_cnt_t func);
#define TIMER_START(FUNC) timer_start(FUNC)
#define TIMER_STOP(FUNC) timer_stop(FUNC)
#else /* NOT TIME_FUNCTIONS */
#define TIMER_START(FUNC)
#define TIMER_STOP(FUNC)
#endif /* TIME_FUNCTIONS */
#else /* NOT TESTS */
#define TIMER_START(FUNC)
#define TIMER_STOP(FUNC)
typedef unsigned long long u64;
#define STATIC static
#define INLINE inline
#endif /*  TESTS */

#ifdef MERSENNE_TWISTER
typedef unsigned long long prng_seed_t;
#else
typedef unsigned int prng_seed_t;
#endif

#define ENC_LEVEL(X) (EL==(X))

#define ENC_LEVEL_1024 (ENC_LEVEL(1024))
#define ENC_LEVEL_512 (ENC_LEVEL(512) || ENC_LEVEL_1024)
#define ENC_LEVEL_256 (ENC_LEVEL(256) || ENC_LEVEL_512)
#define ENC_LEVEL_128 (ENC_LEVEL(128) || ENC_LEVEL_256)
#define ENC_LEVEL_64 (ENC_LEVEL(64) || ENC_LEVEL_128)

typedef struct {
#if ENC_LEVEL_64
    u64 seg_00; /* bits:   0 -   63 */
#endif
#if ENC_LEVEL_128
    u64 seg_01; /* bits:  64 -  127 */
#endif
#if ENC_LEVEL_256
    u64 seg_02; /* bits: 128 -  191 */
    u64 seg_03; /* bits: 192 -  255 */
#endif
#if ENC_LEVEL_512
    u64 seg_04; /* bits: 256 -  319 */
    u64 seg_05; /* bits: 320 -  383 */
    u64 seg_06; /* bits: 384 -  447 */
    u64 seg_07; /* bits: 448 -  511 */
#endif
#if ENC_LEVEL_1024
    u64 seg_08; /* bits: 512 -  575 */
    u64 seg_09; /* bits: 576 -  639 */
    u64 seg_10; /* bits: 640 -  703 */
    u64 seg_11; /* bits: 704 -  767 */
    u64 seg_12; /* bits: 768 -  831 */
    u64 seg_13; /* bits: 832 -  895 */
    u64 seg_14; /* bits: 896 -  959 */
    u64 seg_15; /* bits: 960 - 1023 */
#endif
    u64 buffer; /* buffer */
} u1024_arr_t;

typedef struct {
    u1024_arr_t arr;
    int top;
} u1024_t;

#define RSA_MASTER (!defined(RSA_ENC) && !defined(RSA_DEC))
#define RSA_ENCRYPTER (!defined(RSA_DEC) && !RSA_MASTER)
#define RSA_DECRYPTER (!defined(RSA_ENC) && !RSA_MASTER)

#define BIT_SZ_U64 (sizeof(u64)<<3)
#define BLOCK_SZ_U1024 (EL>>6)
#define BIT_SZ_U1024 (BIT_SZ_U64 * BLOCK_SZ_U1024)

#define ARRAY_SZ(X) (sizeof(X) / sizeof((X)[0]))
#define MSB_PT(X) ((X)(~((X)-1 >> 1)))

#define NUMBER_IS_NEGATIVE(X) ((MSB_PT(u64) & \
    *((u64*)(X) + (BLOCK_SZ_U1024 - 1))) ? 1 : 0)

#define RSA_PTASK_START(FMT, ...) printf(FMT ":\n", ##__VA_ARGS__); \
    fflush(stdout)
#define RSA_PSUB_TASK(FMT, ...) printf("  " FMT "... ", ##__VA_ARGS__); \
    fflush(stdout)
#define RSA_PDONE printf("done\n"); fflush(stdout)

extern u1024_t NUM_0;
extern u1024_t NUM_1;
extern u1024_t NUM_2;
extern u1024_t NUM_5;
extern u1024_t NUM_10;
extern int bit_sz_u64;
extern int encryption_level;
extern int block_sz_u1024;
extern int sizeof_u1024;

typedef struct {
    u64 prime_initializer;
    u1024_t prime;
    u1024_t exp;
    u1024_t power_of_prime;
} small_prime_entry_t;

void number_mul(u1024_t *res, u1024_t *num1, u1024_t *num2);
prng_seed_t number_seed_set(prng_seed_t seed);
int number_init_random(u1024_t *num, int blocks);
void number_init_random_coprime(u1024_t *num, u1024_t *coprime);
void number_find_prime(u1024_t *num);
void number_montgomery_factor_set(u1024_t *num_n, u1024_t *num_factor);
int number_modular_multiplicative_inverse(u1024_t *inv, u1024_t *num,
    u1024_t *mod);
int number_modular_exponentiation_montgomery(u1024_t *res, u1024_t *a,
    u1024_t *b, u1024_t *n);

void rsa_key_generate(void);
int rsa_function(char *file_name, int is_decrypt);

int rsa_io_init(void);
#if RSA_MASTER || RSA_DECRYPTER
FILE *rsa_file_create_private(void);
FILE *rsa_file_create_public(void);
FILE *rsa_open_decryption_file(char *path, char *file_name);
#endif
#if RSA_MASTER || RSA_ENCRYPTER
FILE *rsa_open_encryption_file(char *path, char *file_name);
#endif
FILE *rsa_file_open(char *path, char *preffix, char *suffix, int is_slink,
    int is_new);
int rsa_file_close(FILE *fp);
int rsa_file_write_u1024_hi(FILE *fptr, u1024_t *num);
int rsa_file_read_u1024_hi(FILE *fptr, u1024_t *num);
int rsa_file_write_u1024_low(FILE *fptr, u1024_t *num);
int rsa_file_read_u1024_low(FILE *fptr, u1024_t *num);
int rsa_file_write_u1024(FILE *fptr, u1024_t *num);
int rsa_file_read_u1024(FILE *fptr, u1024_t *num);
int str2u1024_t(u1024_t *num, char *str);
int u1024_t2str(u1024_t *num, char *str);
int rsa_key_get_params(char *preffix, u1024_t *n, u1024_t *exp,
    u1024_t *montgomery_factor, int is_decrypt);
int number_str2num(u1024_t *num, char *str);
#if RSA_DECRYPTER || RSA_ENCRYPTER
int, rsa_key_get_vendor(u1024_t *vendor, int is_decrypt);
#endif

#define number_reset_buffer(num) { \
    do { \
	*((u64*)&(num)->arr + block_sz_u1024) = 0; \
	if ((num)->top == block_sz_u1024) \
	    while ((num)->top && !*((u64*)&(num)->arr + --(num)->top)); \
    } while (0); \
}

#define number_reset(num) memset((num), 0, sizeof_u1024)

#define number_shift_right_once(num) { \
    do { \
	u64 *seg, *top; \
	/* shifting is done up to, at most, the buffer u64 to accomodate for \
	 * number_montgomery_product() */ \
	top = (u64*)&(num)->arr + (num)->top; \
	for (seg = (u64*)&(num)->arr; seg < top; seg++) \
	{ \
	    *seg = *seg >> 1; \
	    *seg = (*(seg+1) & (u64)1) ? *seg | MSB_PT(u64) : \
		*seg & ~MSB_PT(u64); \
	} \
	*seg = *seg >> 1; \
	if ((num)->top && !*seg) \
	    (num)->top--; \
    } while (0); \
}

#define number_shift_left_once(num) { \
    do { \
	u64 *seg, *top; \
	int is_top_can_shift = (num)->top < block_sz_u1024 ? 1 : 0; \
	/* shifting is done from, at most, the buffer u64 */ \
	top = (u64*)&(num)->arr + (num)->top + is_top_can_shift; \
	for (seg = top; seg > (u64*)&(num)->arr; seg--) \
	{ \
	    *seg = *seg << 1; \
	    *seg = *(seg-1) & MSB_PT(u64) ? *seg | (u64)1 : *seg & ~(u64)1; \
	} \
	*seg = *seg << 1; \
	if (is_top_can_shift && *(top)) \
	    (num)->top++; \
    } while (0); \
}

#define number_sub1(num) { \
    do { \
	u1024_t num_1; \
	num_1 = NUM_1; \
	number_sub((num), (num), &num_1);  \
    } while (0); \
}

/* return: num1 > num2  or ret_on_equal if num1 == num2 */
#define number_compare(num1, num2, ret_on_equal) ({ \
    int ret; \
    do { \
	if ((num1)->top == (num2)->top) \
	{ \
	    u64 *seg1 = (u64*)&(num1)->arr + (num1)->top; \
	    u64 *seg2 = (u64*)&(num2)->arr + (num2)->top; \
	    for (; seg1 > (u64*)&(num1)->arr && *seg1==*seg2; seg1--, seg2--); \
	    ret = (*seg1 == *seg2) ? ret_on_equal : *seg1 > *seg2; \
	} \
	else \
	    ret = (num1)->top > (num2)->top; \
    } while (0); \
    ret; \
})

/* return: num1 > num2 */
#define number_is_greater(num1, num2) number_compare((num1), (num2), 0)

/* return: num1 >= num2 */
#define number_is_greater_or_equal(num1, num2) number_compare((num1), (num2), 1)

/* return: num1 == num2 */
#define number_is_equal(num1, num2) !memcmp((num1), (num2), encryption_level>>3)

#define number_mod(r, a, n) { \
    do { \
	u1024_t q; \
	number_dev(&q, (r), (a), (n)); \
    } \
    while (0); \
}

#define number_top_set(num) { \
    do { \
	u64 *seg; \
	for (seg = (u64*)&(num)->arr + block_sz_u1024, \
	    (num)->top = block_sz_u1024; \
	    seg > (u64*)&(num)->arr && !*seg; seg--, (num)->top--); \
    } \
    while (0); \
}

#define number_xor(res, num1, num2) { \
    do { \
	u64 *seg, *seg1, *seg2; \
	for (seg = (u64*)&(res)->arr + block_sz_u1024, \
	    seg1 = (u64*)&(num1)->arr + block_sz_u1024, \
	    seg2 = (u64*)&(num2)->arr + block_sz_u1024; \
	    seg >= (u64*)&(res)->arr; *seg-- = *seg1-- ^ *seg2--); \
	number_top_set(res); \
    } \
    while (0); \
}

#ifdef TESTS
extern int init_reset;
extern u1024_t num_montgomery_n, num_montgomery_factor;
extern prng_seed_t number_random_seed;

int number_init_str(u1024_t *num, char *init_str);
void number_add(u1024_t *res, u1024_t *num1, u1024_t *num2);
void number_sub(u1024_t *res, u1024_t *num1, u1024_t *num2);
void number_shift_left(u1024_t *num, int n);
void number_shift_right(u1024_t *num, int n);
int number_dec2bin(u1024_t *num_bin, char *str_dec);
void number_dev(u1024_t *num_q, u1024_t *num_r, u1024_t *num_dividend,
    u1024_t *num_divisor);
int number_find_most_significant_set_bit(u1024_t *num, u64 **seg,
    u64 *mask);
int number_modular_exponentiation_naive(u1024_t *res, u1024_t *a,
    u1024_t *b, u1024_t *n);
int number_witness(u1024_t *num_a, u1024_t *num_n);
void number_small_dec2num(u1024_t *num_n, u64 dec);
int number_is_prime(u1024_t *num_s);
void number_find_prime1(u1024_t *num);
int number_modular_multiplication_naive(u1024_t *num_res,
    u1024_t *num_a, u1024_t *num_b, u1024_t *num_n);
int number_modular_multiplication_montgomery(u1024_t *num_res,
    u1024_t *num_a, u1024_t *num_b, u1024_t *num_n);
void number_generate_coprime(u1024_t *num_coprime,
    u1024_t *num_increment);
void number_exponentiation(u1024_t *res, u1024_t *num_base,
    u1024_t *num_exp);
void number_extended_euclid_gcd(u1024_t *gcd, u1024_t *x, u1024_t *a,
    u1024_t *y, u1024_t *b);
void number_absolute_value(u1024_t *abs, u1024_t *num);
#endif

#endif
