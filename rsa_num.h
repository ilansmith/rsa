#ifndef _RSA_NUM_H_
#define _RSA_NUM_H_

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

#define RSA_NUMBER_ARRAY_SZ 17

typedef struct {
    u64 arr[RSA_NUMBER_ARRAY_SZ];
    int top;
} u1024_t;

#define MSB(X) ((X)(~((X)-1 >> 1)))

#define NUMBER_IS_NEGATIVE(X) ((MSB(u64) & \
    *((u64*)(X) + (block_sz_u1024 - 1))) ? 1 : 0)

#define RSA_PTASK_START(FMT, ...) printf(FMT ":\n", ##__VA_ARGS__); \
    fflush(stdout)
#define RSA_PSUB_TASK(FMT, ...) printf("  " FMT "... ", ##__VA_ARGS__); \
    fflush(stdout)
#define RSA_PDONE printf("done\n"); fflush(stdout)

#define number_is_odd(num) (*(u64*)&(num)->arr & (u64)1)

#define number_reset_buffer(num) { \
    do { \
	*((u64*)&(num)->arr + block_sz_u1024) = 0; \
	if ((num)->top == block_sz_u1024) \
	    while ((num)->top && !*((u64*)&(num)->arr + --(num)->top)); \
    } while (0); \
}

#define number_reset(num) { \
    do { \
	int __i; \
	for (__i = 0; __i <= block_sz_u1024; __i++) \
	    (num)->arr[__i] = 0; \
	(num)->top = 0; \
    } \
    while (0); \
}

#define number_shift_right_once(num) { \
    do { \
	u64 *__seg, *__top; \
	/* shifting is done up to, at most, the buffer u64 to accommodate for \
	 * number_montgomery_product() */ \
	__top = (u64*)&(num)->arr + (num)->top; \
	for (__seg = (u64*)&(num)->arr; __seg < __top; __seg++) \
	{ \
	    *__seg = *__seg >> 1; \
	    *__seg = (*(__seg+1) & (u64)1) ? *__seg | MSB(u64) : \
		*__seg & ~MSB(u64); \
	} \
	*__seg = *__seg >> 1; \
	if ((num)->top && !*__seg) \
	    (num)->top--; \
    } while (0); \
}

#define number_shift_left_once(num) { \
    do { \
	u64 *__seg, *__top; \
	int __is_top_can_shift = (num)->top < block_sz_u1024 ? 1 : 0; \
	/* shifting is done from, at most, the u64 buffer */ \
	__top = (u64*)&(num)->arr + (num)->top + __is_top_can_shift; \
	for (__seg = __top; __seg > (u64*)&(num)->arr; __seg--) \
	{ \
	    *__seg = *__seg << 1; \
	    *__seg = *(__seg-1) & MSB(u64) ? \
	    *__seg | (u64)1 : *__seg & ~(u64)1; \
	} \
	*__seg = *__seg << 1; \
	if (__is_top_can_shift && *(__top)) \
	    (num)->top++; \
    } while (0); \
}

#define number_sub1(num) { \
    do { \
	u1024_t __num_1; \
	number_assign(__num_1, NUM_1); \
	number_sub((num), (num), &__num_1);  \
    } while (0); \
}

/* return: num1 > num2  or ret_on_equal if num1 == num2 */
#define number_compare(num1, num2, ret_on_equal) ( { \
    int __ret; \
    do { \
	if ((num1)->top == (num2)->top) \
	{ \
	    u64 *__seg1 = (u64*)&(num1)->arr + (num1)->top; \
	    u64 *__seg2 = (u64*)&(num2)->arr + (num2)->top; \
	    for ( ; __seg1 > (u64*)&(num1)->arr && *__seg1==*__seg2; \
		__seg1--, __seg2--); \
	__ret = (*__seg1 == *__seg2) ? ret_on_equal : *__seg1 > *__seg2; \
	} \
	else \
	    __ret = (num1)->top > (num2)->top; \
    } while (0); \
    __ret; \
})

/* return: num1 > num2 */
#define number_is_greater(num1, num2) number_compare((num1), (num2), 0)

/* return: num1 >= num2 */
#define number_is_greater_or_equal(num1, num2) number_compare((num1), (num2), 1)

/* return: num1 == num2 */
#define number_is_equal(num1, num2) ((num1)->top == (num2)->top && \
    !memcmp((num1), (num2), encryption_level>>3))

#define number_mod(r, a, n) { \
    do { \
	u1024_t __q; \
	number_dev(&__q, (r), (a), (n)); \
    } \
    while (0); \
}

#define number_top_set(num) { \
    do { \
	u64 *__seg; \
	for (__seg = (u64*)&(num)->arr + block_sz_u1024, \
	    (num)->top = block_sz_u1024; \
	    __seg > (u64*)&(num)->arr && !*__seg; __seg--, (num)->top--); \
    } \
    while (0); \
}

#define number_xor(res, num1, num2) { \
    do { \
	u64 *__seg, *__seg1, *__seg2; \
	for (__seg = (u64*)&(res)->arr + block_sz_u1024, \
	    __seg1 = (u64*)&(num1)->arr + block_sz_u1024, \
	    __seg2 = (u64*)&(num2)->arr + block_sz_u1024; \
	    __seg >= (u64*)&(res)->arr; *__seg-- = *__seg1-- ^ *__seg2--); \
	number_top_set(res); \
    } \
    while (0); \
}

#define number_assign(to, from) { \
    do { \
	int __i; \
	for (__i = 0; __i <= block_sz_u1024; __i++) \
	    (to).arr[__i] = (from).arr[__i]; \
	(to).top = (from).top; \
    } \
    while (0); \
}

extern u1024_t NUM_0;
extern u1024_t NUM_1;
extern u1024_t NUM_2;
extern u1024_t NUM_5;
extern u1024_t NUM_10;
extern int bit_sz_u64;
extern int encryption_level;
extern int block_sz_u1024;
extern int encryption_levels[];

typedef struct {
    u64 prime_initializer;
    u1024_t prime;
    u1024_t exp;
    u1024_t power_of_prime;
} small_prime_entry_t;

int number_enclevl_set(int level);
int number_data2num(u1024_t *num, void *data, int len);
int number_size(int level);
void number_add(u1024_t *res, u1024_t *num1, u1024_t *num2);
void number_sub(u1024_t *res, u1024_t *num1, u1024_t *num2);
void number_mul(u1024_t *res, u1024_t *num1, u1024_t *num2);
void number_dev(u1024_t *num_q, u1024_t *num_r, u1024_t *num_dividend, 
    u1024_t *num_divisor);
int number_seed_set_random(u1024_t *seed);
int number_seed_set_fixed(u1024_t *seed);
int number_init_random(u1024_t *num, int blocks);
void number_init_random_coprime(u1024_t *num, u1024_t *coprime);
void number_find_prime(u1024_t *num);
void number_montgomery_factor_set(u1024_t *num_n, u1024_t *num_factor);
void number_montgomery_factor_get(u1024_t *num);
int number_modular_multiplicative_inverse(u1024_t *inv, u1024_t *num,
    u1024_t *mod);
int number_modular_exponentiation_montgomery(u1024_t *res, u1024_t *a,
    u1024_t *b, u1024_t *n);
int number_str2num(u1024_t *num, char *str);
void number_small_dec2num(u1024_t *num_n, u64 dec);

#ifdef TESTS
extern int init_reset;
extern u1024_t num_montgomery_n;
extern prng_seed_t number_random_seed;

int number_init_str(u1024_t *num, char *init_str);
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
