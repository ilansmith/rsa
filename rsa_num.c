#include "rsa_util.h"
#include "rsa_num.h"
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <math.h>

#ifdef MERSENNE_TWISTER
#include "mt19937_64.h"
#endif

#define IS_DIGIT(n) ((n)>='0' && (n)<='9')
#define CHAR_2_INT(c) ((int)((c) - '0'))
#define COPRIME_PRIME(X) ((X).prime)
#define COPRIME_DIVISOR(X) ((X).divisor)
#define ASCII_LEN_2_BIN_LEN(STR) (strlen(STR)<<3)
#define NUMBER_GENERATE_COPRIME_ARRAY_SZ 13

#define number_gcd_is_1(u, v) \
( \
    /* algorithm \
     * --------- \
     * g = 0 \
     * while u is even and v is even \
     *   u = u/2 (right shift) \
     *   v = v/2 \
     *   g = g + 1 \
     * now u or v (or both) are odd \
     * while u > 0 \
     *   if u is even, u = u/2 \
     *   else if v is even, v = v/2 \
     *   else if u >= v \
     *     u = (u-v)/2 \
     *   else \
     *     v = (v-u)/2 \
     * return v/2^k \
     * Since radix is of the form 2^k, and n is odd, their GCD is 1 */ \
    1 \
)

u1024_t NUM_0 = {.arr[0]=0};
u1024_t NUM_1 = {.arr[0]=1};
u1024_t NUM_2 = {.arr[0]=2};
u1024_t NUM_5 = {.arr[0]=5};
u1024_t NUM_10 = {.arr[0]=10};
int bit_sz_u64 = sizeof(u64)<<3;
int encryption_level;
int block_sz_u1024;

typedef int (* func_modular_multiplication_t) (u1024_t *num_res, 
    u1024_t *num_a, u1024_t *num_b, u1024_t *num_n);
typedef struct code2list_t {
    int code;
    u64 list[NUMBER_GENERATE_COPRIME_ARRAY_SZ];
    int disabled;
} code2list_t;

STATIC u1024_t num_montgomery_n, num_montgomery_factor, num_res_nresidue;
STATIC prng_seed_t number_random_seed;

static u64 *code2list(code2list_t *list, int code)
{
    for (; list->code != -1 && list->code != code; list++);

    return list->code == -1 ? NULL : list->list;
}

STATIC void INLINE number_add(u1024_t *res, u1024_t *num1, u1024_t *num2)
{
    u1024_t num_big, num_small, num_res;
    u64 *top, *top_max, *seg = NULL, *seg1 = NULL, *seg2 = NULL, carry = 0;

    TIMER_START(FUNC_NUMBER_ADD);
    /* set num_big => num_small */
    if (number_is_greater_or_equal(num1, num2))
    {
	number_assign(num_big, *num1);
	number_assign(num_small, *num2);
    }
    else
    {
	number_assign(num_big, *num2);
	number_assign(num_small, *num1);
    }

    number_assign(num_res, num_big);
    top = (u64*)&num_res.arr + num_small.top + 1;
    for (seg = (u64*)&num_res.arr, seg1 = (u64*)&num_big.arr, 
	seg2 = (u64*)&num_small.arr; seg < top; seg++, seg1++, seg2++)
    {
	*seg = *seg1 + *seg2 + carry;
	if ((*seg1 & MSB(u64)) && (*seg2 & MSB(u64)))
	    carry = 1;
	else if (!(*seg1 & MSB(u64)) && !(*seg2 & MSB(u64)))
	    carry = 0;
	else
	    carry = (*seg & MSB(u64)) ? 0 : 1;
    }

    top_max = (u64*)&num_res.arr + block_sz_u1024;
    for ( ; carry && seg <= top_max; seg++)
    {
	carry = *seg == (u64)-1;
	(*seg)++;
	if (seg > (u64*)&num_res.arr + num_res.top)
	    num_res.top++;
    }
    if (num_res.top > block_sz_u1024)
	num_res.top--;
    if (carry)
	number_reset_buffer(&num_res);
    number_assign(*res, num_res);
    TIMER_STOP(FUNC_NUMBER_ADD);
}

prng_seed_t number_seed_set(prng_seed_t seed)
{
    if (!(number_random_seed = seed))
    {
	struct timeval tv;

	tv.tv_sec = tv.tv_usec = 0;
	if (gettimeofday(&tv, NULL))
	    return 0;
	number_random_seed = (prng_seed_t)tv.tv_sec * (prng_seed_t)tv.tv_usec;
    }

#ifdef MERSENNE_TWISTER
    init_genrand64(number_random_seed);
#else
    srandom(number_random_seed);
#endif
    return number_random_seed;
}

/* initiates the first low (u64) blocks of num with random valules */
int INLINE number_init_random(u1024_t *num, int blocks)
{
    int i, ret;

    TIMER_START(FUNC_NUMBER_INIT_RANDOM);
    if (blocks < 1 || blocks > block_sz_u1024 || (!number_random_seed && 
	!number_seed_set(0)))
    {
	ret = -1;
	goto Exit;
    }

    number_reset(num);

    /* initiate the low u64 blocks of num */
    for (i = 0; i < blocks; i++)
    {
#ifdef MERSENNE_TWISTER
	*((u64*)&num->arr + i) = (u64)genrand64_int64();
#else
	*((u64*)&num->arr + i) = (u64)random();
#ifdef ULLONG
	/* random() returns a long int so another call is required to fill
	 * the block's higher bits */
	*((u64*)&num->arr + i) |= (u64)random()<<(bit_sz_u64/2);
#endif
#endif
    }
    number_top_set(num);
    ret = 0;

Exit:
    TIMER_STOP(FUNC_NUMBER_INIT_RANDOM);
    return ret;
}

STATIC int INLINE number_find_most_significant_set_bit(u1024_t *num, 
    u64 **major, u64 *minor)
{
    int minor_offset;

    TIMER_START(FUNC_NUMBER_FIND_MOST_SIGNIFICANT_SET_BIT);
    *major = (u64*)&num->arr + num->top;
    *minor = MSB(u64);
    minor_offset = bit_sz_u64;

    while (*minor)
    {
	if ((**major & *minor))
	    break;
	*minor = *minor >> 1;
	minor_offset--;
    }
    TIMER_STOP(FUNC_NUMBER_FIND_MOST_SIGNIFICANT_SET_BIT);
    return minor_offset;
}

STATIC void INLINE number_small_dec2num(u1024_t *num_n, u64 dec)
{
    u64 zero = (u64)0;
    u64 *ptr = &zero;

    TIMER_START(FUNC_NUMBER_SMALL_DEC2NUM);
    number_reset(num_n);
    *(u64 *)&num_n->arr = (u64)(*ptr | dec);
    TIMER_STOP(FUNC_NUMBER_SMALL_DEC2NUM);
}

STATIC void INLINE number_2complement(u1024_t *res, u1024_t *num)
{
    u1024_t tmp;
    u64 *seg = NULL, *seg_max = (u64 *)&tmp.arr + block_sz_u1024;
    int cur_block;

    TIMER_START(FUNC_NUMBER_2COMPLEMENT);
    number_assign(tmp, *num);
    for (seg = (u64 *)&tmp.arr, cur_block = 0; seg <= seg_max; seg++, 
	cur_block++)
    {
	if ((*seg = ~*seg)) /* one's complement */
	    tmp.top = cur_block;
    }

    number_add(res, &tmp, &NUM_1); /* two's complement */
    TIMER_STOP(FUNC_NUMBER_2COMPLEMENT);
}

STATIC void INLINE number_sub(u1024_t *res, u1024_t *num1, u1024_t *num2)
{
    u1024_t num2_2complement;

    TIMER_START(FUNC_NUMBER_SUB);
    number_2complement(&num2_2complement, num2);
    number_add(res, num1, &num2_2complement);
    number_reset_buffer(res);
    TIMER_STOP(FUNC_NUMBER_SUB);
}

void INLINE number_mul(u1024_t *res, u1024_t *num1, u1024_t *num2)
{
    int i, top;
    u1024_t tmp_res, multiplicand = *num1, multiplier = *num2;

    TIMER_START(FUNC_NUMBER_MUL);
    number_reset(&tmp_res);
    top = num1->top + num2->top + 1;
    for (i = 0; i < top; i++)
    {
	u64 mask = 1;
	int j;

	for (j = 0; j < bit_sz_u64; j++)
	{
	    if ((*((u64*)&multiplier.arr + i)) & mask)
		number_add(&tmp_res, &tmp_res, &multiplicand);
	    number_shift_left_once(&multiplicand);
	    number_reset_buffer(&multiplicand);
	    mask = mask << 1;
	}
    }
    number_assign(*res, tmp_res);
    TIMER_STOP(FUNC_NUMBER_MUL);
}

STATIC void INLINE number_absolute_value(u1024_t *abs, u1024_t *num)
{
    TIMER_START(FUNC_NUMBER_ABSOLUTE_VALUE);
    number_assign(*abs, *num);
    if (NUMBER_IS_NEGATIVE(num))
    {
	u64 *seg;

	number_sub(abs, abs, &NUM_1);
	for (seg = (u64*)&abs->arr + block_sz_u1024 - 1; seg >= (u64*)&abs->arr;
	    seg--)
	{
	    *seg = ~*seg;
	}
	number_top_set(abs);
    }
    TIMER_STOP(FUNC_NUMBER_ABSOLUTE_VALUE);
}

STATIC void INLINE number_dev(u1024_t *num_q, u1024_t *num_r, 
    u1024_t *num_dividend, u1024_t *num_divisor)
{
    u1024_t dividend, divisor, quotient, remainder;
    u64 *seg_dividend = (u64 *)&dividend.arr + block_sz_u1024 - 1;
    u64 *remainder_ptr = (u64 *)&remainder.arr;
    u64 *quotient_ptr = (u64 *)&quotient.arr;

    TIMER_START(FUNC_NUMBER_DEV);
    number_assign(dividend, *num_dividend);
    number_assign(divisor, *num_divisor);
    number_reset(&remainder);
    number_reset(&quotient);
    while (seg_dividend >= (u64 *)&dividend)
    {
	u64 mask_dividend = MSB(u64);

	while (mask_dividend)
	{
	    number_shift_left_once(&remainder);
	    number_reset_buffer(&remainder);
	    number_shift_left_once(&quotient);
	    number_reset_buffer(&quotient);
	    *remainder_ptr = *remainder_ptr |
		((*seg_dividend & mask_dividend) ? (u64)1 : (u64)0);
	    if (number_is_greater_or_equal(&remainder, &divisor))
	    {
		*quotient_ptr = *quotient_ptr | (u64)1;
		number_sub(&remainder, &remainder, &divisor);
	    }
	    mask_dividend = mask_dividend >> 1;
	}
	seg_dividend--;
    }
    number_assign(*num_q, quotient);
    number_assign(*num_r, remainder);
    TIMER_STOP(FUNC_NUMBER_DEV);
}

STATIC int INLINE number_modular_multiplication_naive(u1024_t *num_res, 
    u1024_t *num_a, u1024_t *num_b, u1024_t *num_n)
{
    u1024_t tmp;

    TIMER_START(FUNC_NUMBER_MODULAR_MULTIPLICATION_NAIVE);
    number_mul(&tmp, num_a, num_b);
    number_mod(num_res, &tmp, num_n);
    number_reset_buffer(num_res);
    TIMER_STOP(FUNC_NUMBER_MODULAR_MULTIPLICATION_NAIVE);
    return 0;
}

/* assigns num_n: 0 < num_n < range */
static void INLINE number_init_random_strict_range(u1024_t *num_n, 
    u1024_t *range)
{
    u1024_t num_tmp, num_range_min1;

    TIMER_START(FUNC_NUMBER_INIT_RANDOM_STRICT_RANGE);
    number_sub(&num_range_min1, range, &NUM_1);
    number_init_random(&num_tmp, block_sz_u1024);
    number_mod(&num_tmp, &num_tmp, &num_range_min1);
    number_add(&num_tmp, &num_tmp, &NUM_1);

    number_assign(*num_n, num_tmp);
    TIMER_STOP(FUNC_NUMBER_INIT_RANDOM_STRICT_RANGE);
}

STATIC void INLINE number_exponentiation(u1024_t *res, u1024_t *num_base, 
    u1024_t *num_exp)
{
    u1024_t num_cnt, num_tmp;

    TIMER_START(FUNC_NUMBER_EXPONENTIATION);
    number_assign(num_cnt, NUM_0);
    number_assign(num_tmp, NUM_1);

    while (!number_is_equal(&num_cnt, num_exp))
    {
	number_mul(&num_tmp, &num_tmp, num_base);
	number_add(&num_cnt, &num_cnt, &NUM_1);
    }

    number_assign(*res, num_tmp);
    TIMER_STOP(FUNC_NUMBER_EXPONENTIATION);
}

STATIC int INLINE number_modular_exponentiation_naive(u1024_t *res, u1024_t *a, 
    u1024_t *b, u1024_t *n)
{
    u1024_t d;
    u64 *seg = NULL, mask;

    TIMER_START(FUNC_NUMBER_MODULAR_EXPONENTIATION_NAIVE);
    number_assign(d, NUM_1);
    number_find_most_significant_set_bit(b, &seg, &mask);
    while (seg >= (u64*)&b->arr)
    {
	while (mask)
	{
	    if (number_modular_multiplication_naive(&d, &d, &d, n))
		return -1;
	    if (*seg & mask)
	    {
		if (number_modular_multiplication_naive(&d, &d, a, n))
		    return -1;
	    }

	    mask = mask >> 1;
	}
	mask = MSB(u64);
	seg--;
    }
    number_assign(*res, d);
    TIMER_STOP(FUNC_NUMBER_MODULAR_EXPONENTIATION_NAIVE);
    return 0;
}

/* montgomery product
 * MonPro(a, b, n)
 *   s(-1) = 0
 *   a = 2a
 *   for i = 0 to n do
 *     q(i) = s(i-1) mod 2 (LSB of s(i-1))
 *     s(i) = (s(i-1) + q(i)n + b(i)a)/2
 *   end for
 *   return s(n)
 */
static void INLINE number_montgomery_product(u1024_t *num_res, u1024_t *num_a, 
    u1024_t *num_b, u1024_t *num_n)
{
    u1024_t multiplier, num_s;
    u64 *seg = NULL, *top = (u64*)&num_b->arr + block_sz_u1024;
    int i;

    TIMER_START(FUNC_NUMBER_MONTGOMERY_PRODUCT);
    number_assign(multiplier, *num_a);
    number_assign(num_s, NUM_0);
    number_shift_left_once(&multiplier);

    /* handle the first 'encryption_level' iterations */
    for (seg = (u64*)&num_b->arr; seg < top; seg++)
    {
	u64 mask;

	for (mask = (u64)1; mask; mask = mask<<1)
	{
	    if (number_is_odd(&num_s))
		number_add(&num_s, &num_s, num_n);
	    if (*seg & mask)
		number_add(&num_s, &num_s, &multiplier);
	    number_shift_right_once(&num_s);
	}
    }

    /* handle extra 2 iterations, as buffer size is is considered to be 
     * MAX(bit_sz) + 2.
     */
    for (i = 0 ;i < 3; i++)
    {
	if (number_is_odd(&num_s))
	    number_add(&num_s, &num_s, num_n);
	/* the two overflow bits of num_b are zero */
	number_shift_right_once(&num_s);
    }

    number_assign(*num_res, num_s);
    TIMER_STOP(FUNC_NUMBER_MONTGOMERY_PRODUCT);
}

/* shift left and do mod num_n 2*(encryption_level + 2) times... */
void INLINE number_montgomery_factor_set(u1024_t *num_n, u1024_t *num_factor)
{
    u1024_t factor;
    int exp, exp_max;
    u64 *buffer;

    TIMER_START(FUNC_NUMBER_MONTGOMERY_FACTOR_SET);
    if (number_is_equal(&num_montgomery_n, num_n))
	return;

    if (num_factor)
	goto Exit;

    exp_max = 2*(encryption_level+2);
    number_small_dec2num(&factor, (u64)1);
    exp = 0;
    buffer = (u64*)&factor.arr + block_sz_u1024;

    while (exp < exp_max)
    {
	while (!*buffer && number_is_greater(num_n, &factor))
	{
	    if (exp == exp_max)
		goto Exit;
	    number_shift_left_once(&factor);
	    exp++;
	}
	number_sub(&factor, &factor, num_n);
    }

Exit:
    number_assign(num_montgomery_factor, factor);
    number_assign(num_montgomery_n, *num_n);
    number_montgomery_product(&num_res_nresidue, &num_montgomery_factor, &NUM_1,
	num_n);
    TIMER_START(FUNC_NUMBER_MONTGOMERY_FACTOR_SET);
}

/* a: exponent
 * b: power
 * n: modulus
 * r: 2^(encryption_level)%n
 * MonPro(a, b, n) = abr^-1%n
 *
 * a * b % n = abrr^-1%n = 1abrr^-1%n = MonPro(1, abr%n, n) = 
 *             MonPro(1, arbrr^-1%n, n) = MonPro(1, ar%n*br%n*r^-1, n) =
 *             MonPro(1, a(r^2)(r^-1)%n * b(r^2)(r^-1) * (r^-1), n) =
 *             MonPro(1, MonPro(a(r^2)(r^-1)%n, b(r^2)(r^-1), n), n) =
 *             MonPro(1, MonPro(MonPro(a, r^2%n, n), MonPro(b, r^2%n, n), n), n)
 *
 * num_montgomery_factor = r^2%n = 2^2BIT_SZ(u1024_t)%n
 * a_tmp = MonPro(a, r^2%n, n)
 * b_tmp = MonPro(b, r^2%n, n)
 * a * b % n = MonPro(1, MonPro(a_tmp, b_tmp, n), n)
 */
STATIC int INLINE number_modular_multiplication_montgomery(u1024_t *num_res, 
    u1024_t *num_a, u1024_t *num_b, u1024_t *num_n)
{
    int ret;
    u1024_t a_tmp, b_tmp;

    TIMER_START(FUNC_NUMBER_MODULAR_MULTIPLICATION_MONTGOMERY);
    number_montgomery_factor_set(num_n, NULL);

    number_montgomery_product(&a_tmp, num_a, &num_montgomery_factor, num_n);
    number_montgomery_product(&b_tmp, num_b, &num_montgomery_factor, num_n);
    number_montgomery_product(num_res, &a_tmp, &b_tmp, num_n);
    number_montgomery_product(num_res, &NUM_1, num_res, num_n);
    ret = 0;

    TIMER_STOP(FUNC_NUMBER_MODULAR_MULTIPLICATION_MONTGOMERY);
    return ret;
}

/* montgomery (right-left, speed optimised) modular exponentiation procedure:
 * MonExp(a, b, n)
 *   c = 2^(2n)
 *   A = MonPro(c, a, n) (mapping)
 *   r = MonPro(c, 1, n)
 *   for i = 0 to k-1 do
 *     if (bi==1) then
 *       r = MonPro(r, a, n) (multiply)
 *     end if
 *     A = MonPro(A, A, n) (square)
 *   end for
 *   r = MonPro(1, r, n)
 *   return r
 */
int INLINE number_modular_exponentiation_montgomery(u1024_t *res, u1024_t *a, 
    u1024_t *b, u1024_t *n)
{
    u1024_t a_nresidue;
    u64 *seg;
    int ret = 0;

    TIMER_START(FUNC_NUMBER_MODULAR_EXPONENTIATION_MONTGOMERY);
    number_montgomery_factor_set(n, NULL);
    number_montgomery_product(&a_nresidue, &num_montgomery_factor, a, n);
    number_assign(*res, num_res_nresidue);

    for (seg = (u64*)&b->arr; seg < (u64*)&b->arr + block_sz_u1024; seg++)
    {
	u64 mask;

	for (mask = (u64)1; mask; mask = mask << 1)
	{
	    if (*seg & mask)
		number_montgomery_product(res, res, &a_nresidue, n);
	    number_montgomery_product(&a_nresidue, &a_nresidue, &a_nresidue, n);
	}
    }
    number_montgomery_product(res, &NUM_1, res, n);

    TIMER_STOP(FUNC_NUMBER_MODULAR_EXPONENTIATION_MONTGOMERY);
    return ret;
}

static void INLINE number_witness_init(u1024_t *num_n_min1, u1024_t *num_u, 
    int *t)
{
    u1024_t tmp;

    TIMER_START(FUNC_NUMBER_WITNESS_INIT);
    number_assign(tmp, *num_n_min1);
    *t = 0;
    while (!number_is_odd(&tmp))
    {
	number_shift_right_once(&tmp);
	(*t)++;
    }

    number_assign(*num_u, tmp);
    TIMER_STOP(FUNC_NUMBER_WITNESS_INIT);
}

/* witness method used by the miller-rabin algorithm. attempt to use num_a as a
 * witness of num_n's compositness:
 * if number_witness(num_a, num_n) is true, then num_n is composit
 */
STATIC int INLINE number_witness(u1024_t *num_a, u1024_t *num_n)
{
    u1024_t num_u, num_x_prev, num_x_curr, num_n_min1;
    int i, t, ret;

    TIMER_START(FUNC_NUMBER_WITNESS);
    if (!number_is_odd(num_n))
    {
	ret = 1;
	goto Exit;
    }

    number_sub(&num_n_min1, num_n, &NUM_1);
    number_witness_init(&num_n_min1, &num_u, &t);
    if (number_modular_exponentiation_montgomery(&num_x_prev, num_a, &num_u, 
	num_n))
    {
	ret = 1;
	goto Exit;
    }

    for (i = 0; i < t; i++)
    {
	if (number_modular_multiplication_montgomery(&num_x_curr, &num_x_prev, 
	    &num_x_prev, num_n))
	{
	    ret = 1;
	    goto Exit;
	}
	if (number_is_equal(&num_x_curr, &NUM_1) && 
	    !number_is_equal(&num_x_prev, &NUM_1) &&
	    !number_is_equal(&num_x_prev, &num_n_min1))
	{
	    ret = 1;
	    goto Exit;
	}
	number_assign(num_x_prev, num_x_curr);
    }

    if (!number_is_equal(&num_x_curr, &NUM_1))
    {
	ret = 1;
	goto Exit;
    }
    ret = 0;

Exit:
    TIMER_STOP(FUNC_NUMBER_WITNESS);
    return ret;
}

/* miller-rabin algorithm
 * num_n is an odd integer greater than 2 
 * return:
 * 0 - if num_n is composit
 * 1 - if num_n is almost surely prime
 */
STATIC int INLINE number_miller_rabin(u1024_t *num_n, u1024_t *num_s)
{
    int ret;
    u1024_t num_j, num_a;

    TIMER_START(FUNC_NUMBER_MILLER_RABIN);
    number_assign(num_j, NUM_1);

    while (!number_is_equal(&num_j, num_s))
    {
	number_init_random_strict_range(&num_a, num_n);
	if (number_witness(&num_a, num_n))
	{
	    ret = 0;
	    goto Exit;
	}
	number_add(&num_j, &num_j, &NUM_1);
    }
    ret = 1;

Exit:
    TIMER_STOP(FUNC_NUMBER_MILLER_RABIN);
    return ret;
}

STATIC int INLINE number_is_prime(u1024_t *num_n)
{
    int ret;
    u1024_t num_s;

    TIMER_START(FUNC_NUMBER_IS_PRIME);
    number_assign(num_s, NUM_10);
    ret = number_miller_rabin(num_n, &num_s);

    TIMER_STOP(FUNC_NUMBER_IS_PRIME);
    return ret;
}

/* initiate number_generate_coprime:small_primes[] fields and generate pi and
 * incrementor
 */
static void INLINE number_small_prime_init(small_prime_entry_t *entry, 
    u64 exp_initializer, u1024_t *num_pi, u1024_t *num_increment)
{
    TIMER_START(FUNC_NUMBER_SMALL_PRIME_INIT);

    /* initiate the entry's prime */
    number_small_dec2num(&(entry->prime), entry->prime_initializer);

    /* initiate the entry's exponent */
    number_small_dec2num(&(entry->exp), exp_initializer);

    /* rase the entry's prime to the required power */
    number_exponentiation(&(entry->power_of_prime), &(entry->prime), 
	&(entry->exp));

    /* update pi */
    number_mul(num_pi, num_pi, &(entry->power_of_prime));

    /* update incrementor */
    number_mul(num_increment, num_increment, &(entry->prime));

    TIMER_STOP(FUNC_NUMBER_SMALL_PRIME_INIT);
}

/* num_increment = 304250263527210, is the product of the first 13 primes
 * num_pi = 7.4619233495664116883370964193144e+153, is the product of the first
 *   13 primes raised to the respective power, exp, in small_primes[]. it is a 
 *   512 bit number
 * retuned value: num_coprime is a large number such that 
 *   gcd(num_coprime, num_increment) == 1, that is, it does not devided by any 
 *   of the first 13 primes
 */
STATIC void INLINE number_generate_coprime(u1024_t *num_coprime, 
    u1024_t *num_increment)
{
    int i;
    static u1024_t num_pi, num_mod, num_jumper, num_inc;
    static int init;
    static small_prime_entry_t small_primes[NUMBER_GENERATE_COPRIME_ARRAY_SZ] = 
    {
	{2}, {3}, {5}, {7}, {11}, {13}, {17}, {19}, {23}, {29}, {31}, {37}, {41}
    };

#ifdef TESTS
    if (init_reset)
    {
	init = 0;
	init_reset = 0;
    }
#endif

    TIMER_START(FUNC_NUMBER_GENERATE_COPRIME);
    if (!init)
    {
	code2list_t exponents[] = {
	    /* encryption_level 64 is not yet implemented */
	    {64, {}},
	    /* 16353755914851064710 */
	    {128, {1, 2, 1, 1, 1, 1, 1, 2, 2, 1, 1, 1, 2}},
	    /* 3.310090638572971097793164988204e+38 */
	    {256, {3, 3, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3}},
	    /* 1.1469339122146834228518724332952e+77 */
	    {512, {5, 5, 5, 5, 5, 5, 5, 5, 5, 6, 5, 6, 6}},
	    /* 7.4619233495664116883370964193144e+153 */
	    {1024, {10, 10, 11, 11, 10, 10, 10, 10, 11, 11, 11, 11, 11}},
	    {-1}
	};
	u64 *exp_initializer = code2list(exponents, encryption_level);

	/* initiate prime, exp and power_of_prime fields in all small_primes[] 
	 * elements. generate num_inc and num_pi at the same time.
	 */
	number_assign(num_pi, NUM_1);
	number_assign(num_inc, NUM_1);
	for (i = 0; i < ARRAY_SZ(small_primes); i++)
	{
	    number_small_prime_init(&small_primes[i], exp_initializer[i], 
		&num_pi, &num_inc);
	}

	init = 1;
    }

    /* generate num_coprime, such that gcd(num_coprime, num_increment) == 1 */
    number_assign(*num_increment, num_inc);
    number_assign(*num_coprime, NUM_0);
    for (i = 0; i < ARRAY_SZ(small_primes); i++)
    {
	u1024_t num_a, num_a_pow;

	do
	{
	    number_init_random(&num_a, block_sz_u1024/2);
	    number_modular_exponentiation_naive(&num_a_pow, &num_a,
		&(small_primes[i].exp), &num_pi);
	}
	while (number_is_equal(&num_a_pow, &NUM_0));
	number_add(num_coprime, num_coprime, &num_a);
    }

    /* bound num_coprime to be less than num_pi */
    number_mod(num_coprime, num_coprime, &num_pi);

    /* refine num_coprime:
     * if num_coprime % small_primes[i].prime == 0, then
     * - generate from num_inc, num_jumper, such that 
     *   gcd(num_jumper, small_primes[i].prime) == 1
     * - do: num_coprime = num_coprime + num_jumper
     * thus, gcd(num_coprime, small_primes[i].prime) == 1
     */
    number_assign(num_jumper, num_inc);
    for (i = 0; i < ARRAY_SZ(small_primes); i++)
    {
	number_mod(&num_mod, num_coprime, &(small_primes[i].prime));
	if (number_is_equal(&num_mod, &NUM_0))
	{
	    number_dev(&num_jumper, &NUM_0, &num_jumper, 
		&(small_primes[i].prime));
	}
    }
    if (!number_is_equal(&num_jumper, &num_inc))
	number_add(num_coprime, num_coprime, &num_jumper);
    TIMER_STOP(FUNC_NUMBER_GENERATE_COPRIME);
}

/* determin x, y and gcd according to a and b such that:
 * ax+by == gcd(a, b)
 * NOTE: a is assumed to be >= b */
STATIC void INLINE number_extended_euclid_gcd(u1024_t *gcd, u1024_t *x, 
    u1024_t *a, u1024_t *y, u1024_t *b)
{
    u1024_t num_x, num_x1, num_x2, num_y, num_y1, num_y2;
    u1024_t num_a, num_b, num_q, num_r;
    int change;

    TIMER_START(FUNC_NUMBER_EXTENDED_EUCLID_GCD);
    if (number_is_greater_or_equal(a, b))
    {
	number_assign(num_a, *a);
	number_assign(num_b, *b);
	change = 0;
    }
    else
    {
	number_assign(num_a, *b);
	number_assign(num_b, *a);
	change = 1;
    }

    number_assign(num_x1, NUM_0);
    number_assign(num_x2, NUM_1);
    number_assign(num_y1, NUM_1);
    number_assign(num_y2, NUM_0);

    while (number_is_greater(&num_b, &NUM_0))
    {
	number_dev(&num_q, &num_r, &num_a, &num_b);

	number_mul(&num_x, &num_x1, &num_q);
	number_sub(&num_x, &num_x2, &num_x);
	number_mul(&num_y, &num_y1, &num_q);
	number_sub(&num_y, &num_y2, &num_y);

	number_assign(num_a, num_b);
	number_assign(num_b, num_r);
	number_assign(num_x2, num_x1);
	number_assign(num_x1, num_x);
	number_assign(num_y2, num_y1);
	number_assign(num_y1, num_y);
    }

    number_assign(*x, change ? num_y2 : num_x2);
    number_assign(*y, change ? num_x2 : num_y2);
    number_assign(*gcd, change ? num_b : num_a);
    TIMER_STOP(FUNC_NUMBER_EXTENDED_EUCLID_GCD);
}

STATIC void INLINE number_euclid_gcd(u1024_t *gcd, u1024_t *a, u1024_t *b)
{
    u1024_t x, y;

    TIMER_START(FUNC_NUMBER_EUCLID_GCD);
    if (number_is_greater_or_equal(a, b))
	number_extended_euclid_gcd(gcd, &x, a, &y, b);
    else
	number_extended_euclid_gcd(gcd, &y, b, &x, a);
    TIMER_STOP(FUNC_NUMBER_EUCLID_GCD);
}

void number_init_random_coprime(u1024_t *num, u1024_t *coprime)
{
    u1024_t num_gcd;

    TIMER_START(FUNC_NUMBER_INIT_RANDOM_COPRIME);
    do
    {
	number_init_random_strict_range(num, coprime);
	number_euclid_gcd(&num_gcd, num, coprime);
    }
    while (!number_is_equal(&num_gcd, &NUM_1));
    TIMER_STOP(FUNC_NUMBER_INIT_RANDOM_COPRIME);
}

/* assumtion: 0 < num < mod */
int number_modular_multiplicative_inverse(u1024_t *inv, u1024_t *num, 
    u1024_t *mod)
{
    u1024_t num_x, num_y, num_gcd, num_y_abs;

    TIMER_START(FUNC_NUMBER_MODULAR_MULTIPLICATIVE_INVERSE);
    number_extended_euclid_gcd(&num_gcd, &num_x, mod, &num_y, num);
    number_absolute_value(&num_y_abs, &num_y);
    number_mod(inv, &num_y_abs, mod);

    if (!number_is_equal(&num_y_abs, &num_y))
	number_sub(inv, mod, inv);
    TIMER_STOP(FUNC_NUMBER_MODULAR_MULTIPLICATIVE_INVERSE);
    return !number_gcd_is_1(num, inv);
}

void number_find_prime(u1024_t *num)
{
    u1024_t num_candidate, num_increment;

    TIMER_START(FUNC_NUMBER_FIND_PRIME);
    number_generate_coprime(&num_candidate, &num_increment);

    while (!(number_is_prime(&num_candidate)))
    {
	number_add(&num_candidate, &num_candidate, &num_increment);

	/* highly unlikely event of rollover renderring num_candidate == 1 */
	if (number_is_equal(&num_candidate, &NUM_1))
	    number_generate_coprime(&num_candidate, &num_increment);
    }

    number_assign(*num, num_candidate);
    TIMER_STOP(FUNC_NUMBER_FIND_PRIME);
}

int number_str2num(u1024_t *num, char *str)
{
    u64 *seg;

    if (ASCII_LEN_2_BIN_LEN(str) > encryption_level)
	return -1;
    number_reset(num);
    sprintf((char *)num, "%s", str);
    for (seg = (u64*)&num->arr + block_sz_u1024, num->top = block_sz_u1024; 
	seg >= (u64*)&num->arr && !*seg; seg--, num->top--);
    return 0;
}

#ifdef TESTS
STATIC void number_shift_right(u1024_t *num, int n)
{
    int i;

    TIMER_START(FUNC_NUMBER_SHIFT_RIGHT);
    for (i = 0; i < n; i++)
	number_shift_right_once(num);
    TIMER_STOP(FUNC_NUMBER_SHIFT_RIGHT);
}

STATIC void number_shift_left(u1024_t *num, int n)
{
    int i;

    TIMER_START(FUNC_NUMBER_SHIFT_LEFT);
    for (i = 0; i < n; i++)
	number_shift_left_once(num);
    TIMER_STOP(FUNC_NUMBER_SHIFT_LEFT);
}

static u64 *number_get_seg(u1024_t *num, int seg)
{
    u64 *ret;

    if (!num)
	return NULL;

    ret = (u64*)&num->arr + seg;
    return ret;
}

static int is_valid_number_str_sz(char *str)
{
    int ret;

    if (!strlen(str))
    {
	ret = 0;
	goto Exit;
    }

    /* allow for number array + buffer */
    if (strlen(str) > encryption_level + bit_sz_u64)
    {
	char *ptr = NULL;

	for (ptr = str + strlen(str) - encryption_level - 1 ;
	    ptr >= str; ptr--)
	{
	    if (*ptr == '1')
	    {
		ret = 0;
		goto Exit;
	    }
	}
    }
    ret = 1;

Exit:
    return ret;

}

int number_init_str(u1024_t *num, char *init_str)
{
    char *ptr = NULL;
    char *end = init_str + strlen(init_str) - 1; /* LSB */
    u64 mask = 1;

    if (!is_valid_number_str_sz(init_str))
	return -1;

    number_reset(num);
    for (ptr = end; ptr >= init_str; ptr--) /* LSB to MSB */
    {
	u64 *seg = NULL;

	if (*ptr != '0' && *ptr != '1')
	    return -1;

	seg = number_get_seg(num, (end - ptr) / bit_sz_u64);
	if (*ptr == '1')
	    *seg = *seg | mask;
	mask = (u64)(mask << 1) ? (u64)(mask << 1) : 1;
    }

    num->top = (end - init_str) / bit_sz_u64;
    return 0;
}

int number_dec2bin(u1024_t *num_bin, char *str_dec)
{
    int ret;
    char *str_start = NULL, *str_end = NULL;
    u1024_t num_tmp, num_counter;
    static char *str_dec2bin[] = {
	"0000", /* 0 */
	"0001", /* 1 */
	"0010", /* 2 */
	"0011", /* 3 */
	"0100", /* 4 */
	"0101", /* 5 */
	"0110", /* 6 */
	"0111", /* 7 */
	"1000", /* 8 */
	"1001", /* 9 */
    };
    
    if (!num_bin || !str_dec)
    {
	ret = -1;
	goto Exit;
    }

    str_start = str_dec;
    str_end = str_dec + strlen(str_dec) - 1;
    number_reset(&num_tmp);
    /* eat leading zeros */
    while (str_start && *str_start == '0')
	str_start++;
    if (str_end < str_start)
    {
	number_assign(*num_bin, num_tmp);
	ret = 0;
	goto Exit;
    }

    num_counter = NUM_1;
    while (str_start <= str_end) 
    {
	u1024_t num_digit, num_addition;

	if (!IS_DIGIT(*str_end))
	{
	    ret = -1;
	    goto Exit;
	}

	number_init_str(&num_digit, str_dec2bin[CHAR_2_INT(*str_end)]);
	number_mul(&num_addition, &num_digit, &num_counter);
	number_add(&num_tmp, &num_tmp, &num_addition);
	number_mul(&num_counter, &num_counter, &NUM_10);
	str_end--;
    }
    /* update top */
    number_top_set(&num_tmp);
    number_assign(*num_bin, num_tmp);
    ret = 0;

Exit:
    return ret;
}
#endif

