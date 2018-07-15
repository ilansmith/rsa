#include "rsa.h"
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <math.h>

#define IS_DIGIT(n) ((n)>='0' && (n)<='9')
#define CHAR_2_INT(c) ((int)((c) - '0'))
#define COPRIME_PRIME(X) ((X).prime)
#define COPRIME_DIVISOR(X) ((X).divisor)

#define FIRST

typedef int (* func_modular_multiplication_t) (u1024_t *num_res, 
    u1024_t *num_a, u1024_t *num_b, u1024_t *num_n);

STATIC u1024_t num_montgomery_n, num_montgomery_factor;

void INLINE number_reset(u1024_t *num)
{
    u64 *seg = NULL;

    TIMER_START(FUNC_NUMBER_RESET);
    for (seg = (u64 *)num; 
	seg < (u64 *)num + (BYTES_SZ(u1024_t) / BYTES_SZ(u64)); seg++)
    {
	*seg = (u64)0;
    }
    TIMER_STOP(FUNC_NUMBER_RESET);
}

STATIC void INLINE number_add(u1024_t *res, u1024_t *num1, u1024_t *num2)
{
    static u1024_t tmp_res;
    static u64 *max_advance = NULL, cmask = MSB_PT(u64);
    u64 *seg = NULL, *seg1 = NULL, *seg2 = NULL, carry = 0;

    TIMER_START(FUNC_NUMBER_ADD);
    if (!max_advance)
	max_advance = (u64 *)&tmp_res + (BYTES_SZ(u1024_t) / BYTES_SZ(u64));

    number_reset(&tmp_res);
    for (seg = (u64 *)&tmp_res, seg1 = (u64 *)num1, seg2 = (u64 *)num2;
	seg < max_advance; seg++, seg1++, seg2++)
    {
	if (!*seg1)
	{
	    *seg = *seg2;
	    if (carry)
	    {
		carry = *seg2 == (u64)-1 ? (u64)1 : (u64)0;
		(*seg)++;
	    }
	    continue;
	}
	if (!*seg2)
	{
	    *seg = *seg1;
	    if (carry)
	    {
		carry = *seg1 == (u64)-1 ? (u64)1 : (u64)0;
		(*seg)++;
	    }
	    continue;
	}
	*seg = *seg1 + *seg2 + carry;
	if ((*seg1 & cmask) && (*seg2 & cmask))
	    carry = 1;
	else if (!(*seg1 & cmask) && !(*seg2 & cmask))
	    carry = 0;
	else
	    carry = (*seg & cmask) ? 0 : 1;
    }
    *res = tmp_res;
    TIMER_STOP(FUNC_NUMBER_ADD);
}

#ifdef TESTS
static u64 *number_get_seg(u1024_t *num, int seg)
{
    u64 *ret;

    if (!num)
	return NULL;

    ret = (u64 *)num + seg;
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

    if (strlen(str) > BITS_SZ(u1024_t))
    {
	char *ptr = NULL;

	for (ptr = str + strlen(str) - BITS_SZ(u1024_t) - 1 ;
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

	seg = number_get_seg(num, (end - ptr) / BITS_SZ(u64));
	if (*ptr == '1')
	    *seg = *seg | mask;
	mask = (u64)(mask << 1) ? (u64)(mask << 1) : 1;
    }

    return 0;
}


#endif

int INLINE number_init_random(u1024_t *num)
{
    int i, ret;
    struct timeval tv;

    TIMER_START(FUNC_NUMBER_INIT_RANDOM);
    number_reset(num);
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    if (gettimeofday(&tv, NULL))
    {
	ret = -1;
	goto Exit;
    }
    srandom((unsigned int)tv.tv_sec * (unsigned int)tv.tv_usec);
    /* since the most significant BITS_SZ(u1024_t)/2 bits of the u1024_t are
     * buffer bits, random numbers are initiated with at most
     * (BITS_SZ(u1024_t)/2) / 2 bits
     */
    for (i = 0; i < ((BYTES_SZ(u1024_t) / 4) / BYTES_SZ(long)); i++)
	*((long *)num + i) |= random();

    ret = 0;

Exit:
    TIMER_STOP(FUNC_NUMBER_INIT_RANDOM);
    return ret;
}

STATIC int INLINE number_find_most_significant_set_bit(u1024_t *num, 
    u64 **major, u64 *minor)
{
    u64 *tmp_major = (u64 *)num + (BYTES_SZ(u1024_t) / BYTES_SZ(u64)) - 1;
    u64 tmp_minor;
    int minor_offset;

    TIMER_START(FUNC_NUMBER_FIND_MOST_SIGNIFICANT_SET_BIT);
    while (tmp_major >= (u64 *)num)
    {
	tmp_minor = MSB_PT(u64);
	minor_offset = BITS_SZ(u64);

	while (tmp_minor)
	{
	    if (!(*tmp_major & tmp_minor))
	    {
		tmp_minor = tmp_minor >> 1;
		minor_offset--;
		continue;
	    }
	    goto Exit;
	}
	tmp_major--;
    }
    tmp_major++; /* while loop terminates when tmp_major == (u64 *)num - 1 */

Exit:
    *minor = tmp_minor;
    *major = tmp_major;

    TIMER_STOP(FUNC_NUMBER_FIND_MOST_SIGNIFICANT_SET_BIT);
    return minor_offset;
}

static void INLINE number_shift_left_once(u1024_t *num)
{
    u64 mask_msb = MSB_PT(u64);
    u64 mask_lsb = ~1;
    u64 *seg = (u64 *)num + (BYTES_SZ(u1024_t) / BYTES_SZ(u64)) - 1;

    TIMER_START(FUNC_NUMBER_SHIFT_LEFT_ONCE);
    *seg = *seg << 1;
    *seg = *seg & mask_lsb;
    seg--;
    while (seg >= (u64 *)num)
    {
	*(seg + 1) += *seg & mask_msb ? 1 : 0;
	*seg = *seg << 1;
	*seg = *seg & mask_lsb;
	seg--;
    }
    TIMER_STOP(FUNC_NUMBER_SHIFT_LEFT_ONCE);
}

#ifdef TESTS
STATIC void number_shift_left(u1024_t *num, int n)
{
    int i;

    TIMER_START(FUNC_NUMBER_SHIFT_LEFT);
    for (i = 0; i < n; i++)
	number_shift_left_once(num);
    TIMER_STOP(FUNC_NUMBER_SHIFT_LEFT);
}
#endif

static void INLINE number_shift_right_once(u1024_t *num)
{
    u64 mask_msb = MSB_PT(u64);
    u64 mask_lsb = 1;
    u64 *seg = (u64 *)num + (BYTES_SZ(u1024_t) / BYTES_SZ(u64)) - 1;
    int next_overflow, prev_overflow = 0;

    TIMER_START(FUNC_NUMBER_SHIFT_RIGHT_ONCE);
    while (seg >= (u64 *)num)
    {
	next_overflow = (int)(*seg & mask_lsb);
	*seg = *seg >> 1;
	if (prev_overflow)
	    *seg = *seg | mask_msb;
	prev_overflow = next_overflow;
	seg--;
    }
    TIMER_STOP(FUNC_NUMBER_SHIFT_RIGHT_ONCE);
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
#endif

STATIC void INLINE number_small_dec2num(u1024_t *num_n, u64 dec)
{
    u64 zero = (u64)0;
    u64 *ptr = &zero;

    TIMER_START(FUNC_NUMBER_SMALL_DEC2NUM);
    number_reset(num_n);
    *(u64 *)num_n = (u64)(*ptr | dec);
    TIMER_STOP(FUNC_NUMBER_SMALL_DEC2NUM);
}

STATIC void INLINE number_2complement(u1024_t *res, u1024_t *num)
{
    u1024_t tmp = *num, num_1;
    u64 *seg = NULL;

    TIMER_START(FUNC_NUMBER_2COMPLEMENT);
    number_small_dec2num(&num_1, (u64)1);
    for (seg = (u64 *)&tmp; 
	seg - (u64 *)&tmp < (BYTES_SZ(u1024_t) / BYTES_SZ(u64)); seg++)
    {
	*seg = ~*seg; /* one's complement */
    }

    number_add(res, &tmp, &num_1); /* two's complement */
    TIMER_STOP(FUNC_NUMBER_2COMPLEMENT);
}

STATIC void INLINE number_sub(u1024_t *res, u1024_t *num1, u1024_t *num2)
{
    u1024_t num2_2complement;

    TIMER_START(FUNC_NUMBER_SUB);
    number_2complement(&num2_2complement, num2);
    number_add(res, num1, &num2_2complement);
    TIMER_STOP(FUNC_NUMBER_SUB);
}

void number_sub1(u1024_t *num)
{
    u1024_t num_1;

    number_small_dec2num(&num_1, (u64)1);
    number_sub(num, num, &num_1);
}

void INLINE number_mul(u1024_t *res, u1024_t *num1, u1024_t *num2)
{
    int i;
    u1024_t tmp_res, multiplicand = *num1, multiplier = *num2;

    TIMER_START(FUNC_NUMBER_MUL);
    number_reset(&tmp_res);
    for (i = 0; i < BYTES_SZ(u1024_t) / BYTES_SZ(u64); i++)
    {
	u64 mask = 1;
	int j;

	for (j = 0; j < BITS_SZ(u64); j++)
	{
	    if ((*((u64 *)(&multiplier) + i)) & mask)
		number_add(&tmp_res, &tmp_res, &multiplicand);
	    number_shift_left_once(&multiplicand);
	    mask = mask << 1;
	}
    }
    *res = tmp_res;
    TIMER_STOP(FUNC_NUMBER_MUL);
}

#ifdef TESTS
int number_dec2bin(u1024_t *num_bin, char *str_dec)
{
    int ret;
    char *str_start = NULL, *str_end = NULL;
    u1024_t num_counter, num_x10, num_digit, num_addition;
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
    number_reset(num_bin);
    number_init_str(&num_x10, "1010");
    number_init_str(&num_counter, "1");
    while (str_start && *str_start == '0')
	str_start++;

    if (str_end < str_start)
    {
	ret = 0;
	goto Exit;
    }

    while (str_start <= str_end) 
    {
	if (!IS_DIGIT(*str_end))
	{
	    ret = -1;
	    goto Exit;
	}

	number_init_str(&num_digit, str_dec2bin[CHAR_2_INT(*str_end)]);
	number_mul(&num_addition, &num_digit, &num_counter);
	number_add(num_bin, num_bin, &num_addition);
	number_mul(&num_counter, &num_counter, &num_x10);
	str_end--;
    }
    ret = 0;

Exit:
    return ret;
}
#endif

STATIC void INLINE number_absolute_value(u1024_t *abs, u1024_t *num)
{
    *abs = *num;

    TIMER_START(FUNC_NUMBER_ABSOLUTE_VALUE);
    if (NUMBER_IS_NEGATIVE(num))
    {
	u1024_t num_1;
	u64 *seg = (u64 *)abs + (BYTES_SZ(u1024_t) / BYTES_SZ(u64) - 1);

	number_small_dec2num(&num_1, (u64)1);
	number_sub(abs, abs, &num_1);
	while (seg >= (u64 *)abs)
	{
	    *seg = ~*seg;
	    seg--;
	}
    }
    TIMER_STOP(FUNC_NUMBER_ABSOLUTE_VALUE);
}

static int INLINE number_compare(u1024_t *num1, u1024_t *num2, int ret_on_equal)
{
    int ret;
    u64 *seg1 = (u64 *)num1 + (BYTES_SZ(u1024_t) / BYTES_SZ(u64)) - 1;
    u64 *seg2 = (u64 *)num2 + (BYTES_SZ(u1024_t) / BYTES_SZ(u64)) - 1;

    TIMER_START(FUNC_NUMBER_COMPARE);
    while (seg1 >= (u64 *)num1)
    {
	u64 mask = MSB_PT(u64);

	while (mask)
	{
	    if ((*seg1 & mask) == (*seg2 & mask))
	    {
		mask = mask >> 1;
		continue;
	    }
	    ret = (*seg1 & mask) > (*seg2 & mask);
	    goto Exit;
	}
	seg1--;
	seg2--;
    }
    ret = ret_on_equal; /* *num1 == *num2 */

Exit:
    TIMER_STOP(FUNC_NUMBER_COMPARE);
    return ret;
}

STATIC int INLINE number_is_equal(u1024_t *a, u1024_t *b)
{
    u64 *seg_a = (u64 *)a, *seg_b = (u64 *)b;
    int i, ret;

    TIMER_START(FUNC_NUMBER_IS_EQUAL);
    for (i = 0; i < BYTES_SZ(u1024_t) / BYTES_SZ(u64); i++)
    {
	if (*(seg_a + i) != *(seg_b + i))
	{
	    ret = 0;
	    goto Exit;
	}
    }
    ret = 1;

Exit:
    TIMER_STOP(FUNC_NUMBER_IS_EQUAL);
    return ret;
}

STATIC int INLINE number_is_greater(u1024_t *num1, u1024_t *num2)
{
    int ret;

    TIMER_START(FUNC_NUMBER_IS_GREATER);
    ret = number_compare(num1, num2, 0);
    TIMER_STOP(FUNC_NUMBER_IS_GREATER);
    return ret;
}

/* return: num1 >= num2 */
static int INLINE number_is_greater_or_equal(u1024_t *num1, u1024_t *num2)
{
    int ret;

    TIMER_START(FUNC_NUMBER_IS_GREATER_OR_EQUAL);
    ret = number_compare(num1, num2, 1);
    TIMER_STOP(FUNC_NUMBER_IS_GREATER_OR_EQUAL);
    return ret;
}

STATIC void INLINE number_dev(u1024_t *num_q, u1024_t *num_r, 
    u1024_t *num_dividend, u1024_t *num_divisor)
{
    u1024_t dividend = *num_dividend, divisor = *num_divisor, quotient, 
	remainder;
    u64 *seg_dividend = (u64 *)&dividend + (BYTES_SZ(u1024_t)/BYTES_SZ(u64)) 
	- 1;
    u64 *remainder_ptr = (u64 *)&remainder, *quotient_ptr = (u64 *)&quotient;

    TIMER_START(FUNC_NUMBER_DEV);
    number_reset(&remainder);
    number_reset(&quotient);
    while (seg_dividend >= (u64 *)&dividend)
    {
	u64 mask_dividend = MSB_PT(u64);

	while (mask_dividend)
	{
	    number_shift_left_once(&remainder);
	    number_shift_left_once(&quotient);
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
    *num_q = quotient;
    *num_r = remainder;
    TIMER_STOP(FUNC_NUMBER_DEV);
}

STATIC void INLINE number_mod(u1024_t *r, u1024_t *a, u1024_t *n)
{
    u1024_t q;

    TIMER_START(FUNC_NUMBER_MOD);
    number_dev(&q, r, a, n);
    TIMER_STOP(FUNC_NUMBER_MOD);
}

STATIC int INLINE number_modular_multiplication_naive(u1024_t *num_res, 
    u1024_t *num_a, u1024_t *num_b, u1024_t *num_n)
{
    u1024_t tmp;

    TIMER_START(FUNC_NUMBER_MODULAR_MULTIPLICATION_NAIVE);
    number_mul(&tmp, num_a, num_b);
    number_mod(num_res, &tmp, num_n);
    TIMER_STOP(FUNC_NUMBER_MODULAR_MULTIPLICATION_NAIVE);
    return 0;
}

/* assigns num_n: 0 < num_n < range */
static void INLINE number_init_random_strict_range(u1024_t *num_n, 
    u1024_t *range)
{
    u1024_t num_tmp, num_range_min1, num_1;

    TIMER_START(FUNC_NUMBER_INIT_RANDOM_STRICT_RANGE);
    number_small_dec2num(&num_1, (u64)1);
    number_sub(&num_range_min1, range, &num_1);
    number_init_random(&num_tmp);
    number_mod(&num_tmp, &num_tmp, &num_range_min1);
    number_add(&num_tmp, &num_tmp, &num_1);

    *num_n = num_tmp;
    TIMER_STOP(FUNC_NUMBER_INIT_RANDOM_STRICT_RANGE);
}

STATIC void INLINE number_exponentiation(u1024_t *res, u1024_t *num_base, 
    u1024_t *num_exp)
{
    u1024_t num_cnt, num_1, num_tmp;

    TIMER_START(FUNC_NUMBER_EXPONENTIATION);
    number_small_dec2num(&num_1, (u64)1);
    number_small_dec2num(&num_cnt, (u64)0);
    number_small_dec2num(&num_tmp, (u64)1);

    while (!number_is_equal(&num_cnt, num_exp))
    {
	number_mul(&num_tmp, &num_tmp, num_base);
	number_add(&num_cnt, &num_cnt, &num_1);
    }

    *res = num_tmp;
    TIMER_STOP(FUNC_NUMBER_EXPONENTIATION);
}

STATIC int INLINE number_modular_exponentiation(u1024_t *res, u1024_t *a, 
    u1024_t *b, u1024_t *n, 
    func_modular_multiplication_t modular_multiplication)
{
    u1024_t d, num_1;
    u64 *seg = NULL, mask;

    number_small_dec2num(&d, (u64)1);
    number_small_dec2num(&num_1, (u64)1);
    number_find_most_significant_set_bit(b, &seg, &mask);
    while (seg >= (u64 *)b)
    {
	while (mask)
	{
	    if (modular_multiplication(&d, &d, &d, n))
		return -1;
	    if (*seg & mask)
	    {
		if (modular_multiplication(&d, &d, a, n))
		    return -1;
	    }

	    mask = mask >> 1;
	}
	mask = MSB_PT(u64);
	seg--;
    }
    *res = d;
    return 0;
}

static int INLINE number_gcd_is_1(u1024_t *num_a, u1024_t *num_b)
{
    /* algorithm
     * ---------
     * g = 0
     * while u is even and v is even
     *   u = u/2 (right shift)
     *   v = v/2
     *   g = g + 1
     * now u or v (or both) are odd
     * while u > 0
     *   if u is even, u = u/2
     *   else if v is even, v = v/2
     *   else if u >= v
     *     u = (u-v)/2
     *   else
     *     v = (v-u)/2
     * return v/2^k
     */

    /* Since radix is of the form 2^k, and n is odd, their GCD is 1 */
    return 1;
}

STATIC inline int number_is_odd(u1024_t *num)
{
    int ret;

    TIMER_START(FUNC_NUMBER_IS_ODD);
    ret = *(u64 *)num & (u64)1;
    TIMER_STOP(FUNC_NUMBER_IS_ODD);
    return ret;
}

STATIC int INLINE number_modular_exponentiation_naive(u1024_t *res, u1024_t *a, 
    u1024_t *b, u1024_t *n)
{
    int ret;

    TIMER_START(FUNC_NUMBER_MODULAR_EXPONENTIATION_NAIVE);
    ret = number_modular_exponentiation(res, a, b, n, 
	number_modular_multiplication_naive);
    TIMER_STOP(FUNC_NUMBER_MODULAR_EXPONENTIATION_NAIVE);
    return ret;
}

/* num_radix = pow(2, 2*(BITS_SZ(u1024_t) + 2) % num_n) 
 * returns: gcd(num_radix, num_n) == 1
 *
 * the algorithm:
 * - let i be such that 2^i be the smallest power of 2 >=n
 * - let num_exp and r be such that num_exp*i + r == two_k where r < i
 * then
 * - pow(2, two_k) == pow(2, num_exp*i + r) == pow(2, num_exp*i) * pow(2, r)
 * - pow(2, num_exp*i) * pow(2, r) % n == 
 * */
int INLINE number_radix(u1024_t *num_radix, u1024_t *num_n)
{
    TIMER_START(FUNC_NUMBER_RADIX);

/* k is the length of the memory buffer + 2 */
#define TWO_K (u64)(2 * (BITS_SZ(u1024_t) + 2))

    u1024_t exp, pow, acm, num_0, num_1;
    int ret;

    number_small_dec2num(&num_0, (u64)0);
    number_small_dec2num(&num_1, (u64)1);
    number_small_dec2num(&acm, (u64)1);
    number_small_dec2num(&exp, (u64)2);
    number_small_dec2num(&pow, TWO_K);

    while (number_is_greater(&exp, &num_1) && !number_is_equal(&pow, &num_0))
    {
	while (!number_is_greater_or_equal(&exp, num_n))
	{
	    if (number_is_odd(&pow))
	    {
		number_mul(&acm, &acm, &exp);
		if (number_is_greater_or_equal(&acm, num_n))
		    number_mod(&acm, &acm, num_n);
		number_sub(&pow, &pow, &num_1);
		break;
	    }

	    number_shift_right_once(&pow);
	    number_mul(&exp, &exp, &exp);
	}

	number_mod(&exp, &exp, num_n);
    }

    number_mod(&acm, &acm, num_n);
    *num_radix = acm;
    ret = number_is_equal(&exp, &num_0) ? 0 :
	number_gcd_is_1(num_radix, num_n) - 1;

    TIMER_STOP(FUNC_NUMBER_RADIX);
    return ret;
}

#if 0
/* num_radix = pow(2, 2*(BITS_SZ(u1024_t) + 2) % num_n) 
 * returns: gcd(num_radix, num_n) == 1
 *
 * the algorithm:
 * - let i be such that 2^i be the smallest power of 2 >=n
 * - let num_exp and r be such that num_exp*i + r == two_k where r < i
 * then
 * - pow(2, two_k) == pow(2, num_exp*i + r) == pow(2, num_exp*i) * pow(2, r)
 * - pow(2, num_exp*i) * pow(2, r) % n == 
 * */
int number_radix(u1024_t *num_radix, u1024_t *num_n)
{
    /* k is the length of the memory buffer + 2 */
    u64 two_k = ((u64)(2 * (BITS_SZ(u1024_t) + 2)));
    u1024_t num_exp;
    u64 i = 0, r;
    int ret;

    TIMER_START(FUNC_NUMBER_RADIX);
    /* num_radix = first power of 2 which is >= num_n 
     * i = log2(*num_radix) */
    number_small_dec2num(num_radix, (u64)1);
    while (!number_is_greater_or_equal(num_radix, num_n))
    {
	number_shift_left_once(num_radix);
	i++;
    }
    number_small_dec2num(&num_exp, (u64)((u64)two_k / i));
    r = (u64)((u64)two_k % i);
    /* num_radix = num_radix % num_n */
    number_sub(num_radix, num_radix, num_n);
    /* ilan: bug */
    number_modular_exponentiation_naive(num_radix, num_radix, &num_exp, num_n);
    while (r)
    {
	number_shift_left_once(num_radix);
	if (number_is_greater_or_equal(num_radix, num_n))
	    number_mod(num_radix, num_radix, num_n);
	r--;
    }
    ret = number_gcd_is_1(num_radix, num_n) - 1;

    TIMER_START(FUNC_NUMBER_RADIX);
    return ret;
}
#endif

static void INLINE number_montgomery_product(u1024_t *num_res, u1024_t *num_a, 
    u1024_t *num_b, u1024_t *num_n)
{
    u1024_t multiplier = *num_a, num_acc;
    u64 *seg = NULL;
    int i;

    TIMER_START(FUNC_NUMBER_MONTGOMERY_PRODUCT);
    number_small_dec2num(&num_acc, (u64)0);
    number_shift_left_once(&multiplier);
    for (seg = (u64 *)num_b; 
	seg < (u64 *)num_b + (BYTES_SZ(u1024_t) / BYTES_SZ(u64)); seg++)
    {
	u64 mask = (u64)1;

	while (mask)
	{
	    if (number_is_odd(&num_acc))
		number_add(&num_acc, &num_acc, num_n);
	    if (*seg & mask)
		number_add(&num_acc, &num_acc, &multiplier);
	    number_shift_right_once(&num_acc);
	    mask = mask << 1;
	}
    }

    for (i = 0; i < 3; i++)
    {
	if (number_is_odd(&num_acc))
	    number_add(&num_acc, &num_acc, num_n);
	number_shift_right_once(&num_acc);
    }

    *num_res = num_acc;
    TIMER_STOP(FUNC_NUMBER_MONTGOMERY_PRODUCT);
}

int INLINE number_montgomery_factor_set(u1024_t *num_n, u1024_t *num_factor)
{
    /* XXX timers... */
    if (number_is_equal(&num_montgomery_n, num_n))
	return 0;
    num_montgomery_n = *num_n;
    if (num_factor)
    {
	num_montgomery_factor = *num_factor;
	return 0;
    }
    else
	return number_radix(&num_montgomery_factor, num_n);
}

STATIC int INLINE number_modular_multiplication_montgomery(u1024_t *num_res, 
    u1024_t *num_a, u1024_t *num_b, u1024_t *num_n)
{
    int ret;
    u1024_t a_nresidue, b_nresidue, num_1;

    TIMER_START(FUNC_NUMBER_MODULAR_MULTIPLICATION_MONTGOMERY);
    if (number_montgomery_factor_set(num_n, NULL))
    {
	ret = -1;
	goto Exit;
    }

    number_small_dec2num(&num_1, (u64)1);
    number_montgomery_product(&a_nresidue, num_a, &num_montgomery_factor,
	num_n);
    number_montgomery_product(&b_nresidue, num_b, &num_montgomery_factor, 
	num_n);
    number_montgomery_product(num_res, &a_nresidue, &b_nresidue, num_n);
    number_montgomery_product(num_res, &num_1, num_res, num_n);
    ret = 0;

Exit:
    TIMER_STOP(FUNC_NUMBER_MODULAR_MULTIPLICATION_MONTGOMERY);
    return ret;
}

int INLINE number_modular_exponentiation_montgomery(u1024_t *res, u1024_t *a, 
    u1024_t *b, u1024_t *n)
{
    TIMER_START(FUNC_NUMBER_MODULAR_EXPONENTIATION_MONTGOMERY);
    return number_modular_exponentiation(res, a, b, n, 
	number_modular_multiplication_montgomery);
    TIMER_STOP(FUNC_NUMBER_MODULAR_EXPONENTIATION_MONTGOMERY);
}

static void INLINE number_witness_init(u1024_t *num_n_min1, u1024_t *num_u, 
    int *t)
{
    u1024_t tmp = *num_n_min1;

    TIMER_START(FUNC_NUMBER_WITNESS_INIT);
    *t = 0;
    while (!number_is_odd(&tmp))
    {
	number_shift_right_once(&tmp);
	(*t)++;
    }

    *num_u = tmp;
    TIMER_STOP(FUNC_NUMBER_WITNESS_INIT);
}

/* If number_witness(num_a, num_n) is true, then num_n is composit */
STATIC int INLINE number_witness(u1024_t *num_a, u1024_t *num_n)
{
    u1024_t num_1, num_2, num_u, num_x_prev, num_x_curr, num_n_min1;
    int i, t, ret;

    TIMER_START(FUNC_NUMBER_WITNESS);
    if (!number_is_odd(num_n))
    {
	ret = 1;
	goto Exit;
    }

    number_small_dec2num(&num_1, (u64)1);
    number_small_dec2num(&num_2, (u64)2);
    number_sub(&num_n_min1, num_n, &num_1);
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
	if (number_is_equal(&num_x_curr, &num_1) && 
	    !number_is_equal(&num_x_prev, &num_1) &&
	    !number_is_equal(&num_x_prev, &num_n_min1))
	{
	    ret = 1;
	    goto Exit;
	}
	num_x_prev = num_x_curr;
    }

    if (!number_is_equal(&num_x_curr, &num_1))
    {
	ret = 1;
	goto Exit;
    }
    ret = 0;

Exit:
    TIMER_STOP(FUNC_NUMBER_WITNESS);
    return ret;
}

/* num_n is an odd integer greater than 2 
 * return:
 * 0 - if num_n is composit
 * 1 - if num_n is almost surely prime
 */
STATIC int INLINE number_miller_rabin(u1024_t *num_n, u1024_t *num_s)
{
    int ret;
    u1024_t num_j, num_a, num_1;

    TIMER_START(FUNC_NUMBER_MILLER_RABIN);
    number_small_dec2num(&num_1, (u64)1);
    number_small_dec2num(&num_j, (u64)1);

    while (!number_is_equal(&num_j, num_s))
    {
	number_init_random_strict_range(&num_a, num_n);
	if (number_witness(&num_a, num_n))
	{
	    ret = 0;
	    goto Exit;
	}
	number_add(&num_j, &num_j, &num_1);
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
    number_small_dec2num(&num_s, (u64)10);
    ret = number_miller_rabin(num_n, &num_s);

    TIMER_STOP(FUNC_NUMBER_IS_PRIME);
    return ret;
}

static void INLINE number_small_prime_init(small_prime_entry_t *entry, 
    u1024_t *num_pi, u1024_t *num_increment)
{
    TIMER_START(FUNC_NUMBER_SMALL_PRIME_INIT);

    /* initiate the entry's prime */
    number_small_dec2num(&(entry->prime), entry->prime_initializer);

    /* initiate the entry's exponent */
    number_small_dec2num(&(entry->exp), entry->exp_initializer);

    /* rase the entry's prime to the required power */
    number_exponentiation(&(entry->power_of_prime), &(entry->prime), 
	&(entry->exp));

    /* update pi */
    number_mul(num_pi, num_pi, &(entry->power_of_prime));

    /* update incrementor*/
    number_mul(num_increment, num_increment, &(entry->prime));

    TIMER_STOP(FUNC_NUMBER_SMALL_PRIME_INIT);
}

STATIC void INLINE number_generate_coprime(u1024_t *num_coprime, 
    u1024_t *num_increment)
{
    int i;
    static u1024_t num_0, num_pi, num_mod, num_jumper;
    static int init;
    static small_prime_entry_t small_primes[] = {
	{ .prime_initializer = 2, .exp_initializer = 10 },
	{ .prime_initializer = 3, .exp_initializer = 10 },
	{ .prime_initializer = 5, .exp_initializer = 11 },
	{ .prime_initializer = 7, .exp_initializer = 11 },
	{ .prime_initializer = 11, .exp_initializer = 10 },
	{ .prime_initializer = 13, .exp_initializer = 10 },
	{ .prime_initializer = 17, .exp_initializer = 10 },
	{ .prime_initializer = 19, .exp_initializer = 10 },
	{ .prime_initializer = 23, .exp_initializer = 11 },
	{ .prime_initializer = 29, .exp_initializer = 11 },
	{ .prime_initializer = 31, .exp_initializer = 11 },
	{ .prime_initializer = 37, .exp_initializer = 11 },
	{ .prime_initializer = 41, .exp_initializer = 11 },
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
	number_small_dec2num(&num_0, (u64)0);
	number_small_dec2num(&num_pi, (u64)1);
	number_small_dec2num(num_increment, (u64)1);
	for (i = 0; i < ARRAY_SZ(small_primes); i++)
	    number_small_prime_init(&small_primes[i], &num_pi, num_increment);

	init = 1;
    }

    /* algorithm */
    number_small_dec2num(num_coprime, (u64)0);
    for (i = 0; i < ARRAY_SZ(small_primes); i++)
    {
	u1024_t num_a, num_a_pow;

	do
	{
	    number_init_random(&num_a);
	    number_modular_exponentiation_naive(&num_a_pow, &num_a,
		&(small_primes[i].exp), &num_pi);
	}
	while (number_is_equal(&num_a_pow, &num_0));
	number_add(num_coprime, num_coprime, &num_a);
    }

    number_mod(num_coprime, num_coprime, &num_pi);

    num_jumper = *num_increment;
    for (i = 0; i < ARRAY_SZ(small_primes); i++)
    {
	number_mod(&num_mod, num_coprime, &(small_primes[i].prime));
	if (number_is_equal(&num_mod, &num_0))
	{
	    number_dev(&num_jumper, &num_0, &num_jumper, 
		&(small_primes[i].prime));
	}
    }

    if (!number_is_equal(&num_jumper, num_increment))
	number_add(num_coprime, num_coprime, &num_jumper);
    TIMER_STOP(FUNC_NUMBER_GENERATE_COPRIME);
}

/* a is assumed to be >= b */
STATIC void INLINE number_extended_euclid_gcd(u1024_t *gcd, u1024_t *x, 
    u1024_t *a, u1024_t *y, u1024_t *b)
{
    u1024_t num_x, num_x1, num_x2, num_y, num_y1, num_y2, num_0;
    u1024_t num_a, num_b, num_q, num_r;
    int change;

    TIMER_START(FUNC_NUMBER_EXTENDED_EUCLID_GCD);
    if (number_is_greater_or_equal(a, b))
    {
	num_a = *a;
	num_b = *b;
	change = 0;
    }
    else
    {
	num_a = *b;
	num_b = *a;
	change = 1;
    }

    number_small_dec2num(&num_x1, (u64)0);
    number_small_dec2num(&num_x2, (u64)1);
    number_small_dec2num(&num_y1, (u64)1);
    number_small_dec2num(&num_y2, (u64)0);
    number_small_dec2num(&num_0, (u64)0);

    while (number_is_greater(&num_b, &num_0))
    {
	number_dev(&num_q, &num_r, &num_a, &num_b);

	number_mul(&num_x, &num_x1, &num_q);
	number_sub(&num_x, &num_x2, &num_x);
	number_mul(&num_y, &num_y1, &num_q);
	number_sub(&num_y, &num_y2, &num_y);

	num_a = num_b;
	num_b = num_r;
	num_x2 = num_x1;
	num_x1 = num_x;
	num_y2 = num_y1;
	num_y1 = num_y;
    }

    *x = change ? num_y2 : num_x2;
    *y = change ? num_x2 : num_y2;
    *gcd = change ? num_b : num_a;
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
    u1024_t num_1, num_gcd;

    TIMER_START(FUNC_NUMBER_INIT_RANDOM_COPRIME);
    number_small_dec2num(&num_1, (u64)1);
    do
    {
	number_init_random_strict_range(num, coprime);
	number_euclid_gcd(&num_gcd, num, coprime);
    }
    while (!number_is_equal(&num_gcd, &num_1));
    TIMER_STOP(FUNC_NUMBER_INIT_RANDOM_COPRIME);
}

void number_modular_multiplicative_inverse(u1024_t *inv, u1024_t *num, 
    u1024_t *mod)
{
    u1024_t num_x, num_y, num_gcd, num_y_abs;

    TIMER_START(FUNC_NUMBER_MODULAR_MULTIPLICATIVE_INVERSE);
    /* num < mod */
    number_extended_euclid_gcd(&num_gcd, &num_x, mod, &num_y, num);
    number_absolute_value(&num_y_abs, &num_y);
    number_mod(inv, &num_y_abs, mod);

    if (!number_is_equal(&num_y_abs, &num_y))
	number_sub(inv, mod, inv);
    TIMER_STOP(FUNC_NUMBER_MODULAR_MULTIPLICATIVE_INVERSE);
}

void number_find_prime(u1024_t *num)
{
    u1024_t num_candidate, num_1, num_increment;

    TIMER_START(FUNC_NUMBER_FIND_PRIME);
    number_small_dec2num(&num_1, (u64)1);
    number_generate_coprime(&num_candidate, &num_increment);

    while (!(number_is_prime(&num_candidate)))
    {
	number_add(&num_candidate, &num_candidate, &num_increment);

	if (number_is_equal(&num_candidate, &num_1))
	    number_generate_coprime(&num_candidate, &num_increment);
    }

    *num = num_candidate;
    TIMER_STOP(FUNC_NUMBER_FIND_PRIME);
}

