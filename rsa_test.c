#include "rsa.h"
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <sys/time.h>
#include <sys/select.h>
#include <stdlib.h>
#include <stdarg.h>
#include <math.h>

#define C_CYAN "\033[01;36m"
#define C_RED "\033[01;31m"
#define C_GREEN "\033[01;32m"
#define C_BLUE "\033[01;34m"
#define C_GREY "\033[00;37m"
#define C_NORMAL "\033[00;00;00m"
#define C_HIGHLIGHT "\033[01;38m"

#define MIN(x, y) ((x) < (y) ? (x) : (y))

/* io functionality */
typedef int (* vio_t)(const char *format, va_list ap);
int vscanf(const char *format, va_list ap);

typedef struct {
    char *description;
    char *known_issue;
    int (* func)(void);
    int disabled;
} test_t;

static int first_comment, ask_user, all_tests;
int init_reset;

static int vio_colour(vio_t vfunc, char *colour, char *fmt, va_list va)
{
    int ret;

    if (!colour)
	colour = C_NORMAL;

    ret = printf("%s", colour);
    ret += vfunc(fmt, va);
    ret += printf("%s", C_NORMAL);
    fflush(stdout);

    return ret;
}

static int p_colour(char *colour, char *fmt, ...)
{
    int ret;
    va_list va;

    va_start(va, fmt);
    vio_colour(vprintf, colour, fmt, va);
    va_end(va);

    return ret;
}

static int io_init(void)
{
    int ret = 0;

    if (first_comment)
    {
	ret = printf("\n");
	first_comment = 0;
    }

    return ret + p_colour(C_GREY, "> ");
}

static int p_comment(char *comment, ...)
{
    int ret;
    va_list va;

    ret = io_init();
    va_start(va, comment);
    ret += vio_colour(vprintf, C_GREY, comment, va);
    ret += p_colour(C_NORMAL, "\n");
    va_end(va);

    return ret;
}

static int to_vscanf(char *fmt, va_list va)
{
    fd_set fdr;
    struct timeval tv;
    int ret = 0, i, timeout = 10;

    for (i = 0; i < timeout; i++)
    {
	ret += vio_colour(vprintf, C_GREY, ".", NULL);

	tv.tv_sec = 0;
	tv.tv_usec = 500000;
	FD_ZERO(&fdr);
	FD_SET(0, &fdr);
	if (select(1, &fdr, NULL, NULL, &tv) || FD_ISSET(0, &fdr))
	    break;
    }

    return (i == timeout) ? 0 : ret + vio_colour(vscanf, C_GREY, fmt, va);
}

static int s_comment(char *comment, char *fmt, ...)
{
    int ret, scn;
    va_list va;

    ret = io_init();
    va_start(va, fmt);
    ret += vio_colour(vprintf, C_GREY, comment, NULL);
    ret += (scn = to_vscanf(fmt, va)) ? scn : printf("\n");

    va_end(va);

    return ret;
}

static char *p_u64(u64 *ptr)
{
#define BUF_SZ 65
    static char buf[BUF_SZ];
    u64 mask = ~((u64)-1 >> 1);
    int idx = 0;

    bzero(buf, BUF_SZ);
    while (mask)
    {
	buf[idx] = *ptr & mask ? '1' : '0';
	idx++;
	mask = mask >> 1;
    }

    return buf;
}

static void p_u1024(u1024_t *num)
{
    int i = sizeof(u1024_t) / sizeof(u64) - 1;
    u64 *ptr;
    u64 *last_seg = (u64 *)num + i;
    u64 *mid_seg = (u64 *)num + i/2;


    for (ptr = last_seg; ptr >= (u64 *)num; ptr--)
    {
	if (ptr == last_seg)
	    p_comment("seg buffer");
	if (ptr == mid_seg)
	    p_comment("    value");
	p_comment("%2i: %s", i, p_u64(ptr));
	i--;
    }
}

#ifdef TIME_FUNCTIONS /* function timing */
#define MAX_IO_BUF 256
#define REM(buf) (sizeof(buf) - strlen(buf))

typedef struct {
    char *name;
    int enabled;
    struct timeval hook;
    unsigned int hits;
    double time;
} func_t;

typedef struct {
    int set;
    int init;
    struct timeval start;
    struct timeval stop;
} number_timer_t;

func_t func_table[FUNC_COUNT] = {
    [ FUNC_NUMBER_RESET ] = {"number_reset", 1},
    [ FUNC_NUMBER_INIT_RANDOM ] = {"number_init_random", 1},
    [ FUNC_NUMBER_FIND_MOST_SIGNIFICANT_SET_BIT ] = 
	{"number_find_most_significant_set_bit ", 1},
    [ FUNC_NUMBER_SHIFT_LEFT_ONCE ] = {"number_shift_left_once", 1},
    [ FUNC_NUMBER_SHIFT_RIGHT_ONCE ] = {"number_shift_right_once", 1},
    [ FUNC_NUMBER_ADD ] = {"number_add", 1},
    [ FUNC_NUMBER_SMALL_DEC2NUM ] = {"func_number_small_dec2num", 1},
    [ FUNC_NUMBER_2COMPLEMENT ] = {"number_2complement", 1},
    [ FUNC_NUMBER_SUB ] = {"number_sub", 1},
    [ FUNC_NUMBER_MUL ] = {"number_mul", 1},
    [ FUNC_NUMBER_MODULAR_MULTIPLICATION_NAIVE ] = 
	{"number_modular_multiplication_naive", 1},
    [ FUNC_NUMBER_MODULAR_MULTIPLICATION_MONTGOMERY ] = 
	{"number_modular_multiplication_montgomery", 1},
    [ FUNC_NUMBER_ABSOLUTE_VALUE ] = {"number_absolute_value", 1},
    [ FUNC_NUMBER_COMPARE ] = {"number_compare", 1},
    [ FUNC_NUMBER_IS_GREATER] = {"number_is_greater", 1},
    [ FUNC_NUMBER_IS_GREATER_OR_EQUAL ] = {"number_is_greater_or_equal", 1},
    [ FUNC_NUMBER_IS_EQUAL ] = {"number_is_equal", 1},
    [ FUNC_NUMBER_DEV ] = {"number_dev", 1},
    [ FUNC_NUMBER_MOD ] = {"number_mod", 1},
    [ FUNC_NUMBER_INIT_RANDOM_STRICT_RANGE ] = 
	{"number_init_random_strict_range",  1},
    [ FUNC_NUMBER_EXPONENTIATION ] = {"number_exponentiation", 1},
    [ FUNC_NUMBER_MODULAR_EXPONENTIATION_NAIVE ] = 
	{"number_modular_exponentiation_naive", 1},
    [ FUNC_NUMBER_RADIX ] = {"number_radix", 1},
    [ FUNC_NUMBER_MONTGOMERY_PRODUCT] = {"number_montgomery_product", 1},
    [ FUNC_NUMBER_MODULAR_EXPONENTIATION_MONTGOMERY ] = 
	{"number_modular_exponentiation_montgomery", 1},
    [ FUNC_NUMBER_IS_ODD ] = {"number_is_odd", 1},
    [ FUNC_NUMBER_WITNESS_INIT ] = {"number_witness_init", 1},
    [ FUNC_NUMBER_WITNESS ] = {"number_witness", 1},
    [ FUNC_NUMBER_MILLER_RABIN ] = {"number_miller_rabin", 1},
    [ FUNC_NUMBER_IS_PRIME ] = {"number_is_prime", 1},
    [ FUNC_NUMBER_IS_PRIME1 ] = {"number_is_prime1", 1},
    [ FUNC_NUMBER_IS_PRIME2 ] = {"number_is_prime2", 1},
    [ FUNC_NUMBER_SMALL_PRIME_INIT ] = {"number_small_prime_init", 1},
    [ FUNC_NUMBER_GENERATE_COPRIME ] = {"number_generate_coprime", 1},
    [ FUNC_NUMBER_EXTENDED_EUCLID_GCD ] = {"number_extended_euclid_gcd", 1},
    [ FUNC_NUMBER_EUCLID_GCD ] = {"number_euclid_gcd", 1},
    [ FUNC_NUMBER_INIT_RANDOM_COPRIME ] = {"number_init_random_coprime", 1},
    [ FUNC_NUMBER_MODULAR_MULTIPLICATIVE_INVERSE ] = 
	{"number_modular_multiplicative_inverse", 1},
    [ FUNC_NUMBER_FIND_PRIME ] = {"number_find_prime", 1},
    [ FUNC_NUMBER_FIND_PRIME ] = {"number_find_prime", 1},
    /* TESTS */
    [ FUNC_NUMBER_SHIFT_LEFT ] = {"number_shift_left", 1},
    [ FUNC_NUMBER_SHIFT_RIGHT ] = {"number_shift_right", 1},
};

static number_timer_t timer;

inline void timer_start(func_cnt_t func)
{
    if (!func_table[func].enabled || !timer.set)
	return;

    if (!timer.init)
    {
	timer.init = 1;
	gettimeofday(&timer.start, NULL);
    }
    func_table[func].hook.tv_sec = 0;
    func_table[func].hook.tv_usec = 0;
    gettimeofday(&func_table[func].hook, NULL);
}

inline void timer_stop(func_cnt_t func)
{
    if (!func_table[func].enabled || !timer.set)
	return;
    timer.stop.tv_sec = 0;
    timer.stop.tv_usec = 0;
    gettimeofday(&timer.stop, NULL);
    func_table[func].time += ((double)(timer.stop.tv_sec - 
	func_table[func].hook.tv_sec)) + ((double)(timer.stop.tv_usec - 
	func_table[func].hook.tv_usec) / 1000000);
    func_table[func].hits++;
}

#else
static struct timeval tv1, tv2;
#endif

static inline void local_timer_start(void)
{
#ifdef TIME_FUNCTIONS
    int i;

    for (i = 0; i < FUNC_COUNT; i++)
    {
	if (!func_table[i].hits)
	    continue;
	func_table[i].hits = 0;
	func_table[i].time = 0;
    }

    timer.set = 1;
    timer.init = 0;
    timer.start.tv_sec = 0;
    timer.start.tv_usec = 0;
#else
    tv1.tv_sec = 0;
    tv1.tv_usec = 0;
    tv2.tv_sec = 0;
    tv2.tv_usec = 0;

    gettimeofday(&tv1, NULL);
#endif
}

static inline void local_timer_stop(void)
{
#ifdef TIME_FUNCTIONS
    timer.stop.tv_sec = 0;
    timer.stop.tv_usec = 0;
    gettimeofday(&timer.stop, NULL);
    timer.set = 0;
#else
    gettimeofday(&tv2, NULL);
#endif
}

static void p_local_timer(void)
{
    double total_time;
    char *fmt = "computation time: %.3lg seconds";

#ifdef TIME_FUNCTIONS
    int i;
    char buf[MAX_IO_BUF];

    total_time = (double)(timer.stop.tv_sec - timer.start.tv_sec) + 
	((double)(timer.stop.tv_usec - timer.start.tv_usec) / 1000000);
    p_comment(fmt, total_time);
    for (i = 0; i < FUNC_COUNT; i++)
    {
	char *ptr = buf;

	bzero(buf, sizeof(buf));
	if (!func_table[i].name)
	    continue;
	ptr += snprintf(ptr, REM(buf), "%s(): ", func_table[i].name);
	if (!func_table[i].enabled)
	{
	    ptr += snprintf(ptr, REM(buf), "not timed");
	    p_comment("%s", buf);
	    continue;
	}
	ptr += snprintf(ptr, REM(buf), "hits: %u", func_table[i].hits);
	if (func_table[i].hits)
	{
	    ptr += snprintf(ptr, REM(buf), ", func time: %.3lg, average cycle "
		"time: %.3lg, percentage: %.3lg", func_table[i].time, 
	    func_table[i].hits ? func_table[i].time / func_table[i].hits : -1, 
	    total_time ? (func_table[i].time / total_time) * 100 : -1);
	}
	p_comment("%s", buf);
    }
#else
    total_time = (double)(tv2.tv_sec - tv1.tv_sec) + 
	((double)(tv2.tv_usec - tv1.tv_usec) / 1000000);
    p_comment(fmt, total_time);
#endif
}

/* the tests */

static int test01(void)
{
    int u1024_sz = sizeof(u1024_t);
    int u64_sz = sizeof(u64);
    int u64_num = u1024_sz / u64_sz;

    p_comment("sizeof(u1024_t) = %d * sizeof(u64) bytes = %d * %d = %d bytes = "
	"%d bits", u64_num, u64_num, u64_sz * 8, u1024_sz, u1024_sz * 8);
    return 0;
}

static int test02(void)
{
    u1024_t a;

    return (number_init_str(&a,
	"00000000"

	"01010110"
	"01101101"
	"00011010"
	"11101011"
	"01010100"
	"01011101"
	"01010010"
	"10101010"
	"11010110"
	"01101101"
	"00011010"
	"11101011"
	"01010100"
	"01011101"
	"01010010"
	"10101010"
	)) ? -1 : 0;
}

static int test03(void)
{
#define RNDM_TBL_SZ 10000
    u1024_t number[RNDM_TBL_SZ];
    int i, j;

    for (i = 0; i < RNDM_TBL_SZ; i++)
    {
	if (number_init_random(&number[i]))
	    continue;
	for (j = 0; j < i; j++)
	{
	    if (number_is_equal(&number[j], &number[i]))
	    {
		p_comment("number[%i] == number[%i] (out of %i):", j, i, 
		    RNDM_TBL_SZ);
		p_u1024(&number[j]);
		return -1;
	    }
	}
    }

    return 0;
}

static int test04(void)
{
    u1024_t a, b, c, res;

    if (number_init_str(&a, 
	"11111111"
	"11111111"
	"11111111"
	"11101011"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	) || number_init_str(&b, 
	"1"
	) || number_init_str(&res,
	"11111111"
	"11111111"
	"11111111"
	"11101100"
	"00000000"
	"00000000"
	"00000000"
	"00000000"
	"00000000"
	"00000000"
	"00000000"
	"00000000"
	"00000000"
	"00000000"
	"00000000"
	"00000000"))
    {
	p_comment("initializing a failed");
	return -1;
    }

    local_timer_start();
    number_add(&c, &a, &b);
    local_timer_stop();
    p_local_timer();
    return !number_is_equal(&c,&res);
}

static int test05(void)
{
    u1024_t a, b, c;

    number_small_dec2num(&a, (u64)115);
    number_small_dec2num(&b, (u64)217);
    number_add(&c, &a, &b);
    return !(*(u64 *)&c == (u64)332);
}

static int test06(void)
{
    u1024_t a, b, c;

    if (number_init_random(&a) || number_init_random(&b))
    {
	p_comment("initializing a failed");
	return -1;
    }
    number_add(&c, &a, &b);
    return 0;
}

static int test07(void)
{
    u1024_t a, b, n, res;

    number_dec2bin(&res, "4294968000");
    number_dec2bin(&a, "4294960000");
    number_dec2bin(&b, "8000");
    number_add(&n, &a, &b);
    return !number_is_equal(&n, &res);
}

static int test08(void)
{
    u1024_t a, res;

    if (number_init_str(&a,
	"11000001"
	"10111100"
	"11010011"
	"01111000"
	"00001101"
	"01110111"
	"10001110"
	"00100110"
	) || number_init_str(&res,
	"00000011"
	"00000110"
	"11110011"
	"01001101"
	"11100000"
	"00110101"
	"11011110"
	"00111000"
	"10011000"
	))
    {
	p_comment("initializing a failed");
	return -1;
    }

    number_shift_left(&a, 2);
    return !number_is_equal(&a, &res);
}

static int test09(void)
{
    u1024_t a, b, res;

    if (number_init_str(&a,
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	) ||
	(number_init_random(&b)) ||
	(number_init_str(&res,
	"00000001"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111110")))
    {
	p_comment("initializing a failed");
	return -1;
    }
    number_shift_left(&a, 1);
    number_shift_left(&b, 3);
    return !(*(u64*)&a == *(u64*)&res);
}

static int test10(void)
{
    u1024_t a, b, c, res;

    if (number_init_str(&a, 
	"1101"
	) || number_init_str(&b, 
	"101"
	) || number_init_str(&res,
	"01000001"
	))
    {
	p_comment("initializing a or b failed");
	return -1;
    }

    number_mul(&c, &a, &b);
    return !number_is_equal(&c, &res);
}

static int test11(void)
{
    u1024_t a, b, c, res;

    if (number_init_str(&a, 
	"1101"
	) || number_init_str(&b, 
	"101101"
	) || number_init_str(&res,
	"1001001001"))
    {
	p_comment("initializing a or b failed");
	return -1;
    }

    local_timer_start();
    number_mul(&c, &a, &b);
    local_timer_stop();
    p_local_timer();
    return !number_is_equal(&c, &res);
}

static int test12(void)
{
    u1024_t a, b, c, res;

    if (number_init_str(&a, 
	"11000001"
	"10111100"
	"11010011"
	"01111000"
	"00001101"
	"01110111"
	"10001110"
	"00100110"
	) || number_init_str(&b, 
	"11000001"
	"10111100"
	"11010011"
	"01111000"
	"00001101"
	"01110111"
	"10001110"
	"00100110"
	) || number_init_str(&res,
	"10010010"
	"10011110"
	"01000010"
	"00100010"
	"01001011"
	"01010001"
	"00101010"
	"01101101"
	"11001000"
	"11101101"
	"01000011"
	"11100101"
	"01010010"
	"01000010"
	"00101101"
	"10100100"
	))
    {
	p_comment("initializing numbers failed");
	return -1;
    }

    number_mul(&c, &a, &b);
    return !number_is_equal(&c, &res);
}

static int test13(void)
{
    u1024_t a, res;

    number_init_str(&res,
	"00001110"
	"00000011"
	"01100000"
	"10010000");
    number_dec2bin(&a, "00235102352");
    return !number_is_equal(&a, &res);
}

static int test14(void)
{
    u1024_t a, b, res1, res2;

    number_init_str(&res1,
	"11111111"
	);
    number_init_str(&res2,
	"00000001"
	"00000000"
	);

    number_dec2bin(&a, "255");
    number_dec2bin(&b, "256");
    return !(number_is_equal(&a, &res1) && number_is_equal(&b, &res2));
}

static int test15(void)
{
    u1024_t a, res;
    char str[256];

    number_init_str(&res,
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	);
    memset(str, 0, 256);
    snprintf(str, 256, "%llu", 18446744073709551615ULL);

    number_dec2bin(&a, str);
    return !number_is_equal(&a, &res);
}

static int test16(void)
{
    u1024_t a, b, res1, res2;

    number_init_str(&res1,
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	);
    number_init_str(&res2,
	"00000001"
	"00000000"
	"00000000"
	"00000000"
	"00000000"
	"00000000"
	"00000000"
	"00000000"
	"00000000"
	);

    number_dec2bin(&a, "18446744073709551615");
    number_dec2bin(&b, "18446744073709551616");
    return !(number_is_equal(&a, &res1) && number_is_equal(&b, &res2));
}

static int test17(void)
{
    u1024_t a, res;

    if (number_init_str(&a,
	"11010110"
	"01101101"
	"00011010"
	"11101011"
	"01010100"
	"01011101"
	"01010010"
	"10101010"
	"11010110"
	"01101101"
	"00011010"
	"11101011"
	"01010100"
	"01011101"
	"01010010"
	"10101010"
	) || number_init_str(&res,
	"01101011"
	"00110110"
	"10001101"
	"01110101"
	"10101010"
	"00101110"
	"10101001"
	"01010101"
	"01101011"
	"00110110"
	"10001101"
	"01110101"
	"10101010"
	"00101110"
	"10101001"
	"01010101"
	))
    {
	printf("initializing a failed\n");
	return -1;
    }
    number_shift_right(&a, 1);
    return !number_is_equal(&a, &res);
}

static int test18(void)
{
    u1024_t a;
    u64 *seg, mask, tmp, *res_seg, res_mask = 1;
    int i;
    char *str_a =
	"00010100"
	"01011101"
	"01010010"
	"10101010"
	"11010110"
	"01101101"
	"00011010"
	"11101011"
	"01010100"
	"01011101"
	"01010010"
	"10101010";

    if (number_init_str(&a, str_a))
    {
	printf("initializing a failed\n");
	return -1;
    }
    res_seg = (u64 *)&a + (u64)((strlen(str_a) - 1) / (sizeof(u64) * 8));
    tmp = *res_seg;
    for (i = 0; i < sizeof(u64) * 8; i++)
    {
	if (tmp & ~((u64)-1 >> i))
	    break;
    }
    res_mask = pow(2, sizeof(u64) * 8 - i);
    number_find_most_significant_set_bit(&a, &seg, &mask);

    return !(seg == res_seg && mask == res_mask);
}


static int test19(void)
{
    u1024_t a;
    u64 *seg, mask, *res_seg, res_mask;

    res_seg = (u64 *)&a + 1;
    res_mask = (u64)268435456;
    if (number_init_str(&a,
	"00010100"
	"01011101"
	"01010010"
	"10101010"
	"11010110"
	"01101101"
	"00011010"
	"11101011"
	"01010100"
	"01011101"
	"01010010"
	"10101010"
	))
    {
	printf("initializing a failed\n");
	return -1;
    }
    number_find_most_significant_set_bit(&a, &seg, &mask);
    return !(seg == res_seg && mask == res_mask);
}

static int test20(void)
{
    u1024_t a, b, n, res, test_res;

    number_dec2bin(&test_res, "2");
    number_dec2bin(&a, "3");
    number_dec2bin(&b, "2");
    number_dec2bin(&n, "4");
    number_modular_multiplication_naive(&res, &a, &b, &n);
    return !number_is_equal(&res, &test_res);
}

static int test21(void)
{
    u1024_t a, b, c, res;

    if (number_init_str(&a, 
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	) || number_init_str(&b, 
	"1") || number_init_str(&res,
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111111"
	"11111110"
	))
    {
	printf("initializing a or b failed\n");
	return -1;
    }

    number_sub(&c, &a, &b);
    return !number_is_equal(&c, &res);
}

static int test22(void)
{
    u1024_t a, b, c, res;

    if (number_init_str(&a, 
	"1000100011" /* 547 */
	) || number_init_str(&b, 
	"11111100" /* 252 */
	) || number_init_str(&res,
	"100100111"
	))
    {
	printf("initializing a or b failed\n");
	return -1;
    }

    number_sub(&c, &a, &b);
    return !number_is_equal(&c, &res);
}

static int test23(void)
{
    u1024_t a, b, q, r, res_q, res_r;

    if (number_init_str(&a, "100") || /* 4 */
	number_init_str(&b, "10") ||/* 2 */
	number_init_str(&res_q, "10") ||
	number_init_str(&res_r, "0"))
    {
	printf("initializing a or b failed\n");
	return -1;
    }

    number_dev(&q, &r, &a, &b);
    return !(number_is_equal(&q, &res_q) && number_is_equal(&r, &res_r));
}

static int test24(void)
{
    u1024_t a, b, q, r, res_q, res_r;

    if (number_init_str(&a, "1000100011") || /* 547 */
	number_init_str(&b, "11111100") || /* 252 */
	number_init_str(&res_q, "10") ||
	number_init_str(&res_r, "101011"))
    {
	printf("initializing a or b failed\n");
	return -1;
    }

    number_dev(&q, &r, &a, &b);
    return !(number_is_equal(&q, &res_q) && number_is_equal(&r, &res_r));
}

static int test25(void)
{
    u1024_t r, a, b, n, res;

    if (number_dec2bin(&a, "3") || number_dec2bin(&b, "3"), 
	number_dec2bin(&n, "7") || number_dec2bin(&res, "6"))
    {
	printf("initializing a, b or n failed\n");
	return -1;
    }

    number_modular_exponentiation_naive(&r, &a, &b, &n);
    return !number_is_equal(&r, &res);
}

static int test26(void)
{
    u1024_t r, a, b, n, res;

    if (number_dec2bin(&a, "289") || number_dec2bin(&b, "276"), 
	number_dec2bin(&n, "258") || number_dec2bin(&res, "121"))
    {
	printf("initializing a, b or n failed\n");
	return -1;
    }

    number_modular_exponentiation_naive(&r, &a, &b, &n);
    return !number_is_equal(&r, &res);
}

static int test27(void)
{
    u1024_t a, n;

    if (number_dec2bin(&a, "2") || number_dec2bin(&n, "5"))
    {
	printf("initializing a, n failed\n");
	return -1;
    }

    return number_witness(&a, &n);
}

static int test28(void)
{
    u1024_t num_n;
    char str[5];
    int i = 3;

	snprintf(str, 5, "%i", i);
	number_dec2bin(&num_n, str);
    return !number_is_prime(&num_n);
}

static int test29(void)
{
    u1024_t n;
    char *dec = "99991";

    number_dec2bin(&n, dec);
    return !number_is_prime(&n);
}

static int test30(void)
{
    int i;
    static int arr[1000] =
    {
	[3] = 1, [5] = 1, [7] = 1, [11] = 1, [13] = 1, [17] = 1, [19] = 1,
	[23] = 1, [29] = 1, [31] = 1, [37] = 1, [41] = 1, [43] = 1, [47] = 1,
	[53] = 1, [59] = 1, [61] = 1, [67] = 1, [71] = 1, [73] = 1, [79] = 1,
	[83] = 1, [89] = 1, [97] = 1, [101] = 1, [103] = 1, [107] = 1,
	[109] = 1, [113] = 1, [127] = 1, [131] = 1, [137] = 1, [139] = 1, 
	[149] = 1, [151] = 1, [157] = 1, [163] = 1, [167] = 1, [173] = 1, 
	[179] = 1, [181] = 1, [191] = 1, [193] = 1, [197] = 1, [199] = 1, 
	[211] = 1, [223] = 1, [227] = 1, [229] = 1, [233] = 1, [239] = 1, 
	[241] = 1, [251] = 1, [257] = 1, [263] = 1, [269] = 1, [271] = 1, 
	[277] = 1, [281] = 1, [283] = 1, [293] = 1, [307] = 1, [311] = 1, 
	[313] = 1, [317] = 1, [331] = 1, [337] = 1, [347] = 1, [349] = 1, 
	[353] = 1, [359] = 1, [367] = 1, [373] = 1, [379] = 1, [383] = 1,
	[389] = 1, [397] = 1, [401] = 1, [409] = 1, [419] = 1, [421] = 1,
	[431] = 1, [433] = 1, [439] = 1, [443] = 1, [449] = 1, [457] = 1,
	[461] = 1, [463] = 1, [467] = 1, [479] = 1, [487] = 1, [491] = 1,
	[499] = 1, [503] = 1, [509] = 1, [521] = 1, [523] = 1, [541] = 1,
	[547] = 1, [557] = 1, [563] = 1, [569] = 1, [571] = 1, [577] = 1,
	[587] = 1, [593] = 1, [599] = 1, [601] = 1, [607] = 1, [613] = 1,
	[617] = 1, [619] = 1, [631] = 1, [641] = 1, [643] = 1, [647] = 1,
	[653] = 1, [659] = 1, [661] = 1, [673] = 1, [677] = 1, [683] = 1,
	[691] = 1, [701] = 1, [709] = 1, [719] = 1, [727] = 1, [733] = 1,
	[739] = 1, [743] = 1, [751] = 1, [757] = 1, [761] = 1, [769] = 1,
	[773] = 1, [787] = 1, [797] = 1, [809] = 1, [811] = 1, [821] = 1,
	[823] = 1, [827] = 1, [829] = 1, [839] = 1, [853] = 1, [857] = 1,
	[859] = 1, [863] = 1, [877] = 1, [881] = 1, [883] = 1, [887] = 1,
	[907] = 1, [911] = 1, [919] = 1, [929] = 1, [937] = 1, [941] = 1,
	[947] = 1, [953] = 1, [967] = 1, [971] = 1, [977] = 1, [983] = 1,
	[991] = 1, [997] = 1,
    };

    for (i = 3; i < 1000; i++)
    
    {
	u1024_t num_n;
	char str_num[5];

	if (i == 3 || !(i % 100))
	    p_comment("testing in [%i, %i]...", i, i == 3 ? 99 : (i + 99));
	memset(str_num, 0, sizeof(str_num));
	sprintf(str_num, "%i", i);
	number_dec2bin(&num_n, str_num);
	if (number_is_prime(&num_n) != arr[i])
	{
	    p_comment("%i is %sprime and was found to be %sprime", i,
		arr[i] ? "" : "non ", arr[i] ? "non " : "");
	    return -1;
	}
    }
    return 0;
}

static int test31(void)
{
    u1024_t num_n;
    char *prime = "10726904659";
    int is_prime;

    number_dec2bin(&num_n, "10726904659");
    p_comment("%s is %sprime", prime, is_prime ? "" : "not ");
    return !is_prime;
}

static int test32(void)
{
    u1024_t num_n;
    char *prime = "55350776431903243";
    int is_prime;

    number_dec2bin(&num_n, prime);
    is_prime = number_is_prime(&num_n);
    p_comment("%s is %sprime", prime, is_prime ? "" : "not ");
    return !is_prime;
}

static int test33(void)
{
    u1024_t num_n;
    char prime[143];
    int i, is_prime;

    for (i = 0; i < 71*2; i = i + 2)
    {
	prime[i] = '9';
	prime[i + 1] = '4';
    }
    prime[142] = '9';
    prime[143] = 0;

    /* 475 bits */
    number_dec2bin(&num_n, prime);
    local_timer_start();
    is_prime = number_is_prime(&num_n);
    local_timer_stop();
    p_comment("94R(71)9 is %sprime", is_prime ? "" : "not ");
    p_local_timer();
    return !is_prime;
}

static int test34(void)
{
    u1024_t num_n;
    char *non_prime = "2285760293497823444790323455592340983477";
    int is_prime;

    number_dec2bin(&num_n, non_prime);
    is_prime = number_is_prime(&num_n);
    p_comment("%s is %sprime", non_prime, is_prime ? "" : "not ");
    return is_prime;
}

static int test35(void)
{
    u1024_t num_n;

    p_comment("finding a large prime...");
    local_timer_start();
    number_find_prime(&num_n);
    local_timer_stop();
    p_u1024(&num_n);
    p_local_timer();
    return 0;
}

static int test36(void)
{
    u1024_t num_n, num_m, res;

    number_small_dec2num(&num_n, 163);
    number_small_dec2num(&res, 88);
    number_radix(&num_m, &num_n);
    return !number_is_equal(&num_m, &res);
}

static int test37(void)
{
    u1024_t num_n, num_res;

    number_init_random(&num_n);
    return number_radix(&num_res, &num_n);
}

static int test38(void)
{
    u1024_t num_n, num_base, num_exp, num_res, res;
    u64 r, n, base, exp;

#ifdef UCHAR
    /* disabled: u64 values greater than 255 are truncated by the compiler */
    r = n = base = exp = 0;
#else
    r = 143;
    n = 163;
    base = 2;
    exp = 260;
#endif


    number_small_dec2num(&res, r);
    number_small_dec2num(&num_n, n);
    number_small_dec2num(&num_base, base);
    number_small_dec2num(&num_exp, exp);
    number_modular_exponentiation_naive(&num_res, &num_base, &num_exp, &num_n);
    return !number_is_equal(&num_res, &res);
}

static int test39(void)
{
    u1024_t num_93, num_64, num_163, num_134, num_16, num_25, res;

    number_small_dec2num(&res, (u64)25);
    number_small_dec2num(&num_93, (u64)93);
    number_small_dec2num(&num_64, (u64)64);
    number_small_dec2num(&num_163, (u64)163);
    number_small_dec2num(&num_16, (u64)16);

    number_modular_exponentiation_naive(&num_134, &num_93, &num_64, &num_163);
    number_modular_multiplication_naive(&num_25, &num_134, &num_16, &num_163);
    return !number_is_equal(&num_25, &res);
}

/* compile: TESTS=y U64=ULLONG */
static int test40(void)
{
    u1024_t num_1, num_2, num_516, num_9, res;

    number_small_dec2num(&res, (u64)1);
    number_small_dec2num(&num_2, (u64)2);
    number_small_dec2num(&num_516, (u64)516);
    number_small_dec2num(&num_9, (u64)9);

    number_modular_exponentiation_naive(&num_1, &num_2, &num_516, &num_9);
    return !number_is_equal(&num_1, &res);
}

static int test41(void)
{
    u1024_t num_4, num_5, num_8, num_9, res;

    number_small_dec2num(&res, (u64)4);
    number_small_dec2num(&num_5, (u64)5);
    number_small_dec2num(&num_8, (u64)8);
    number_small_dec2num(&num_9, (u64)9);
    number_modular_multiplication_montgomery(&num_4, &num_5, &num_8, &num_9);
    return !number_is_equal(&num_4, &res);
}

static int test42(void)
{
    u1024_t num_45, num_594, num_1019, num_117, res;

    number_small_dec2num(&res, (u64)45);
    number_small_dec2num(&num_594, (u64)594);
    number_small_dec2num(&num_1019, (u64)1019);
    number_small_dec2num(&num_117, (u64)117);
    number_modular_multiplication_montgomery(&num_45, &num_594, &num_1019, 
	&num_117);
    return !number_is_equal(&num_45, &res);
}

static int test43(void)
{
    u1024_t num_n, num_29, num_res, num_rem, res;
    char prime[144];
    int i;

    number_init_str(&res, 
	"0000000000000000000000000000000000000000010001001011110000011011"
	"1101100101111111010101101100000110111111010110111000110010000010"
	"1000000101001100100111001101110010001010111011011010111111110001"
	"1110110001101110001111000100010111010111110010110010010110101011"
	"0011100101100111000110110001001111101010101101000000010100010111"
	"0101101010001100010011010000011110111110001111001011011010000110"
	"1010010010011010011100000010110000111010001000110010000111001011"
	"0110010000100010100110001101010101001001111010110111110111010000"
	);

    for (i = 0; i < 142; i = i + 2)
    {
	prime[i] = '9';
	prime[i + 1] = '4';
    }
    prime[142] = '9';
    prime[143] = 0;

    /* 475 bits */
    number_dec2bin(&num_n, prime);
    number_small_dec2num(&num_29, (u64)29);
    local_timer_start();
    number_dev(&num_res, &num_rem, &num_n, &num_29);
    local_timer_stop();
    p_local_timer();
    return !(number_is_equal(&num_res, &res));
}

static int test44(void)
{
    u1024_t num_2, num_3, num_5, num_7, num_11, num_13, num_17, num_19, 
	num_23, num_29, num_31, num_37, num_41;
    u1024_t num_res, num_a, num_a_pow2, num_a_pow10, num_b, res;

    number_init_str(&res, 
	"1000111001111001000111110001111101010000101001100010111011110011"
	"1000010110001101111101011010001011100011011010011100010001010110"
	"0101001110011011011100000001111101001101011001010110010100101100"
	"1011101010110110110101010000100110101100001000100110010110010110"
	"0110010110010010111111111001101100101110100100001011010000010010"
	"1000100000100000001111001011101011110111001011100000110011001110"
	"1000100000100000111111000000101111110110100011011110000010100010"
	"1010010000101100111001000000000000010000010010100010110000000000"
	);

    number_small_dec2num(&num_a, (u64)1);
    number_small_dec2num(&num_b, (u64)1);
    number_small_dec2num(&num_2, (u64)2);
    number_small_dec2num(&num_3, (u64)3);
    number_small_dec2num(&num_5, (u64)5);
    number_small_dec2num(&num_7, (u64)7);
    number_small_dec2num(&num_11, (u64)11);
    number_small_dec2num(&num_13, (u64)13);
    number_small_dec2num(&num_17, (u64)17);
    number_small_dec2num(&num_19, (u64)19);
    number_small_dec2num(&num_23, (u64)23);
    number_small_dec2num(&num_29, (u64)29);
    number_small_dec2num(&num_31, (u64)31);
    number_small_dec2num(&num_37, (u64)37);
    number_small_dec2num(&num_41, (u64)41);

    number_mul(&num_a, &num_a, &num_2);
    number_mul(&num_a, &num_a, &num_3);
    number_mul(&num_a, &num_a, &num_11);
    number_mul(&num_a, &num_a, &num_13);
    number_mul(&num_a, &num_a, &num_17);
    number_mul(&num_a, &num_a, &num_19);

    number_mul(&num_b, &num_b, &num_5);
    number_mul(&num_b, &num_b, &num_7);
    number_mul(&num_b, &num_b, &num_23);
    number_mul(&num_b, &num_b, &num_29);
    number_mul(&num_b, &num_b, &num_31);
    number_mul(&num_b, &num_b, &num_37);
    number_mul(&num_b, &num_b, &num_41);

    number_mul(&num_a, &num_a, &num_b);

    number_mul(&num_a_pow2, &num_a, &num_a);
    number_mul(&num_a_pow10, &num_a_pow2, &num_a_pow2);
    number_mul(&num_a_pow10, &num_a_pow10, &num_a_pow10);
    number_mul(&num_a_pow10, &num_a_pow10, &num_a_pow2);

    number_mul(&num_res, &num_a_pow10, &num_b);

    return !number_is_equal(&num_res, &res);
}

static int test45(void)
{
    u1024_t num_a, num_b, res;
    int i;
    static u64 first_1000_primes[1000] = 
    {
	2, 3, 5, 7, /* <-- 4th prime */ 11, 13, 17, 19, 23, 29,
	31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
	73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
	127, 131, 137, 139, 149, 151, 157, 163, 167, 173,
	179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
#ifndef UCHAR
	233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
	283, 293, 307, 311, 313, 317, 331, 337, 347, 349,
	353, 359, 367, 373, 379, /* <-- 75th prime */ 383, 389, 397, 401, 409,
	419, 421, 431, 433, 439, 443, 449, 457, 461, 463,
	467, 479, 487, 491, 499, 503, 509, 521, 523, 541,
	547, 557, 563, 569, 571, 577, 587, 593, 599, 601,
	607, 613, 617, 619, 631, 641, 643, 647, 653, 659,
	661, 673, 677, 683, 691, 701, 709, 719, 727, 733,
	739, 743, 751, 757, 761, 769, 773, 787, 797, 809,
	811, 821, 823, 827, 829, 839, 853, 857, 859, 863,
	877, 881, 883, 887, 907, 911, 919, 929, 937, 941,
	947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013,
	1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069,
	1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151,
	1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223,
	1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283, 1289, 1291,
	1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373,
	1381, 1399, 1409, 1423, 1427, 1429, 1433, 1439, 1447, 1451,
	1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511,
	1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583,
	1597, 1601, 1607, 1609, 1613, 1619, 1621, 1627, 1637, 1657,
	1663, 1667, 1669, 1693, 1697, 1699, 1709, 1721, 1723, 1733,
	1741, 1747, 1753, 1759, 1777, 1783, 1787, 1789, 1801, 1811,
	1823, 1831, 1847, 1861, 1867, 1871, 1873, 1877, 1879, 1889,
	1901, 1907, 1913, 1931, 1933, 1949, 1951, 1973, 1979, 1987,
	1993, 1997, 1999, 2003, 2011, 2017, 2027, 2029, 2039, 2053,
	2063, 2069, 2081, 2083, 2087, 2089, 2099, 2111, 2113, 2129,
	2131, 2137, 2141, 2143, 2153, 2161, 2179, 2203, 2207, 2213,
	2221, 2237, 2239, 2243, 2251, 2267, 2269, 2273, 2281, 2287,
	2293, 2297, 2309, 2311, 2333, 2339, 2341, 2347, 2351, 2357,
	2371, 2377, 2381, 2383, 2389, 2393, 2399, 2411, 2417, 2423,
	2437, 2441, 2447, 2459, 2467, 2473, 2477, 2503, 2521, 2531,
	2539, 2543, 2549, 2551, 2557, 2579, 2591, 2593, 2609, 2617,
	2621, 2633, 2647, 2657, 2659, 2663, 2671, 2677, 2683, 2687,
	2689, 2693, 2699, 2707, 2711, 2713, 2719, 2729, 2731, 2741,
	2749, 2753, 2767, 2777, 2789, 2791, 2797, 2801, 2803, 2819,
	2833, 2837, 2843, 2851, 2857, 2861, 2879, 2887, 2897, 2903,
	2909, 2917, 2927, 2939, 2953, 2957, 2963, 2969, 2971, 2999,
	3001, 3011, 3019, 3023, 3037, 3041, 3049, 3061, 3067, 3079,
	3083, 3089, 3109, 3119, 3121, 3137, 3163, 3167, 3169, 3181,
	3187, 3191, 3203, 3209, 3217, 3221, 3229, 3251, 3253, 3257,
	3259, 3271, 3299, 3301, 3307, 3313, 3319, 3323, 3329, 3331,
	3343, 3347, 3359, 3361, 3371, 3373, 3389, 3391, 3407, 3413,
	3433, 3449, 3457, 3461, 3463, 3467, 3469, 3491, 3499, 3511,
	3517, 3527, 3529, 3533, 3539, 3541, 3547, 3557, 3559, 3571,
	3581, 3583, 3593, 3607, 3613, 3617, 3623, 3631, 3637, 3643,
	3659, 3671, 3673, 3677, 3691, 3697, 3701, 3709, 3719, 3727,
	3733, 3739, 3761, 3767, 3769, 3779, 3793, 3797, 3803, 3821,
	3823, 3833, 3847, 3851, 3853, 3863, 3877, 3881, 3889, 3907,
	3911, 3917, 3919, 3923, 3929, 3931, 3943, 3947, 3967, 3989,
	4001, 4003, 4007, 4013, 4019, 4021, 4027, 4049, 4051, 4057,
	4073, 4079, 4091, 4093, 4099, 4111, 4127, 4129, 4133, 4139,
	4153, 4157, 4159, 4177, 4201, 4211, 4217, 4219, 4229, 4231,
	4241, 4243, 4253, 4259, 4261, 4271, 4273, 4283, 4289, 4297,
	4327, 4337, 4339, 4349, 4357, 4363, 4373, 4391, 4397, 4409,
	4421, 4423, 4441, 4447, 4451, 4457, 4463, 4481, 4483, 4493,
	4507, 4513, 4517, 4519, 4523, 4547, 4549, 4561, 4567, 4583,
	4591, 4597, 4603, 4621, 4637, 4639, 4643, 4649, 4651, 4657,
	4663, 4673, 4679, 4691, 4703, 4721, 4723, 4729, 4733, 4751,
	4759, 4783, 4787, 4789, 4793, 4799, 4801, 4813, 4817, 4831,
	4861, 4871, 4877, 4889, 4903, 4909, 4919, 4931, 4933, 4937,
	4943, 4951, 4957, 4967, 4969, 4973, 4987, 4993, 4999, 5003,
	5009, 5011, 5021, 5023, 5039, 5051, 5059, 5077, 5081, 5087,
	5099, 5101, 5107, 5113, 5119, 5147, 5153, 5167, 5171, 5179,
	5189, 5197, 5209, 5227, 5231, 5233, 5237, 5261, 5273, 5279,
	5281, 5297, 5303, 5309, 5323, 5333, 5347, 5351, 5381, 5387,
	5393, 5399, 5407, 5413, 5417, 5419, 5431, 5437, 5441, 5443,
	5449, 5471, 5477, 5479, 5483, 5501, 5503, 5507, 5519, 5521,
	5527, 5531, 5557, 5563, 5569, 5573, 5581, 5591, 5623, 5639,
	5641, 5647, 5651, 5653, 5657, 5659, 5669, 5683, 5689, 5693,
	5701, 5711, 5717, 5737, 5741, 5743, 5749, 5779, 5783, 5791,
	5801, 5807, 5813, 5821, 5827, 5839, 5843, 5849, 5851, 5857,
	5861, 5867, 5869, 5879, 5881, 5897, 5903, 5923, 5927, 5939,
	5953, 5981, 5987, 6007, 6011, 6029, 6037, 6043, 6047, 6053,
	6067, 6073, 6079, 6089, 6091, 6101, 6113, 6121, 6131, 6133,
	6143, 6151, 6163, 6173, 6197, 6199, 6203, 6211, 6217, 6221,
	6229, 6247, 6257, 6263, 6269, 6271, 6277, 6287, 6299, 6301,
	6311, 6317, 6323, 6329, 6337, 6343, 6353, 6359, 6361, 6367,
	6373, 6379, 6389, 6397, 6421, 6427, 6449, 6451, 6469, 6473,
	6481, 6491, 6521, 6529, 6547, 6551, 6553, 6563, 6569, 6571,
	6577, 6581, 6599, 6607, 6619, 6637, 6653, 6659, 6661, 6673,
	6679, 6689, 6691, 6701, 6703, 6709, 6719, 6733, 6737, 6761,
	6763, 6779, 6781, 6791, 6793, 6803, 6823, 6827, 6829, 6833,
	6841, 6857, 6863, 6869, 6871, 6883, 6899, 6907, 6911, 6917,
	6947, 6949, 6959, 6961, 6967, 6971, 6977, 6983, 6991, 6997,
	7001, 7013, 7019, 7027, 7039, 7043, 7057, 7069, 7079, 7103,
	7109, 7121, 7127, 7129, 7151, 7159, 7177, 7187, 7193, 7207,
	7211, 7213, 7219, 7229, 7237, 7243, 7247, 7253, 7283, 7297,
	7307, 7309, 7321, 7331, 7333, 7349, 7351, 7369, 7393, 7411,
	7417, 7433, 7451, 7457, 7459, 7477, 7481, 7487, 7489, 7499,
	7507, 7517, 7523, 7529, 7537, 7541, 7547, 7549, 7559, 7561,
	7573, 7577, 7583, 7589, 7591, 7603, 7607, 7621, 7639, 7643,
	7649, 7669, 7673, 7681, 7687, 7691, 7699, 7703, 7717, 7723,
	7727, 7741, 7753, 7757, 7759, 7789, 7793, 7817, 7823, 7829,
	7841, 7853, 7867, 7873, 7877, 7879, 7883, 7901, 7907, 7919,
#endif
    };

    number_init_str(&res, 
	"1110010111010101010010111100000001110111111000011011001000001101"
	"1010011100010001010010100011101011010001101100110010100010110010"
	"0110100011101110101101000010110111110001101001111100001001101000"
	"1001011111110110101101101101110000110110101100001111010101100011"
	"1110110101011111101011110100110100100100101100010011100001001100"
	"0001000100100011110110001110011100000000110011111010001010000000"
	"1011100011101111000111000100100000110111111100111101101001010000"
	"1100001011110100111101001100000010000110101010101011111111010010"
	);

    number_small_dec2num(&num_a, (u64)1);
    for (i = 0; i < 75; i++)
    {
	number_small_dec2num(&num_b, first_1000_primes[i]);
	number_mul(&num_a, &num_a, &num_b);
    }
    number_small_dec2num(&num_b, (u64)7);
	number_mul(&num_a, &num_a, &num_b);

    return !number_is_equal(&num_a, &res);
}

static int test46(void)
{
#define NUM_P "num_p"
#define NUM_INC "num_inc"

    u1024_t num_p, num_inc, num_mod1, num_mod2, num_0, num_1;
    u1024_t num_primes[13];
    u64 primes[13] = {(u64)2, (u64)3, (u64)5, (u64)7, (u64)11, (u64)13, 
	(u64)17, (u64)19, (u64)23, (u64)29, (u64)31, (u64)37, (u64)41};
    int i, res = 0;

    number_small_dec2num(&num_0, (u64)0);
    number_small_dec2num(&num_1, (u64)1);

    /* initiate u1024_t primes */
    for (i = 0; i < 13; i++)
	number_small_dec2num(&num_primes[i], primes[i]);
    number_generate_coprime(&num_p, &num_inc);

    p_comment(NUM_P":");
    p_u1024(&num_p);
    p_comment(NUM_INC":");
    p_u1024(&num_inc);

    for (i = 0; i < 13; i++)
    {
	int res_num_p;
	int res_num_inc;

	number_mod(&num_mod1, &num_p, &num_primes[i]);
	number_mod(&num_mod2, &num_inc, &num_primes[i]);

	res_num_p = number_is_equal(&num_mod1, &num_0);
	res_num_inc = number_is_equal(&num_mod2, &num_0);

	if (res_num_p || !res_num_inc)
	    res = 1;

	p_comment("coprime("NUM_P", %llu) = %s, coprime("NUM_INC", %llu) = "
	    "%s", primes[i], res_num_p ? "no" : "yes", primes[i], res_num_inc ? 
	    " no" : "yes");
    }
    return res;

#undef NUM_P
#undef NUM_INC
}

static int test47(void)
{
    u1024_t num_0, num_big1, num_big2, num_5, num_mod1, num_mod2;
    int res1, res2;
    char *big_num1_str = "10098841051971095635";
    char *big_num2_str = "6788835914016483306";

    number_small_dec2num(&num_0, (u64)0);
    number_small_dec2num(&num_5, (u64)5);
    number_dec2bin(&num_big1, big_num1_str);
    number_dec2bin(&num_big2, big_num2_str);

    number_mod(&num_mod1, &num_big1, &num_5);
    number_mod(&num_mod2, &num_big2, &num_5);

    res1 = number_is_equal(&num_mod1, &num_0);
    res2 = number_is_equal(&num_mod2, &num_0);

    p_comment("coprime(%s, 5) = %s", big_num1_str, res1 ? "no" : "yes");
    p_comment("coprime(%s, 5) = %s", big_num2_str, res2 ? "no" : "yes");

    return !(res1 && !res2);
}

static int test48(void)
{
    u1024_t num_0, num_1, num_4, num_x, num_res;
    
    number_small_dec2num(&num_0, (u64)0);
    number_small_dec2num(&num_1, (u64)1);
    number_small_dec2num(&num_4, (u64)4);
    number_small_dec2num(&num_res, (u64)5);

    number_sub(&num_x, &num_0, &num_4);
    number_sub(&num_x, &num_1, &num_x);

    return !number_is_equal(&num_x, &num_res);
}

static int test53(void)
{
    u1024_t a, b, n, axb, num_1;
    u64 i, prime = 13;

    number_small_dec2num(&num_1, (u64)1);
    number_small_dec2num(&n, (u64)prime);

    for (i = (u64)1; i < (u64)prime; i++)
    {
	number_small_dec2num(&a, (u64)i);
	number_modular_multiplicative_inverse(&b, &a, &n);
	number_mul(&axb, &a, &b);
	number_mod(&axb, &axb, &n);
	p_comment("%2.llu^(-1)mod(%llu) = %2.llu, %2.llux%llu mod(%llu) "
	    "= %llu", *(u64 *)&a, prime, *(u64 *)&b, *(u64 *)&a, *(u64 *)&b, 
	    prime, *(u64 *)&axb);
	if (!number_is_equal(&axb, &num_1))
	    return -1;
    }
    return 0;
}

static int test54(void)
{
    u1024_t num_a, num_abs, num_5;

    number_small_dec2num(&num_5, (u64)5);
    number_small_dec2num(&num_a, (u64)0);

    number_sub(&num_a, &num_a, &num_5); /* a = -5 */
    number_absolute_value(&num_abs, &num_a); /* |a| = 5 */

    return !(number_is_equal(&num_abs, &num_5));
}

static int test55(void)
{
#define PRIME 11

#if defined USHORT
#define FMT_SZ "%hu"
#elif defined ULONG
#define FMT_SZ "%lu"
#else
#define FMT_SZ "%llu"
#endif

    u1024_t x, a, y, b, d, xa, yb, sum, abs_y, mod_y;
    u64 i, cnt[PRIME], ret = 0;

    bzero(cnt, sizeof(cnt));
    number_small_dec2num(&a, (u64)PRIME);
    for (i = 1; i < PRIME; i++)
    {
	u1024_t tmp_x;
	u64 *res_gcd = (u64*)&d;
	u64 *res_sum = (u64*)&sum;
	u64 *mod_y_res = (u64*)&mod_y;

	number_small_dec2num(&b, i);
	number_extended_euclid_gcd(&d, &x, &a, &y, &b);
	number_mul(&xa, &x, &a);
	number_mul(&yb, &y, &b);
	number_add(&sum, &xa, &yb);

	tmp_x = x;
	number_absolute_value(&x, &x);
	number_absolute_value(&abs_y, &y);
	number_mod(&mod_y, &abs_y, &a);
	if (!number_is_equal(&abs_y, &y))
	    number_sub(&mod_y, &a, &mod_y);

	if (*res_gcd != 1 || *res_sum != 1 || (cnt[*mod_y_res] && 
	    (cnt[*mod_y_res] = 1)))
	{
	    ret = -1;
	}

	p_comment("x = %s"FMT_SZ", a = "FMT_SZ", y = %s"FMT_SZ", b = "FMT_SZ
	    ", gcd = "FMT_SZ", xa + yb = "FMT_SZ", y mod("FMT_SZ") = "FMT_SZ"",
	    number_is_equal(&tmp_x, &x) ? "" : "-", *(u64*)&x, *(u64*)&a, 
	    number_is_equal(&y, &abs_y) ? "" : "-", *(u64*)&abs_y, *(u64*)&b, 
	    *res_gcd, *res_sum, (u64)PRIME, *mod_y_res);

    }
    return ret;

#undef FMT_SZ
#undef PRIME
}

static int test56(void)
{
    u1024_t num_min, num_abs, num_0, num_1;
    int is_1_gt_0, is_min1_gt_0, is_abs_min1_gt_0, ret = 0;

    number_small_dec2num(&num_0, (u64)0);
    number_small_dec2num(&num_1, (u64)1);
    number_sub(&num_min, &num_0, &num_1);
    number_absolute_value(&num_abs, &num_min);

    is_1_gt_0 = !NUMBER_IS_NEGATIVE(&num_1) && 
	number_is_greater(&num_1, &num_0);
    is_min1_gt_0 = NUMBER_IS_NEGATIVE(&num_abs) && 
	number_is_greater(&num_min, &num_0);
    is_abs_min1_gt_0 = !NUMBER_IS_NEGATIVE(&num_abs) && 
	number_is_greater(&num_abs, &num_0);

    if (!is_1_gt_0 || is_min1_gt_0 || !is_abs_min1_gt_0)
	ret = -1;

    p_comment("1%s0", is_1_gt_0  ? ">" :"<");
    p_comment("-1%s0", is_min1_gt_0  ? ">" :"<");
    p_comment("|-1|%s0", is_abs_min1_gt_0 ? ">" : "<");

    return ret;
}

static int test57(void)
{
    u1024_t p1, p2, n, e, d, phi, montgomery_converter;
    int ret;

    local_timer_start();
    p_comment("finding large prime p1...");
    number_find_prime(&p1);
    p_comment("finding large prime p2...");
    number_find_prime(&p2);
    p_comment("calculating n = p1*p2...");
    number_mul(&n, &p1, &p2);
    p_comment("calculating phi = (p1-1)*(p2-1)...");
    number_sub1(&p1);
    number_sub1(&p2);
    number_mul(&phi, &p1, &p2);
    p_comment("generating puglic key: (e, n) - where e is coprime with phi...");
    number_init_random_coprime(&e, &phi);
    p_comment("calculating private key: (d, n) - where d is the multiplicative "
	"inverse of e mod phi...");
    number_modular_multiplicative_inverse(&d, &e, &phi);
    p_comment("calculating the montgomery converter constant...");
    ret = number_radix(&montgomery_converter, &n);
    local_timer_stop();
    p_local_timer();

    return ret;
}

typedef struct test58_t {
    int i;
    char c;
} test58_t;

static int test58(void)
{
#define FNAME_1 "f1"
#define FNAME_2 "f2"

//    test58_t a = {34, 'a'}, b = {345, 'b'}, c = {4636, 'c'};
    char x[100];
    FILE *f;
    int i;

    bzero(x, 100);
    p_comment("sizeof(int) = %i", sizeof(int));
    p_comment("sizeof(char) = %i", sizeof(char));
    p_comment("sizeof(test58_t) = %i", sizeof(test58_t));
    p_comment("sizeof(u64) = %i", sizeof(u64));

    i = 0;
    f = fopen(FNAME_1, "w+");
    i += fwrite("hello", strlen("hello"), 1, f);
    i += fwrite("nice", strlen("nice"), 1, f);
    i += fwrite("world", strlen("world"), 1, f);
    fclose(f);
    p_comment("wrote %i test58_t", i);

    i = 0;
    f = fopen(FNAME_1, "r+");
    i += fread(x, strlen("hello"), 1, f);
    i += fread(x + strlen("hello"), strlen("nice"), 1, f);
    fclose(f);
    p_comment("read %i test58_t", i);

    f = fopen(FNAME_2, "w+");
    p_comment("wrote %i test58_t", fwrite(x, strlen(x), 1, f));
    fclose(f);

    remove(FNAME_1);
    remove(FNAME_2);

    return 0;

#undef FNAME_2
#undef FNAME_1
}

static int test59(void)
{
    FILE *fe, *fd;
    u1024_t ne, nd, e, d, mf, buf1, buf2, buf3;
    char *vendor = "ilan";
    char *home = getenv("HOME");
    char pub_path[100], prv_path[100];
    int ret = 0;

    snprintf(pub_path, sizeof(pub_path), "%s/.rsa/pub/", home);
    snprintf(prv_path, sizeof(prv_path), "%s/.rsa/prv/", home);

    if (!(fe = rsa_file_open(pub_path, "ilan", ".pub", 0, 0)) || 
	!(fd = rsa_file_open(prv_path, "ilan", ".prv", 0, 0)))
    {
	p_comment("couldn't open key files");
	ret = -1;
	goto Exit;
    }
    else
	p_comment("key files opened");

    rsa_file_read_u1024(fe, &ne);
    rsa_file_read_u1024(fe, &e);
    rsa_file_read_u1024(fe, &mf);

    rsa_file_read_u1024(fd, &nd);
    rsa_file_read_u1024(fd, &d);

    number_reset(&buf1);
    number_reset(&buf2);
    number_reset(&buf3);

    memcpy(&buf1, vendor, sizeof(vendor));
//    number_small_dec2num(&buf1, (u64)5);

    number_modular_exponentiation_montgomery(&buf2, &buf1, &e, &ne);
    number_modular_exponentiation_montgomery(&buf3, &buf2, &d, &nd);

    p_comment("buf1 %s= buf3", memcmp(&buf1, &buf3, sizeof(u1024_t)) ? "!" : 
	"=");

Exit:
    if (fe)
	rsa_file_close(fe);
    if (fd)
	rsa_file_close(fd);

    return ret;
}

#if 0
void test60(void)
{
    u1024_t n, e, d, buf1, buf2, buf3;
    u1024_t p1, p2, p1_sub, p2_sub, phi, tmp1, tmp2;
    char *vendor = 
	"ilan is a really nice guy indeed and  4 this we are all greatful";

    number_find_prime(&p1);
    number_find_prime(&p2);

    /*
	7841, 7853, 7867, 7873, 7877, 7879, 7883, 7901, 7907, 7919,

    number_small_dec2num(&p1, (u64)7907);
    number_small_dec2num(&p2, (u64)7919);
    */
    number_mul(&n, &p1, &p2);

    p1_sub = p1;
    p2_sub = p2;
    number_sub1(&p1_sub);
    number_sub1(&p2_sub);
    number_mul(&phi, &p1_sub, &p2_sub);

    number_init_random_coprime(&e, &phi);
    number_modular_multiplicative_inverse(&d, &e, &phi);

//    number_small_dec2num(&buf1, (u64)5);
    number_reset(&buf1);
    number_reset(&buf2);
    number_reset(&buf3);
    memcpy(&buf1, vendor, strlen(vendor));

    number_modular_exponentiation_montgomery(&buf2, &buf1, &e, &n);
    number_modular_exponentiation_montgomery(&buf3, &buf2, &d, &n);

    /* this multiplication cannot be done correctly */
    number_modular_multiplication_montgomery(&tmp1, &e, &d, &phi);
    number_modular_multiplication_naive(&tmp2, &e, &d, &phi);
    printf("buf1 %s= buf3\n", memcmp(&buf1, &buf3, sizeof(u1024_t)) ? "!" : 
	"=");
    return;
}

static void test61(void)
{
    u1024_t a, b, n, r;

    number_init_str(&a,
	    /*
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    */

	    "00111111"
	    "11111111"
	    "11111111"
	    "11111111"
	    "11111111"
	    "11111111"
	    "11111111"
	    "11111111"
	    "11111111"
	    "11111111"
	    "11111111"
	    "11111111"
	    "11111111"
	    "11111111"
	    "11111111"
	    "11111111"
	    );
    number_init_str(&b,
	    /*
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    */

	    "00111111"
	    "11111111"
	    "11111111"
	    "11111111"
	    "11111111"
	    "11111111"
	    "11111111"
	    "11111111"
	    "11111111"
	    "11111111"
	    "11111111"
	    "11111111"
	    "11111111"
	    "11111111"
	    "11111111"
	    "11111111"
	    );
    number_init_str(&n,
	    /*
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    */

	    "01000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    "00000000"
	    );

    number_modular_multiplication_montgomery(&r, &a, &b, &n);
    return;
}
#endif

static int test62(void)
{
    int res;
    u1024_t n, e, d, buf1, buf2, buf3, tmp;
    u1024_t p1, p2, p1_sub, p2_sub, phi; /*, tmp1, tmp2;*/
    char *vendor = 
	"ilan is a really nice guy indeed and  4 this we are all greatful";

    number_reset(&buf1);
    number_reset(&buf2);
    number_reset(&buf3);
    memcpy(&buf1, vendor, strlen(vendor));

    number_init_str(&p1, 
	"0001101010010111011110001100101101101110001010000111001001011000"
	"1011101111001011100100010001011110111000010110001000101011001010"
	"1110010100101001111100110100001110001010110111001000100001110101"
	"0100111100000001010110110111110111010100110010001101111011011111"
	"1010110110000100110110100100110010111011110010110110011001011111"
	"1101011111100000101000000111101100010000101001001101010111010001"
	"0101010001011010101000010101000110000000011101100100011011000100"
	"0101110000011111011111110011000010010001000101000000001000100101");

    number_init_str(&p2,
	"0001000010000000101110101101110000110001010000011010111000100110"
	"1010000100111001011101010100111101101101010011010100010101100101"
	"0010111010111010111000100000000110110010100101110010101000000101"
	"0101010100111111101111100110100000011011000011100010101001110011"
	"0110101001101101010010111111111110110100000111001010111111101101"
	"0111000110000010001001011001010010101101101100111110000000111100"
	"0101110010010100100111001100000011011100011110000011000010110101"
	"1000011000100000101011001111010100001110100100010111111001001111");

    p_comment("calculating n = p1*p2...");
    number_mul(&n, &p1, &p2);

    p1_sub = p1;
    p2_sub = p2;
    number_sub1(&p1_sub);
    number_sub1(&p2_sub);
    p_comment("calculating phi = (p1-1)*(p2-1)...");
    number_mul(&phi, &p1_sub, &p2_sub);

    number_init_str(&e,
	"0001010101101001000110110101011001010100001110010001000001010101"
	"0001101110010011101011011000011100100100000000101100100001000111"
	"0100001010011100000100111000011100111011101111110110110111011100"
	"0000010110000001010001011001010000101100010100010110111111100010"
	"0100110011110011001100111010101101000011011110001100011001011001"
	"0111000110110010101000101100011001110100100000110110110101111001"
	"0110110110100011001001110100000000100101010111010101010001000100"
	"0000000001001101100010110110101100101100011100110010100110000011");

    number_init_str(&d,
	"0000000101110010101100010111100011100000101100100001101110000001"
	"0110101100010110011001101110010101111100001111010110011010001100"
	"1111001011110111100000011111011000010110010101011001110010101001"
	"1001111110101000111001001010101100101001100110100101111000000001"
	"0010000110101110010000101101111101001010111101010011101000100010"
	"1001001110110101001001100100010011111101110000010110011001000100"
	"0001001011010110100001000110100011100111101010011101011011101000"
	"0000110110110100011000010110010100001010101011100010011010100010"
	"0111100010011100000000101011110101110011101101110011010011001001"
	"0010001000110011101111101000111001010001011101101100000110110001"
	"0000100101101011000101011111101011011000010010111011111100111011"
	"0101110001101000101111101101001100110001010000001000001101110000"
	"0100101010100010110011111000000001100011100001001111101000000001"
	"1001100001101001110000110111100011110000101100101000111011101111"
	"1011101010110101011011010101010111011010111101001000010000110010"
	"0101010011000001001000101110000110010000101111101110011011101011");

#if 0
    number_init_str(&num_montgomery_factor,
	"0000000100110010100011011000101110101000110011011110101011101011"
	"0011110101001101010110110101010000001011100111110110010001100010"
	"1101110011110110100100000100110100000100011101110000001111100000"
	"0101001011101010100100010001010000010101011101111111000010111100"
	"1110101110101110111111000010000101000111000011001110000101000001"
	"1000001111111011001000101100011011011010011110110110001000101101"
	"0011110001011111010111111000101001000110010110000001011110010001"
	"1101011011001111010111010111111011100110000100001111001010100110"
	"1011101011101011001111001111111000110110000011111010101110110111"
	"0011001010101110111010111000010001111100001100110100100001100010"
	"0100101000000011101110011110111111001001111011010011110011101111"
	"1001101101011110110101011100001100011010110101110001000110011110"
	"1110000011100100001101011100100111101011100111101111000001001110"
	"0100100110000101011100111011110111011000000111111000101000000100"
	"0010000100111111011111010010000010010011011101010101111101101111"
	"0111101001100010101100011011100101000001000111110001000010100100");

    num_montgomery_n = n;
#endif

    /*
    p_comment("generating e coprime with phi...");
    number_init_random_coprime(&e, &phi);
    p_comment("calculating d multiplicative inverse of e mod phi...");
    number_modular_multiplicative_inverse(&d, &e, &phi);
    */

    p_comment("encrypting buf1 -> buf2...");
    number_modular_exponentiation_montgomery(&buf2, &buf1, &e, &n);
    p_comment("decrypting buf2 -> buf3...");
    number_modular_exponentiation_montgomery(&buf3, &buf2, &d, &n);

    /* this multiplication cannot be done correctly */
//    number_modular_multiplication_montgomery(&tmp1, &e, &d, &phi);
//    number_modular_multiplication_naive(&tmp2, &e, &d, &phi);

    res = memcmp(&buf1, &buf3, sizeof(u1024_t));
    p_comment("buf1 %s= buf3",  res ? "!" : "=");
    tmp = num_montgomery_factor;
#if 0    
    printf("a * montgomery factor\n");
    printf("  mul: %i\n", mul_a_x_mf);
    printf("  res: %i\n", res_a_x_mf);
    printf("b * montgomery factor\n");
    printf("  mul: %i\n", mul_b_x_mf);
    printf("  res: %i\n", res_b_x_mf);
    printf("a nresidue * b nresidue\n");
    printf("  mul: %i\n", mul_ares_x_bres);
    printf("  res: %i\n", res_ares_x_bres);
    printf("1 x result\n");
    printf("  mul: %i\n", mul_1_x_res);
    printf("  res: %i\n", res_1_x_res);
    printf("radix = %i\n", radix);
    printf("addition1 = %i\n", addition1);
    printf("addition2 = %i\n", addition2);
    printf("addition3 = %i\n", addition3);
    printf("addition4 = %i\n", addition4);
    printf("addition5 = %i\n", addition5);
    printf("multiplicand = %i\n", multi);
    printf("result = %i\n", result);
#endif

    return res;
}

static int is_test63_do(void)
{
    char c = 0;

    if (!ask_user)
	return 1;

    s_comment("do you want to perform this test (approx 10 min.)? [Y/n] ", "%c",
	&c);
    if (c == 'n' || c == 'N')
	return 0;
    return 1;
}

static int test63(void)
{
    int res;
    u1024_t n, e, d, buf1, buf2, buf3;
    u1024_t p1, p2, p1_sub, p2_sub, phi;
    char *vendor = 
	"ilan is a really nice guy indeed and  4 this we are all greatful";

    if (!is_test63_do())
    {
	p_comment("skipping...");
	return 0;
    }

    number_reset(&buf1);
    number_reset(&buf2);
    number_reset(&buf3);
    memcpy(&buf1, vendor, strlen(vendor));

    local_timer_start();
    p_comment("finding large prime p1...");
    number_find_prime(&p1);
    p_comment("finding large prime p2...");
    number_find_prime(&p2);

    p_comment("calculating n = p1*p2...");
    number_mul(&n, &p1, &p2);

    p1_sub = p1;
    p2_sub = p2;
    number_sub1(&p1_sub);
    number_sub1(&p2_sub);
    p_comment("calculating phi = (p1-1)*(p2-1)...");
    number_mul(&phi, &p1_sub, &p2_sub);

    p_comment("generating puglic key: (e, n) - where e is coprime with phi...");
    number_init_random_coprime(&e, &phi);
    p_comment("calculating private key: (d, n) - where d is the multiplicative "
	"inverse of e mod phi...");
    number_modular_multiplicative_inverse(&d, &e, &phi);
    local_timer_stop();
    p_local_timer();

    p_comment("phrase: '%s'", vendor);
    p_comment("encrypting...");
    local_timer_start();
    number_modular_exponentiation_montgomery(&buf2, &buf1, &e, &n);
    local_timer_stop();
    p_local_timer();

    p_comment("decrypting...");
    local_timer_start();
    number_modular_exponentiation_montgomery(&buf3, &buf2, &d, &n);
    local_timer_stop();
    p_local_timer();

    res = memcmp(&buf1, &buf3, sizeof(u1024_t));
    p_comment("decryption %smatche%s the original",  res ? "does not " : "", 
	res ? "" : "s");

    return res;
}


static test_t rsa_tests[] = 
{
    {
	description: "sizeof(u1024_t)",
	func: test01,
    },
    {
	description: "number_init_str()",
	func: test02,
    },
    {
	description: "number_init_random() - compare many numbers",
	func: test03,
    },
    {
	description: "number_add() - basic functionality",
	func: test04,
    },
    {
	description: "number_add() - functionality",
	func: test05,
#ifndef UCHAR
	disabled: 1,
#endif
    },
    {
	description: "number_add() - random numbers",
	func: test06,
#ifdef TIME_FUNCTIONS
	disabled: 1,
#endif
    },
    {
	description: "number_add() - testing new implementation",
	func: test07,
#ifdef TIME_FUNCTIONS
	disabled: 1,
#endif
    },
    {
	description: "number_shift_left() - functionality",
	func: test08,
    },
    {
	description: "number_shift_left() - edge conditions, "
	    "random numbers",
	func: test09,
#ifndef UCHAR
	disabled: 1,
#endif
    },
    {
	description: "number_mul() - multiplicand > multiplier",
	func: test10,
#ifndef UCHAR
	disabled: 1,
#endif
    },
    {
	description: "number_mul() - multiplicand < multiplier",
	func: test11,
#ifndef UCHAR
	disabled: 1,
#endif
    },
    {
	description: "number_mul() - big numbers",
	func: test12,
#ifndef UCHAR
	disabled: 1,
#endif
    },
    {
	description: "number_dec2bin()",
	func: test13,
#ifndef UCHAR
	disabled: 1,
#endif
    },
    {
	description: "number_dec2bin() - edge conditions",
	func: test14,
#ifndef UCHAR
	disabled: 1,
#endif
    },
    {
	description: "number_dec2bin() - max size number",
	func: test15,
#ifndef ULLONG
	disabled: 1,
#endif
    },

    {
	description: "number_dec2bin() - edge conditions",
	func: test16,
#ifndef ULLONG
	disabled: 1,
#endif
    },
    {
	description: "number_shift_right()",
	func: test17,
#ifndef UCHAR
	disabled: 1,
#endif
    },
    {
	description: "number_find_most_significant_set_bit()",
	func: test18,
#ifndef UCHAR
	disabled: 1,
#endif
    },
    {
	description: "number_find_most_significant_set_bit()",
	func: test19,
#ifndef ULLONG
	disabled: 1,
#endif
    },
    {
	description: "number_modular_multiplication_naive()",
	func: test20,
#ifndef UCHAR
	disabled: 1,
#endif
    },
    {
	description: "number_sub() - basic functionality",
	func: test21,
#ifndef UCHAR
	disabled: 1,
#endif
    },
    {
	description: "number_sub() - advanced functionality",
	func: test22,
#ifndef UCHAR
	disabled: 1,
#endif
    },
    {
	description: "number_dev() - basic functionality",
	func: test23,
#ifndef UCHAR
	disabled: 1,
#endif
    },
    {
	description: "number_dev()",
	func: test24,
#ifndef UCHAR
	disabled: 1,
#endif
    },
    {
	description: "number_modular_exponentiation_naive() - basic "
	    "functionality",
	func: test25,
#ifndef UCHAR
	disabled: 1,
#endif
    },
    {
	description: "number_modular_exponentiation_naive()",
	func: test26,
#ifndef UCHAR
	disabled: 1,
#endif
    },
    {
	description: "number_witness() - basic functionality",
	func: test27,
#ifndef UCHAR
	disabled: 1,
#endif
    },
    {
	description: "number_is_prime() - basic functionality",
	func: test28,
#ifndef UCHAR
	disabled: 1,
#endif
    },
    {
	description: "number_is_prime(99991)",
	func: test29,
#ifndef USHORT
	disabled: 1,
#endif
    },
    {
	description: "number_is_prime() primes in [3, 999]",
	func: test30,
#ifndef USHORT
	disabled: 1,
#endif
    },
    {
	description: "number_is_prime(10,726,904,659) - large prime",
	func: test31,
#ifdef UCHAR
	disabled: 1,
#endif
    },
    {
	description: "number_is_prime(55,350,776,431,903,243) - very large "
	    "prime",
	func: test32,
#ifdef UCHAR
	disabled: 1,
#endif
    },
    {
	description: "number_is_prime(94R(71)9) - 475 bit prime",
	func: test33,
#if !defined(ULLONG) || defined(TIME_FUNCTIONS)
	disabled: 1,
#endif
    },
    {
	description: "number_is_prime("
	    "2,285,760,293,497,823,444,790,323,455,592,340,983,477) - very "
	    "large non prime",
	func: test34,
#ifndef ULLONG
	disabled: 1,
#endif
    },
    {
	description: "number_find_prime()",
	func: test35,
#if defined(UCHAR)
	disabled: 1,
#endif
    },
    {
	description: "number_radix()",
	func: test36,
#ifndef ULLONG
	disabled: 1,
#endif
    },
    {
	description: "number_radix() - for a random number",
	func: test37,
#ifdef UCHAR
	disabled: 1,
#endif
    },
    {
	description: "number_modular_exponentiation_naive() - large power of 2",
	func: test38,
#ifndef ULLONG
	disabled: 1,
#endif
    },
    {
	description: "naive modular multiplication and exponentiation",
	func: test39,
#ifndef USHORT
	disabled: 1,
#endif
    },
    {
	description: "number_modular_exponentiation_naive()",
	func: test40,
#ifdef UCHAR
	disabled: 1,
#endif
    },
    {
	description: "number_modular_multiplication_montgomery()",
	func: test41,
#ifndef USHORT
	disabled: 1,
#endif
    },
    {
	description: "number_modular_multiplication_montgomery()",
	func: test42,
#ifndef USHORT
	disabled: 1,
#endif
    },
    {
	description: "deviding a 475 bit number by 29",
	func: test43,
#ifndef ULLONG
	disabled: 1,
#endif
    },
    {
	description: "(2x3x5x7x11x13x17x19x23x29x31x37x41)^10 "
	    "x5x7x23x29x31x37x41",
	func: test44,
#ifndef ULLONG
	disabled: 1,
#endif
    },
    {
	description: "multiply the first 75 primes (and again by the 4th)",
	func: test45,
#ifndef ULLONG
	disabled: 1,
#endif
    },
    {
	description: "coprimality testing",
	func: test46,
#ifndef ULLONG
	disabled: 1,
#endif
    },
    {
	description: "number_mod() sanity test",
	func: test47,
#ifndef ULLONG
	disabled: 1,
#endif
    },
    {
	description: "negative numbers",
	func: test48,
#ifndef UCHAR
	disabled: 1,
#endif
    },
    {
	description: "number_modular_multiplicative_inverse()",
	func: test53,
#ifndef ULLONG
	disabled: 1,
#endif
    },
    {
	description: "number_absolute_value()",
	func: test54,
#ifndef UCHAR
	disabled: 1,
#endif
    },
    {
	description: "number_extended_euclid_gcd()",
	func: test55,
#ifdef UCHAR
	disabled: 1,
#endif
    },
    {
	description: "negative and absolute numbers",
	func: test56,
#ifndef UCHAR
	disabled: 1,
#endif
    },
    {
	description: "create rsa key",
	func: test57,
#ifndef ULLONG
	disabled: 1,
#endif
    },
    {
	description: "test fread() and fwrite()",
	known_issue: "wrong result for sizeof(test58_t)",
	func: test58,
#ifndef ULLONG
	disabled: 1,
#endif
    },
    {
	description: "encryption - decryption test",
	func: test59,
#ifndef ULLONG
	disabled: 1,
#endif
    },
    {
	description: "encryption - decryption test",
	func: test62,
#ifndef ULLONG
	disabled: 1,
#endif
    },
    {
	description: "complete RSA test - key generation, encryption and "
	    "decryption",
	func: test63,
#if !defined(ULLONG) || defined(TIME_FUNCTIONS)
	disabled: 1,
#endif
    },
    {0},
};

/*
static test_t tests[] = 
{
    { "encryption - decryption test", test60, DISABLED },
    { "montgomery multiplication of large numbers", test61, DISABLED },
    { }
};
*/

static int p_u64_type(char *colour)
{
    char *type = "unsigned "
#if defined UCHAR
    "char";
#elif defined USHORT
    "short";
#elif defined ULONG
    "long";
#elif defined ULLONG
    "long long";
#else
    ;
    /* should never get here */
    printf("U64 undefined");
    return -1;
#endif

    p_colour(colour, "u64 = %s", type);
    return 0;
}

static void p_test_summery(int total, int passed, int failed, int known_issues, 
    int disabled)
{
    int type_bad;

    printf("\ntest summery (");
    type_bad = p_u64_type(C_NORMAL);
    printf(")\n");
    if (type_bad)
	return;
    printf("------------\n");
    printf("%stotal:        %i%s\n", C_HIGHLIGHT, total, C_NORMAL);
    printf("passed:       %i\n", passed);
    printf("failed:       %i\n", failed);
    printf("known issues: %i\n", known_issues);
    printf("disabled:     %i\n", disabled);
}

static void test_usage(char *app)
{
    printf("usage:\n"
	"%s               - run all tests\n"
	"  or\n"
	"%s <test>        - run a specific test\n"
	"  or\n"
	"%s <from> <to>   - run a range of tests\n"
	"  or\n"
	"%s list          - list all tests\n",
	app, app, app, app);
}

static int test_getarg(char *arg, int *arg_ival, int min, int max)
{
    char *err;

    *arg_ival = strtol(arg, &err, 10);
    if (*err)
	return -1;
    if (*arg_ival < min || *arg_ival > max)
    {
	printf("test number out of range: %i\n", *arg_ival);
	return -1;
    }
    return 0;
}

static int test_getargs(int argc, char *argv[], int *from, int *to, int max)
{
    if (argc > 3)
    {
	test_usage(argv[0]);
	return -1;
    }

    if (argc == 1)
    {
	*from = 0;
	*to = max;
	ask_user = 1;
	return 0;
    }

    /* 2 <= argc <= 3*/
    if (test_getarg(argv[1], from, 1, max))
    {
	test_usage(argv[0]);
	return -1;
    }

    if (argc == 2)
    {
	*to = *from;
    }
    else /* argc == 3 */
    {
	if (test_getarg(argv[2], to, *from, max))
	{
	    test_usage(argv[0]);
	    return -1;
	}
    }

    (*from)--; /* map test number to table index */
    return 0;

}

static int is_list_tests(int argc, char *argv[])
{
    int i;

    if (argc != 2 || strcmp(argv[1], "list"))
	return 0;

    p_colour(C_HIGHLIGHT, "rsa unit tests (");
    p_u64_type(C_HIGHLIGHT);
    p_colour(C_HIGHLIGHT, ")\n");
    for (i = 0; i < ARRAY_SZ(rsa_tests) - 1; i++)
    {
	test_t *t =  &rsa_tests[i];

	printf("%i. ", i + 1);
	p_colour(!all_tests && t->disabled ? C_GREY : C_NORMAL, "%s", 
	    t->description);
	if (!all_tests && t->disabled)
	    p_colour(C_CYAN, " (disabled)");
	if (!t->disabled && t->known_issue)
	{
	    p_colour(C_BLUE, " (known issue: ");
	    p_colour(C_GREY, t->known_issue);
	    p_colour(C_BLUE, ")");
	}
	printf("\n");
    }

    return 1;
}

int main(int argc, char *argv[])
{
    test_t *t;
    int from, to, max = ARRAY_SZ(rsa_tests), ret;
    int  total = 0, disabled = 0, passed = 0, failed = 0, known_issues = 0;

#if defined(ALL_TESTS)
    all_tests = 1;
#endif

    if (is_list_tests(argc, argv))
	return 0;

    if (test_getargs(argc, argv, &from, &to, max - 1))
	return -1;

    for (t = &rsa_tests[from]; t < rsa_tests + MIN(to, max); t++)
    {
	first_comment = 1;
	total++;
	printf("%i. %s", total, t->description);
	printf(": ");
	if (!all_tests && t->disabled)
	{
	    disabled++;
	    p_colour(C_CYAN, "disabled\n");
	    continue;
	}
	if (t->known_issue)
	{
	    p_colour(C_BLUE, "known issue: ");
	    p_colour(C_NORMAL, "%s\n", t->known_issue);
	    known_issues++;
	    continue;
	}
	if (!t->func)
	{
	    p_colour(C_CYAN, "function does not exist\n");
	    return -1;
	}
	fflush(stdout);

	init_reset = 1;

	if ((ret = t->func()))
	{
	    p_colour(C_RED, "Failed");
	    failed++;
	}
	else
	{
	    p_colour(C_GREEN, "OK");
	    passed++;
	}
	printf("\n");
    }

    p_test_summery(total, passed, failed, known_issues, disabled);
    return 0;
}

