#include "rsa_util.h"
#include "rsa_num.h"
#include "unit_test.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <math.h>

#define B (8)
#define K (1024)
#define M (K*K)

enum {
    DISABLE_UCHAR = 1<<0,
    DISABLE_USHORT = 1<<1,
    DISABLE_ULONG = 1<<2,
    DISABLE_ULLONG_64 = 1<<3,
    DISABLE_ULLONG_128 = 1<<4,
    DISABLE_ULLONG_256 = 1<<5,
    DISABLE_ULLONG_512 = 1<<6,
    DISABLE_ULLONG_1024 = 1<<7,
    DISABLE_ULLONG = DISABLE_ULLONG_64 | DISABLE_ULLONG_128 | 
	DISABLE_ULLONG_256 | DISABLE_ULLONG_512 | DISABLE_ULLONG_1024,
    DISABLE_TIME_FUNCTIONS = 1<<8
};

static code2str_t el2phrase[] = {
    {64, ""},
    {128, "Testing 128 bits"},
    {256, "Validation of 256 bit encryption"},
    {512, "Ilan A. Smith 512 bits encryption / decryption validation string"},
    {1024, "Ilan A. Smith 1024 bit encryption / decryption validation string\n"
	" used for varifying that encryption is identical to decryption."},
    {-1}
};

static code2str_t el2data[] = {
    {128, 
	"0000000000000000011001010111001101100001011010000111000000100000"
	"0111010001101001011000100010000000110001001100110010000001100001"
    },
    {1024, 
	"0110011101101110011010010111010001100001011100100110010101101110"
	"0110010101100111011001010111001000100000011100110110010001100101"
	"0110010101101110001000000111100101100101011010110010000001000001"
	"0101001101010010001000000110010101101000011101000010000001110100"
	"0110111101101110001000000111001001101111001000000111001001100101"
	"0110100001110100011001010110100001110111001000000110011101101110"
	"0110100101110100011100110110010101110100001000000111001001101111"
	"0110011000100000011001000110010101110011011101010010000000001010"
	"0110011101101110011010010111001001110100011100110010000001101110"
	"0110111101101001011101000110000101100100011010010110110001100001"
	"0111011000100000011011100110111101101001011101000111000001111001"
	"0111001001100011011001010110010000100000001011110010000001101110"
	"0110111101101001011101000111000001111001011100100110001101101110"
	"0110010100100000011101000110100101100010001000000011010000110010"
	"0011000000110001001000000110100001110100011010010110110101010011"
	"0010000000101110010000010010000001101110011000010110110001001001" },
    {-1}
};

static code2str_t el2p1[] = {
    {128, "1011010001000100100011101100011110010000011010011010110111110101"},
    {1024, 
	"1000000100010100111001000110011011001010010011110011011101111000"
	"1000101011110100100010011000110010100101000011011100000111110011"
	"0000010110101011001110110110111000001000100100101101000001110010"
	"1100100101101110101110011010111101001100101111011000111101001110"
	"1011110001010001001111110100001011010010110111111110010011011110"
	"0010001111000101011011011111011111110110111011111100011111101000"
	"1010011010001100001011110101000101101010111111110000111001101100"
	"0111101001110110011110010000110010001110011001101001001110101111"
    },
    {-1}
};

static code2str_t el2p2[] = {
    {128, "1101010011111100001011111011000100101111111100000011010110111001"},
    {1024, 
	"1000001111101111010111100000010010011011010010010100001011100000"
	"1010101100111111010000000001011010000001000100011010110011000011"
	"0011100111100100101100001000110010101010111110111110001000010011"
	"1001110101111100110010110111100100101000110100111100110101101101"
	"1111110011101101110011101101110100001010101100100010000111011110"
	"0111110011000111110101110111100001111111111101110111000010001011"
	"1000010111000010111111011110100100111001011011001010110011010000"
	"0001010001100100011000110110000100110001111011010111110101101001"
    },
    {-1}
};

static code2str_t el2e[] = {
    {128, 
	"0111101001111100100110010101111100000001011011001001000000100000"
	"0001110001111101011010101011111001011001011110110110001001100101"	
    },
    {1024, 
	"0000010000011100101101000001011101101100000110010100010111010110"
	"0100001000111101001111010111010001001010110001110100000111101111"
	"0101010100111011010100101111010101100110000000100101000111010100"
	"0101100100000000011001010011110100010101001000001000000111101000"
	"0110010101000101111101110000001000111111110000000001101101111001"
	"0010111111101000110111011001100101100011100011011111100101101001"
	"0110111100011111100110110011001001100010111011010101011010011100"
	"0011011001011110001100001000101101001100000111011100100010111100"
	"0010111000000111111101101110101100110110110110111111000111110110"
	"0010111000000111010011000010010001011100111110111010101001000101"
	"0101010010000001100001011001111100001110000001100011100000001010"
	"0101110110101100011001011010010100001000000000001000100000111110"
	"0010010000111000010101001000011100110100000011010010101000010101"
	"0011111010110010100111101010001100111010010011010001100000111110"
	"0010010000010001100010001000111001011101110011110101000000011000"
	"0111001100111100101111110110110000111001010101010111001000101001"
    },
    {-1}
};

int init_reset;

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
    int i = block_sz_u1024;
    u64 *ptr;

    p_comment("tp: %d", num->top);
    p_comment("bf: %s", p_u64((u64*)&num->arr + i--));
    for (ptr = (u64*)&num->arr + i; ptr >= (u64*)&num->arr; ptr--)
    {
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
    [ FUNC_NUMBER_INIT_RANDOM ] = {"number_init_random", 1},
    [ FUNC_NUMBER_FIND_MOST_SIGNIFICANT_SET_BIT ] = 
	{"number_find_most_significant_set_bit ", 1},
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
    [ FUNC_NUMBER_DEV ] = {"number_dev", 1},
    [ FUNC_NUMBER_INIT_RANDOM_STRICT_RANGE ] = 
	{"number_init_random_strict_range",  1},
    [ FUNC_NUMBER_EXPONENTIATION ] = {"number_exponentiation", 1},
    [ FUNC_NUMBER_MODULAR_EXPONENTIATION_NAIVE ] = 
	{"number_modular_exponentiation_naive", 1},
    [ FUNC_NUMBER_MONTGOMERY_FACTOR_SET ] = {"number_montgomery_factor_set", 1},
    [ FUNC_NUMBER_MONTGOMERY_PRODUCT] = {"number_montgomery_product", 1},
    [ FUNC_NUMBER_MODULAR_EXPONENTIATION_MONTGOMERY ] = 
	{"number_modular_exponentiation_montgomery", 1},
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

static int test001(void)
{
    p_comment("bit_sz_u64 = %d", bit_sz_u64);
#if defined(UCHAR) || defined(USHORT) || defined(ULONG)
    p_comment("block_sz_u1024 = %d", block_sz_u1024);
    p_comment("encryption_level = bit_sz_u64*block_sz_u1024 = %d*%d = %d", 
	bit_sz_u64, block_sz_u1024, encryption_level);
#else
    p_comment("encryption_level = %d", encryption_level);
    p_comment("block_sz_u1024 = encryption_level/bit_sz_u64 = %d/%d = %d", 
	encryption_level, bit_sz_u64, block_sz_u1024);
#endif

#if defined(UCHAR)
    return !(bit_sz_u64==8 && block_sz_u1024==16 && encryption_level==128);
#elif defined(USHORT)
    return !(bit_sz_u64==16 && block_sz_u1024==16 && encryption_level==256);
#elif defined(ULONG)
    return !(bit_sz_u64==32 && block_sz_u1024==16 && encryption_level==512);
#else
    switch (encryption_level)
    {
    case 64:
	return !(bit_sz_u64==64 && block_sz_u1024==1 && encryption_level==64);
    case 128:
	return !(bit_sz_u64==64 && block_sz_u1024==2 && encryption_level==128);
    case 256:
	return !(bit_sz_u64==64 && block_sz_u1024==4 && encryption_level==256);
    case 512:
	return !(bit_sz_u64==64 && block_sz_u1024==8 && encryption_level==512);
    case 1024:
	return !(bit_sz_u64==64 && block_sz_u1024==16 && 
	    encryption_level==1024);
    default:
	return -1;
    }
#endif
}

static int test006(void)
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

static int test007(void)
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

static int test008(void)
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

static int test009(void)
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

static int test010(void)
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

static int test011(void)
{
#define RNDM_TBL_SZ 10000
    u1024_t number[RNDM_TBL_SZ];
    int i, j;

    for (i = 0; i < RNDM_TBL_SZ; i++)
    {
	if (number_init_random(&number[i], block_sz_u1024/2))
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
#undef RNDM_TBL_SZ
}

static int test016(void)
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

static int test017(void)
{
    u1024_t a, b, c, res;

    number_reset(&res);
    if (number_init_str(&a, 
	"11111111" /* buffer */

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
	) || number_init_str(&b, "1"))
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

static int test018(void)
{
    u1024_t a, b, c;

    number_small_dec2num(&a, (u64)115);
    number_small_dec2num(&b, (u64)217);
    number_add(&c, &a, &b);
    return !(*(u64*)&c == (u64)332);
}

static int test019(void)
{
    u1024_t a, b, c;

    if (number_init_random(&a, block_sz_u1024/2) || 
	number_init_random(&b, block_sz_u1024/2))
    {
	p_comment("initializing a failed");
	return -1;
    }
    number_add(&c, &a, &b);
    return 0;
}

static int test020(void)
{
    u1024_t a, b, n, res;

    number_dec2bin(&res, "4294968000");
    number_dec2bin(&a, "4294960000");
    number_dec2bin(&b, "8000");
    number_add(&n, &a, &b);
    return !number_is_equal(&n, &res);
}

static int test025(void)
{
    u1024_t p, res;

    number_init_str(&p, 
	"1000010110111011100111000000100110111110101111010010011111110001"
	);
    number_init_str(&res, 
	"0100001011011101110011100000010011011111010111101001001111111000"
	);
    number_shift_right_once(&p);
    return !number_is_equal(&p, &res);
}

static int test026(void)
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

static int test027(void)
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

static int test028(void)
{
    u1024_t a, res;

    if (number_init_str(&a,
	"11111111" /* buffer */

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
	) || number_init_str(&res,
	"11111111" /* buffer */

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
	"11111100"
	))
    {
	p_comment("initializing a failed");
	return -1;
    }

    number_shift_left(&a, 2);
    return !number_is_equal(&a, &res);
}
static int test029(void)
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
	(number_init_random(&b, block_sz_u1024/2)) ||
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

static int test031(void)
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

static int test032(void)
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

static int test033(void)
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

static int test034(void)
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

static int test035(void)
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

static int test041(void)
{
    u1024_t num_547, num_547_again, num_252;
    int res = 0;

    if (number_init_str(&num_547, "1000100011") || 
	number_init_str(&num_547_again, "1000100011") || 
	number_init_str(&num_252, "11111100"))
    {
	printf("initializing num_547, num_547_again or num_252 failed\n");
	return -1;
    }

    if (!number_is_greater(&num_547, &num_252))
    {
	p_comment("!number_is_greater(&num_547, &num_252)");
	res = -1;
    }
    if (number_is_greater(&num_252, &num_547))
    {
	p_comment("number_is_greater(&num_252, &num_547)");
	res = -1;
    }
    if (!number_is_equal(&num_547, &num_547))
    {
	p_comment("!number_is_equal(&num_547, &num_547)");
	res = -1;
    }
    if (!number_is_equal(&num_547, &num_547_again))
    {
	p_comment("!number_is_equal(&num_547, &num_547_again)");
	res = -1;
    }
    if (number_is_equal(&num_252, &num_547))
    {
	p_comment("number_is_equal(&num_252, &num_547)");
	res = -1;
    }
    if (!number_is_greater_or_equal(&num_547, &num_252))
    {
	p_comment("!number_is_greater_or_equal(&num_547, &num_252)");
	res = -1;
    }
    if (!number_is_greater_or_equal(&num_547, &num_547))
    {
	p_comment("!number_is_greater_or_equal(&num_547, &num_547)");
	res = -1;
    }
    if (!number_is_greater_or_equal(&num_547_again, &num_547))
    {
	p_comment("!number_is_greater_or_equal(&num_547_again, &num_547)");
	res = -1;
    }
    if (number_is_greater_or_equal(&num_252, &num_547))
    {
	p_comment("number_is_greater_or_equal(&num_252, &num_547)");
	res = -1;
    }

    return res;
}

static int test042(void)
{
    u1024_t num_a, num_b;

    if (number_init_str(&num_a, 
	"0000000000000000000000000000000000000000000000000000000000000001"
	"0010001100111000111110100101010000100011001001001011101011010000"
	"0000110001011000001010011110111000010001001101011011101110111000"
	) || 
	number_init_str(&num_b, 
	"1001010111111010010110110100111100101011011010001100001111100101"
	"0101011011100010100010101000010101001110000100100110111100001101"
	))
    {
	printf("initializing num_547, num_547_again or num_252 failed\n");
	return -1;
    }

    return !number_is_greater(&num_a, &num_b);
}

static int test043(void)
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

static int test044(void)
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

static int test045(void)
{
    u1024_t a, b, c, res;

    number_reset(&a);
    if (number_init_str(&b, "11111111") ||
	number_init_str(&res,
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
	"00000001"
	))
    {
	printf("initializing b or res failed\n");
	return -1;
    }

    number_sub(&c, &a, &b);
    return !number_is_equal(&c, &res);
}

static int test046(void)
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

static int test047(void)
{
    u1024_t num_a, num_abs, num_5;

    number_small_dec2num(&num_5, (u64)5);
    number_small_dec2num(&num_a, (u64)0);

    number_sub(&num_a, &num_a, &num_5); /* a = -5 */
    number_absolute_value(&num_abs, &num_a); /* |a| = 5 */

    return !(number_is_equal(&num_abs, &num_5));
}

static int test048(void)
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

static int test051(void)
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

static int test052(void)
{
    u1024_t a, b, q, r, res_q, res_r;

    if (number_init_str(&a, "1000100011") || /* 547 */
	number_init_str(&b, "11111100") || /* 252 */
	number_init_str(&res_q, "10") || /* 2 */
	number_init_str(&res_r, "101011")) /* 43 */
    {
	printf("initializing a or b failed\n");
	return -1;
    }

    number_dev(&q, &r, &a, &b);
    return !(number_is_equal(&q, &res_q) && number_is_equal(&r, &res_r));
}

static int test053(void)
{
    u1024_t a, b, q, r, res_q, res_r;

    if (number_init_str(&a, "11111100") ||  /* 252 */
	number_init_str(&b, "1000100011") || /* 547 */
	number_init_str(&res_q, "0") || /* 0 */
	number_init_str(&res_r, "11111100")) /* 252 */
    {
	printf("initializing a or b failed\n");
	return -1;
    }

    number_dev(&q, &r, &a, &b);
    return !(number_is_equal(&q, &res_q) && number_is_equal(&r, &res_r));
}

static int test054(void)
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

static int test055(void)
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

static int test056(void)
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

	number_assign(tmp_x, x);
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

static int test057(void)
{
    u1024_t a, b, n, axb, num_1;
    u64 i, prime = 13;

    number_small_dec2num(&num_1, (u64)1);
    number_small_dec2num(&n, (u64)prime);

    for (i = (u64)1; i < (u64)prime; i++)
    {
	number_small_dec2num(&a, (u64)i);
	number_modular_multiplicative_inverse(&b, &a, &n);
	number_modular_multiplication_montgomery(&axb, &a, &b, &n);
	p_comment("%2.llu^(-1)mod(%llu) = %2.llu, %2.llux%llu mod(%llu) = %llu",
	    *(u64*)&a, prime, *(u64*)&b, *(u64*)&a, *(u64*)&b, prime, 
	    *(u64*)&axb);
	if (!number_is_equal(&axb, &num_1))
	    return -1;
    }
    return 0;
}

static int test061(void)
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
    res_seg = (u64*)&a + (u64)((strlen(str_a) - 1) / (sizeof(u64) * 8));
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

static int test062(void)
{
    u1024_t a;
    u64 *seg, mask, *res_seg, res_mask;

    res_seg = (u64*)&a + 1;
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

static int test063(void)
{
    u1024_t a, b, n, res, test_res;

    number_dec2bin(&test_res, "2");
    number_dec2bin(&a, "3");
    number_dec2bin(&b, "2");
    number_dec2bin(&n, "4");
    number_modular_multiplication_naive(&res, &a, &b, &n);
    return !number_is_equal(&res, &test_res);
}

static int test064(void)
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

static int test066(void)
{
    u1024_t r, a, b, n, res;

    if (number_dec2bin(&a, "3") || number_dec2bin(&b, "3") || 
	number_dec2bin(&n, "7") || number_dec2bin(&res, "6"))
    {
	printf("initializing a, b or n failed\n");
	return -1;
    }

    number_modular_exponentiation_naive(&r, &a, &b, &n);
    return !number_is_equal(&r, &res);
}

static int test067(void)
{
    u1024_t r, a, b, n, res;

    if (number_dec2bin(&a, "289") || number_dec2bin(&b, "276") || 
	number_dec2bin(&n, "258") || number_dec2bin(&res, "121"))
    {
	printf("initializing a, b or n failed\n");
	return -1;
    }

    number_modular_exponentiation_naive(&r, &a, &b, &n);
    return !number_is_equal(&r, &res);
}

static int test068(void)
{
    u1024_t num_1, num_2, num_516, num_9, res;

    number_small_dec2num(&res, (u64)1);
    number_small_dec2num(&num_2, (u64)2);
    number_small_dec2num(&num_516, (u64)516);
    number_small_dec2num(&num_9, (u64)9);

    number_modular_exponentiation_naive(&num_1, &num_2, &num_516, &num_9);
    return !number_is_equal(&num_1, &res);
}

static int test069(void)
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

static int test071(void)
{
    u1024_t num_n, res, num_montgomery_factor;

    number_small_dec2num(&num_n, 163);
    number_small_dec2num(&res, 58);
    number_montgomery_factor_set(&num_n, NULL);
    number_montgomery_factor_get(&num_montgomery_factor);
    return !number_is_equal(&num_montgomery_factor, &res);
}

static int test072(void)
{
    u1024_t num_n, num_montgomery_factor;

    number_init_random(&num_n, block_sz_u1024);
    *(u64*)&num_n |= (u64)1;
    number_montgomery_factor_set(&num_n, NULL);
    p_comment("n, is a ~%d bit sized random odd number:", encryption_level);
    p_u1024(&num_n);
    p_comment("");
    p_comment("n's montgomery_factor = pow(2, 2^(2*(%d+2))) %% n:", 
	encryption_level);
    number_montgomery_factor_get(&num_montgomery_factor);
    p_u1024(&num_montgomery_factor);
    return 0;
}

static int test076(void)
{
    u1024_t num_4, num_5, num_8, num_9, res;

    number_small_dec2num(&res, (u64)4);
    number_small_dec2num(&num_5, (u64)5);
    number_small_dec2num(&num_8, (u64)8);
    number_small_dec2num(&num_9, (u64)9); /* modulus must be coprime with 2 */
    number_modular_multiplication_montgomery(&num_4, &num_5, &num_8, &num_9);
    return !number_is_equal(&num_4, &res);
}

static int test077(void)
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

static int test081(void)
{
    u1024_t num_4, num_7, num_5, num_9, res;

    number_small_dec2num(&res, (u64)4);
    number_small_dec2num(&num_7, (u64)7);
    number_small_dec2num(&num_5, (u64)5);
    number_small_dec2num(&num_9, (u64)9);
    number_modular_exponentiation_montgomery(&num_4, &num_7, &num_5, &num_9);
    return !number_is_equal(&num_4, &res);
}

static int test082(void)
{
    u1024_t num_7829, num_312, num_47, num_7919, res;

    number_small_dec2num(&res, (u64)7829);
    number_small_dec2num(&num_312, (u64)312);
    number_small_dec2num(&num_47, (u64)47);
    number_small_dec2num(&num_7919, (u64)7919);
    number_modular_exponentiation_montgomery(&num_7829, &num_312, &num_47, 
	&num_7919);
    return !number_is_equal(&num_7829, &res);
}

static int test083(void)
{ 
    u1024_t n, num_res, num_1, num_2;

    number_small_dec2num(&n, (u64)7);
    number_small_dec2num(&num_1, (u64)1);
    number_small_dec2num(&num_2, (u64)2);
    number_modular_exponentiation_montgomery(&num_res, &num_2, &num_1, &n);
    return !number_is_equal(&num_2, &num_res);
}

static int test084(void)
{ 
    u1024_t n, res1, res2, num_1, num_2, num_3, num_6;

    number_small_dec2num(&n, (u64)7);
    number_small_dec2num(&num_1, (u64)1);
    number_small_dec2num(&num_2, (u64)2);
    number_small_dec2num(&num_3, (u64)3);
    number_small_dec2num(&num_6, (u64)6);
    number_modular_exponentiation_montgomery(&res1, &num_2, &num_3, &n);
    number_modular_exponentiation_montgomery(&res2, &num_3, &num_3, &n);

    return !number_is_equal(&res1, &num_1) || !number_is_equal(&res2, &num_6);
}

static int test085(void)
{ 
    u1024_t res_0, res_1, num_0, num_1, num_4, n;

    number_assign(res_0, NUM_0);
    number_assign(res_1, NUM_1);
    number_assign(num_0, NUM_0);
    number_assign(num_1, NUM_1);
    number_small_dec2num(&num_4, (u64)4);
    number_small_dec2num(&n, (u64)7);
    number_modular_exponentiation_montgomery(&num_0, &num_0, &num_4, &n);
    number_modular_exponentiation_montgomery(&num_1, &num_1, &num_4, &n);

    return !number_is_equal(&res_0, &num_0) || !number_is_equal(&res_1, &num_1);
}

static int test086(void)
{ 
    int res; 
    u1024_t n, p1, p2, num_2, num_4, num_7, buf1, buf2, res1, res2;

    number_reset(&num_2);
    number_reset(&num_4);
    number_reset(&num_7);
    number_reset(&res1);
    number_reset(&res2);
    *(u64*)&num_2 = 2;
    *(u64*)&num_4 = 4;
    *(u64*)&num_7 = 7;
    *(u64*)&res1 = (u64)2;
    *(u64*)&res2 = (u64)16;

    number_init_str(&p1, 
	"0111000000011110000111011010101001000111011111101010101011101110"
	"1101101010110100100111101010111110100010100111100111101111000011"
	"1000010101111000011001011010111111000001101111001011000010000010"
	"1001010011000101100111100111110110110101010111101011101101001101"
	"0101010100101011111100010110001101111100110000110111001011111110"
	"0100010110000000111010011011001111101001011100101011100101001011"
	"1000010100011110111010111010000110001111011000000010100101101101"
	"0110010100101100001101001110000101101101010101011101101101001101");

    number_init_str(&p2,
	"0101011010000010111100110110101110011001011100010100010111011110"
	"0100100000010010001100010101011100001110101100011011001001001011"
	"1001001100101100100101110110000111101010101000010000111001110011"
	"1000110101101100001001010111011011001111011000001111110001000101"
	"0100001001101001101111110110011011011001000000110010010100101101"
	"0001101000010001000010100101110100100110110010111100001010010001"
	"1111100111011001010011011001110101111101001101100110010010000101"
	"0001010011111101100111100001110101001111000000111001011101010001");

    number_mul(&n, &p1, &p2);
    number_modular_exponentiation_montgomery(&buf1, &num_2, &num_4, &num_7);
    number_modular_exponentiation_montgomery(&buf2, &num_2, &num_4, &n);
    res = !(number_is_equal(&res1, &buf1) && number_is_equal(&res2, &buf2));

    return res;
}

static int test087(void)
{
    u1024_t res, pow, two, bit_sz;

    number_reset(&res);
    *((u64*)&res + block_sz_u1024 - 1) = MSB(u64);
    res.top = block_sz_u1024 - 1;
    number_small_dec2num(&two, (u64)2);
    number_small_dec2num(&bit_sz, (u64)(encryption_level - 1));

    number_exponentiation(&pow, &two, &bit_sz);
    return !number_is_equal(&res, &pow);
}

static int test091(void)
{
    u1024_t a, n;

    if (number_dec2bin(&a, "2") || number_dec2bin(&n, "5"))
    {
	printf("initializing a, n failed\n");
	return -1;
    }

    return number_witness(&a, &n);
}

static int test092(void)
{
    u1024_t num_n;

    number_dec2bin(&num_n, "7");
    return !number_is_prime(&num_n);
}

static int test093(void)
{
    u1024_t num_9;

    number_dec2bin(&num_9, "9");
    if (number_is_prime(&num_9))
    {
	p_comment("9 is non prime and was found to be prime");
	return -1;
    }
    return 0;
}

static int test094(void)
{
    u1024_t num_n;

    number_small_dec2num(&num_n, (u64)17);
    return !number_is_prime(&num_n);
}

static int test095(void)
{
    u1024_t n;
    char *dec = "99991";

    number_dec2bin(&n, dec);
    return !number_is_prime(&n);
}

static int test096(void)
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

    local_timer_start();
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
	    p_colour(C_NORMAL, "\n");
	    p_comment("%i is %sprime and was found to be %sprime", i,
		arr[i] ? "" : "non ", arr[i] ? "non " : "");
	    return -1;
	}
	if (i==3 || !(i%20))
	{
	    char *fmt = i==3 ? "%-17s" : "%s";

	    p_colour(C_GREY, fmt, "> ");
	}
	p_colour(arr[i] ? C_NORMAL : C_GREY, "%3s", str_num);
	p_colour(C_NORMAL, "%s", (i%20)==19 ? "\n" : ", ");
    }
    local_timer_stop();
    p_local_timer();
    return 0;
}

static int test097(void)
{
    u1024_t num;
    u64 p = (u64)1299709;
    int ret;

    number_small_dec2num(&num, p);
    p_u1024(&num);
    ret = number_is_prime(&num);
    p_comment("1299709 is prime%s", ret ? 
	"" : " and was found to be not prime");
    return !ret;
}

static int test098(void)
{
    u1024_t num_n;
    char *prime = "10726904659";
    int is_prime;

    number_dec2bin(&num_n, "10726904659");
    p_comment("%s is %sprime", prime, is_prime ? "" : "not ");
    return !is_prime;
}

static int test099(void)
{
    u1024_t num_n;
    char *prime = "55350776431903243";
    int is_prime;

    number_dec2bin(&num_n, prime);
    is_prime = number_is_prime(&num_n);
    p_comment("%s is %sprime", prime, is_prime ? "" : "not ");
    return !is_prime;
}

#define LSB_94R71_7 '7'
#define LSB_94R71_9 '9'
static int is_475bit_num_prime(char lsb)
{
    u1024_t num_n;
    char prime[143];
    int i, is_prime;

    for (i = 0; i < 71*2; i = i + 2)
    {
	prime[i] = '9';
	prime[i + 1] = '4';
    }
    prime[142] = lsb;
    prime[143] = 0;

    /* 475 bits */
    number_dec2bin(&num_n, prime);
    local_timer_start();
    is_prime = number_is_prime(&num_n);
    local_timer_stop();
    p_comment("94R(71)%c is %sprime", lsb, is_prime ? "" : "not ");
    p_local_timer();

    return is_prime;
}

static int test100(void)
{
    /* 94R(71)7 is not prime */
    return is_475bit_num_prime(LSB_94R71_7);
}

static int test101(void)
{
    /* 94R(71)9 is prime */
    return !is_475bit_num_prime(LSB_94R71_9);
}
#undef LSB_94R71_7 
#undef LSB_94R71_9 

static int test102(void)
{
    u1024_t num_n;
    char *non_prime = "2285760293497823444790323455592340983477";
    int is_prime;

    number_dec2bin(&num_n, non_prime);
    is_prime = number_is_prime(&num_n);
    p_comment("%s is %sprime", non_prime, is_prime ? "" : "not ");
    return is_prime;
}

static int test106(void)
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

static int test107(void)
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

static int rsa_key_generator_do(void)
{
    char c = 0;
    int is_do;

    if (!ask_user)
	return 1;

    s_comment("do you want to perform this test? [Y/n] ", "%c",	&c);
    if (!(is_do = (c != 'n' && c != 'N')))
	p_comment("skipping...");
    return is_do;
}

static void rsa_key_generator(u1024_t *p1, u1024_t *p2, u1024_t *n, u1024_t *e, 
    u1024_t *d, int is_print)
{
    u1024_t p1_sub1, p2_sub1, phi;
    int iter = 0;
    static int init;
    static u1024_t min;

    if (!init)
    {
	u64 *ptr;

	for (ptr = (u64*)&min; ptr < (u64*)&min + block_sz_u1024; ptr++)
	    *ptr = 1;
	min.top = block_sz_u1024 - 1;
	init = 1;
    }

    do
    {
	if (is_print)
	{
	    local_timer_start();
	    p_comment("finding large prime p1...");
	}
	number_find_prime(p1);
	if (is_print)
	    p_comment("finding large prime p2...");
	number_find_prime(p2);

	if (is_print)
	    p_comment("calculating n = p1*p2...");
	number_mul(n, p1, p2);

	number_assign(p1_sub1, *p1);
	number_assign(p2_sub1, *p2);
	number_sub1(&p1_sub1);
	number_sub1(&p2_sub1);
	if (is_print)
	    p_comment("calculating phi = (p1-1)*(p2-1)...");
	number_mul(&phi, &p1_sub1, &p2_sub1);

	if (is_print)
	{
	    p_comment("generating puglic key: (e, n) - where e is coprime with "
		"phi...");
	}
	number_init_random_coprime(e, &phi);
	if (is_print)
	{
	    p_comment("calculating private key: (d, n) - where d is the "
		"multiplicative inverse of e mod phi...");
	}
	number_modular_multiplicative_inverse(d, e, &phi);
	if (is_print)
	{
	    local_timer_stop();
	    p_local_timer();
	}

	iter++;
    }
    while (!number_is_greater_or_equal(n, &min));

    if (iter > 1)
	p_comment("key generation required %d iterations", iter);
}

static int rsa_pre_encrypt(u1024_t *input, u64 *multiplier, u1024_t *encryptor,
    u1024_t *n)
{
    u1024_t q, num_0;

    if (!number_is_greater_or_equal(input, n))
    {
	number_assign(*encryptor, *input);
	*multiplier = (u64)0;
	return 0;
    }
    number_dev(&q, encryptor, input, n);
    *multiplier = *(u64*)&q;

    /* varify that q can be represented by a u64 */
    number_shift_right(&q, bit_sz_u64);
    number_reset(&num_0);
    return !number_is_equal(&q, &num_0);
}

static int rsa_post_decrypt(u1024_t *output, u64 multiplier, 
    u1024_t *decryption, u1024_t *n)
{
    if (multiplier)
    {
	u1024_t num_multipier;

	number_small_dec2num(&num_multipier, multiplier);
	number_mul(output, &num_multipier, n);
	number_add(output, output, decryption);
    }
    else
	number_assign(*output, *decryption);

    return *((u64*)&output->arr + block_sz_u1024) ? -1 : 0;
}

static int rsa_encryptor_decryptor(u1024_t *n, u1024_t *e, u1024_t *d, 
    u1024_t *data, int is_print)
{
    int res;
    u1024_t input, output, encryption, decryption, r;
    u64 q;

    if (!data)
	number_str2num(&input, code2str(el2phrase, encryption_level));
    else
	number_assign(input, *data);
    number_reset(&encryption);
    number_reset(&decryption);

    /* RSA requires that input is in Zn, that is: 1 <= input < n */
    if (rsa_pre_encrypt(&input, &q, &r, n))
	return -1;
    if (is_print)
    {
	p_comment("data: \"%s\"", &input);
	p_comment("encrypting...");
	local_timer_start();
    }
    number_modular_exponentiation_montgomery(&encryption, &r, e, n);
    if (is_print)
    {
	local_timer_stop();
	p_local_timer();

	p_comment("decrypting...");
	local_timer_start();
    }
    number_modular_exponentiation_montgomery(&decryption, &encryption, d, n);
    if (is_print)
    {
	local_timer_stop();
	p_local_timer();
    }

    if (rsa_post_decrypt(&output, q, &decryption, n))
	return -1;
    res = !number_is_equal(&input, &output);
    if (is_print)
    {
	p_comment("decryption of encrypted data %s data",  res ? 
	    "does not equal" : "equals");
    }
    return res;
}

static int test108(void)
{ 
    u1024_t p1, p2, n, e, d;

    number_init_str(&p1, 
	"1000000100010100111001000110011011001010010011110011011101111000"
	"1000101011110100100010011000110010100101000011011100000111110011"
	"0000010110101011001110110110111000001000100100101101000001110010"
	"1100100101101110101110011010111101001100101111011000111101001110"
	"1011110001010001001111110100001011010010110111111110010011011110"
	"0010001111000101011011011111011111110110111011111100011111101000"
	"1010011010001100001011110101000101101010111111110000111001101100"
	"0111101001110110011110010000110010001110011001101001001110101111");

    number_init_str(&p2,
	"1000001111101111010111100000010010011011010010010100001011100000"
	"1010101100111111010000000001011010000001000100011010110011000011"
	"0011100111100100101100001000110010101010111110111110001000010011"
	"1001110101111100110010110111100100101000110100111100110101101101"
	"1111110011101101110011101101110100001010101100100010000111011110"
	"0111110011000111110101110111100001111111111101110111000010001011"
	"1000010111000010111111011110100100111001011011001010110011010000"
	"0001010001100100011000110110000100110001111011010111110101101001");
    p_comment("calculating n = p1*p2...");
    number_mul(&n, &p1, &p2);

    number_init_str(&e,
	"0000010000011100101101000001011101101100000110010100010111010110"
	"0100001000111101001111010111010001001010110001110100000111101111"
	"0101010100111011010100101111010101100110000000100101000111010100"
	"0101100100000000011001010011110100010101001000001000000111101000"
	"0110010101000101111101110000001000111111110000000001101101111001"
	"0010111111101000110111011001100101100011100011011111100101101001"
	"0110111100011111100110110011001001100010111011010101011010011100"
	"0011011001011110001100001000101101001100000111011100100010111100"
	"0010111000000111111101101110101100110110110110111111000111110110"
	"0010111000000111010011000010010001011100111110111010101001000101"
	"0101010010000001100001011001111100001110000001100011100000001010"
	"0101110110101100011001011010010100001000000000001000100000111110"
	"0010010000111000010101001000011100110100000011010010101000010101"
	"0011111010110010100111101010001100111010010011010001100000111110"
	"0010010000010001100010001000111001011101110011110101000000011000"
	"0111001100111100101111110110110000111001010101010111001000101001");

    number_init_str(&d,
	"0000100101100011001100100100100110100010011001011101000010111100"
	"0001101001111111011110110110011011001110000000100110100010101011"
	"0110010011001001111111011011000010001000111111010011000010011000"
	"1000001011000101101101111110101111011000110000001101101110000001"
	"0000001100101100010000000110100000100011111111110000010000111111"
	"0100100111100000001110111001010010001111101111100010010111110100"
	"1010000000001100101001010011010110001001100110100010101110111111"
	"0110011111101011000111111100110100110000001001101011000100001100"
	"1110000101001100101100000001101110011110111001000010111111110000"
	"1010000111100001000011101001100111111111110001110110111011111100"
	"1000101110011111111000000010010010110000001110011111000011001001"
	"1011111111000000101101110101011001110110010010100100000001110100"
	"1110011000110011010100011100101111001100101111111000110010010101"
	"1100101111100001101010101000010101111110100011100000010100001010"
	"0100101111010011110010111000100001111001000000000110101000101111"
	"0101111010011110010110011001010010010111101000111110100101001001");

    /* note, cannot compute ed%phi:
     * - number_modular_multiplication_montgomery cannot be used since 
     *   gcd(phi,radix(phi)) != 1
     * - number_modular_multiplication_naive cannot be used since e and d are
     *   ~1024 bit number and cannot be multiplied naively in a 1024 bit buffer.
     */
    return rsa_encryptor_decryptor(&n, &e, &d, NULL, 1);
}

static int test109(void)
{ 
    u1024_t p1, p2, n, e, d, data;
	
    number_init_str(&data, 
	"0000000000000000011001010111001101100001011010000111000000100000"
	"0111010001101001011000100010000000110001001100110010000001100001");

    number_init_str(&p1, 
	"1011010001000100100011101100011110010000011010011010110111110101");

    number_init_str(&p2,
	"1101010011111100001011111011000100101111111100000011010110111001");
    number_mul(&n, &p1, &p2);

    number_init_str(&e,
	"0111101001111100100110010101111100000001011011001001000000100000"
	"0001110001111101011010101011111001011001011110110110001001100101"
	);

    number_init_str(&d,
	"0111000000010010110011101110101101110000100000100111100001001100"
	"0000011111100001111000110100100111101000111010111110101011101101"
	);

    return rsa_encryptor_decryptor(&n, &e, &d, &data, 1);
}

static int test110(void)
{ 
    u1024_t p1, p2, n, e, d, data;
	
    number_str2num(&data, code2str(el2phrase, encryption_level));

    number_init_str(&p1, 
	"0101010000011110100111111100011110011111100101010000011100011001"
	);

    number_init_str(&p2,
	"0111100101110011100110011110001001110101110100100110000000010111"
	);
    number_mul(&n, &p1, &p2);

    number_init_str(&e,
	"0001100011000010110100110001111010010100000101100100100000011011"
	"0001001000101111010001001010110110110110101001101111000000011001"
	);

    number_init_str(&d,
	"0001111101100000110101000111101110110100011000011010011011111100"
	"1011111010011100101111110000010001010100100111100110001101011001"
	);

    return rsa_encryptor_decryptor(&n, &e, &d, &data, 1);
}

static int test112(void)
{
    u1024_t p1, p2, n, s, res;

    number_init_str(&res, 
	"1000010110111011100111000000100110111110101111010010011111110000"
	"0001111110100110110100111011101000001110011001001001111011000001"
	);
    number_init_str(&p1, 
	"1011010001000100100011101100011110010000011010011010110111110101");
    number_init_str(&p2,
	"1101010011111100001011111011000100101111111100000011010110111001");
    number_mul(&n, &p1, &p2);
    number_init_str(&s,
	"0111010101111100110111001100010001010010000100011000101111111010"
	"1110100001101011000111001110111011001110101101101100111001110101");
    number_add(&s, &s, &n);
    number_shift_right_once(&s);
    p_u1024(&s);

    return !number_is_equal(&s, &res);
}

static int test116(void)
{ 
    u1024_t p1, p2, n, e, data, encryption;
    int i, iter;
    char *quantity;

    switch (encryption_level)
    {
    case 128:
	iter = (K*B)/(bit_sz_u64 * block_sz_u1024);
	quantity = "1KB";
	break;
    case 1024:
	iter = K/(bit_sz_u64 * block_sz_u1024);
	quantity = "128B";
	break;
    default:
	p_comment("encryption_level %d not supported by this test", 
	    encryption_level);
	return -1;
    }

    number_init_str(&data, code2str(el2data, encryption_level));
    number_init_str(&p1, code2str(el2p1, encryption_level));
    number_init_str(&p2, code2str(el2p2, encryption_level));
    number_mul(&n, &p1, &p2);
    number_init_str(&e, code2str(el2e, encryption_level));

    p_comment("encrypting %s of data:", quantity);
    local_timer_start();
    for (i = 0; i < iter; i++)
	number_modular_exponentiation_montgomery(&encryption, &data, &e, &n);
    local_timer_stop();
    p_local_timer();
    return 0;
}

static int test117(void)
{
    u1024_t p1, p2, n, e, d;

    rsa_key_generator(&p1, &p2, &n, &e, &d, 1);
    return rsa_encryptor_decryptor(&n, &e, &d, NULL, 1);
}

static int test118(void)
{
#define MULTIPLE_RSA "1000"
#define LEN 50 

    u1024_t p1, p2, n, e, d;
    int i, timeout, iter;
    char *err = NULL;

    if (!rsa_key_generator_do())
	return 0;

    iter = strtol(MULTIPLE_RSA, &err, 10);
    if (*err)
    {
	p_comment("MULTIPLE_RSA (%s) must be an integer string", MULTIPLE_RSA);
	return -1;
    }
    timeout = iter/LEN;
    io_init();
    for (i = 1; i <= iter; i++)
    {
	rsa_key_generator(&p1, &p2, &n, &e, &d, 0);
	if (rsa_encryptor_decryptor(&n, &e, &d, NULL, 0))
	    goto error;
	if (!(i%(iter/LEN)))
	    vio_colour(vprintf, C_GREY, ".", NULL);
    }
    fprintf(stdout, "\n");
    return 0;

error:
    fprintf(stdout, "\n");
    p_comment("iteration %d failed", i + 1);
    p_comment("p1:");
    p_u1024(&p1);
    p_comment("p2:");
    p_u1024(&p2);
    p_comment("n:");
    p_u1024(&n);
    p_comment("e:");
    p_u1024(&e);
    p_comment("d:");
    p_u1024(&d);

    return -1;
#undef LEN
}

static int test120(void)
{
    u1024_t p1, p2, n, e, d, input, encryption, decryption, num_xor, seed;
    int res;

    rsa_key_generator(&p1, &p2, &n, &e, &d, 1);

    number_str2num(&input, code2str(el2phrase, encryption_level));
    p_comment("data: \"%s\"", &input);

    p_comment("encrypting...");
    local_timer_start();
    number_reset(&seed);
    if (number_seed_set_random(&seed))
    {
	p_comment("number_seed_set_random()");
	return -1;
    }
    number_modular_exponentiation_montgomery(&seed, &seed, &e, &n);
    number_init_random(&num_xor, block_sz_u1024);
    number_xor(&encryption, &num_xor, &input);
    local_timer_stop();
    p_local_timer();

    p_comment("decrypting...");
    local_timer_start();
    number_modular_exponentiation_montgomery(&seed, &seed, &d, &n);
    if (number_seed_set_fixed(&seed))
    {
	p_comment("number_seed_set_fixed()");
	return -1;
    }
    number_init_random(&num_xor, block_sz_u1024);
    number_xor(&decryption, &num_xor, &encryption);
    local_timer_stop();
    p_local_timer();

    res = !number_is_equal(&input, &decryption);
    p_comment("decryption of encrypted data %s data",  res ? 
	"does not equal" : "equals");
    return res;
}

static int test125(void)
{ 
    u1024_t p1, p2, n, e, data, encryption, seed;
    int i, mb, iter;

    mb = 5;
    iter = (mb * M*B)/(bit_sz_u64 * block_sz_u1024);

    number_init_str(&data, code2str(el2data, encryption_level));
    number_init_str(&p1, code2str(el2p1, encryption_level));
    number_init_str(&p2, code2str(el2p2, encryption_level));
    number_mul(&n, &p1, &p2);
    number_init_str(&e, code2str(el2e, encryption_level));

    p_comment("encrypting %dMB of data:", mb);
    local_timer_start();
    p_comment("seeding pseudo random number generator...");
    if (number_seed_set_random(&seed))
    {
	p_comment("number_seed_set_random()");
	return -1;
    }
    number_seed_set_fixed(&seed);
    number_modular_exponentiation_montgomery(&seed, &seed, &e, &n);
    local_timer_stop();
    p_local_timer();
    p_comment("encrypting...");
    local_timer_start();
    for (i = 0; i < iter; i++)
    {
	u1024_t num_xor;

	number_init_random(&num_xor, block_sz_u1024);
	number_xor(&encryption, &num_xor, &data);
    }
    local_timer_stop();
    p_local_timer();
    return 0;
}

typedef struct test130_t {
    int i;
    char c;
} test130_t;

static int test130(void)
{
#define FNAME_1 "f1"
#define FNAME_2 "f2"

    char x[100];
    FILE *f;
    int i;

    bzero(x, 100);
    p_comment("sizeof(int) = %i", sizeof(int));
    p_comment("sizeof(char) = %i", sizeof(char));
    p_comment("sizeof(test130_t) = %i", sizeof(test130_t));
    p_comment("sizeof(u64) = %i", sizeof(u64));

    i = 0;
    f = fopen(FNAME_1, "w+");
    i += fwrite("hello", strlen("hello"), 1, f);
    i += fwrite("nice", strlen("nice"), 1, f);
    i += fwrite("world", strlen("world"), 1, f);
    fclose(f);
    p_comment("wrote %i test130_t", i);

    i = 0;
    f = fopen(FNAME_1, "r+");
    i += fread(x, strlen("hello"), 1, f);
    i += fread(x + strlen("hello"), strlen("nice"), 1, f);
    fclose(f);
    p_comment("read %i test130_t", i);

    f = fopen(FNAME_2, "w+");
    p_comment("wrote %i test130_t", fwrite(x, strlen(x), 1, f));
    fclose(f);

    remove(FNAME_1);
    remove(FNAME_2);

    return 0;

#undef FNAME_2
#undef FNAME_1
}

#if 0
static int test117(void)
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

void test118(void)
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

static void test119(void)
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

static test_t rsa_tests[] = 
{
    /* basics: data structure sizes */
    {
	description: "RSA data structure sizes",
	func: test001,
    },
    /* basics: data structure initiation */
    {
	description: "number_init_str()",
	func: test006,
    },
    {
	description: "number_dec2bin()",
	func: test007,
	disabled: DISABLE_USHORT | DISABLE_ULONG | DISABLE_ULLONG,
    },
    {
	description: "number_dec2bin() - edge conditions",
	func: test008,
	disabled: DISABLE_USHORT | DISABLE_ULONG | DISABLE_ULLONG,
    },
    {
	description: "number_dec2bin() - max size number",
	func: test009,
	disabled: DISABLE_UCHAR | DISABLE_USHORT | DISABLE_ULONG,
    },
    {
	description: "number_dec2bin() - edge conditions",
	func: test010,
	disabled: DISABLE_UCHAR | DISABLE_USHORT | DISABLE_ULONG,
    },
    {
	description: "number_init_random() - compare many numbers",
	func: test011,
    },
    /* number addition */
    {
	description: "number_add() - basic functionality",
	func: test016,
    },
    {
	description: "number_add() - edge condition",
	func: test017,
	disabled: DISABLE_USHORT | DISABLE_ULONG | DISABLE_ULLONG,
    },
    {
	description: "number_add() - functionality",
	func: test018,
	disabled: DISABLE_USHORT | DISABLE_ULONG | DISABLE_ULLONG,
    },
    {
	description: "number_add() - random numbers",
	func: test019,
	disabled: DISABLE_TIME_FUNCTIONS,
    },
    {
	description: "number_add() - testing new implementation",
	func: test020,
	disabled: DISABLE_TIME_FUNCTIONS,
    },
    /* right and left shifting */
    {
	description: "number_shift_right_once() - basic functionality",
	func: test025,
	disabled: DISABLE_UCHAR | DISABLE_USHORT | DISABLE_ULONG | 
	    DISABLE_ULLONG_64 | DISABLE_ULLONG_256 | DISABLE_ULLONG_512 | 
	    DISABLE_ULLONG_1024,
    },
    {
	description: "number_shift_right()",
	func: test026,
	disabled: DISABLE_USHORT | DISABLE_ULONG | DISABLE_ULLONG,
    },
    {
	description: "number_shift_left() - functionality",
	func: test027,
    },
    {
	description: "number_shift_left() - edge condition",
	func: test028,
	disabled: DISABLE_USHORT | DISABLE_ULONG | DISABLE_ULLONG,
    },
    {
	description: "number_shift_left() - edge conditions, "
	    "random numbers",
	func: test029,
	disabled: DISABLE_USHORT | DISABLE_ULONG | DISABLE_ULLONG,
    },
    /* number multiplication  */
    {
	description: "number_mul() - multiplicand > multiplier",
	func: test031,
	disabled: DISABLE_USHORT | DISABLE_ULONG | DISABLE_ULLONG,
    },
    {
	description: "number_mul() - multiplicand < multiplier",
	func: test032,
	disabled: DISABLE_USHORT | DISABLE_ULONG | DISABLE_ULLONG,
    },
    {
	description: "number_mul() - big numbers",
	func: test033,
	disabled: DISABLE_USHORT | DISABLE_ULONG | DISABLE_ULLONG,
    },
    {
	description: "(2x3x11x13x17x19)^10 x (5x7x23x29x31x37x41)^11",
	func: test034,
	disabled: DISABLE_UCHAR | DISABLE_USHORT | DISABLE_ULONG | 
	    DISABLE_ULLONG_64 | DISABLE_ULLONG_128 | DISABLE_ULLONG_256 | 
	    DISABLE_ULLONG_512,
    },
    {
	description: "multiply the first 75 primes (and again by the 4th)",
	func: test035,
	disabled: DISABLE_UCHAR | DISABLE_USHORT | DISABLE_ULONG | 
	    DISABLE_ULLONG_64 | DISABLE_ULLONG_128 | DISABLE_ULLONG_256 | 
	    DISABLE_ULLONG_512,
    },
    /* number subtraction */
    {
	description: "number_is_greater() and number_is_equal()",
	func: test041,
	disabled: DISABLE_USHORT | DISABLE_ULONG | DISABLE_ULLONG,
    },
    {
	description: "number_is_greater() u1024_t.arr.buffer != 0",
	func: test042,
	disabled: DISABLE_UCHAR | DISABLE_USHORT | DISABLE_ULONG | 
	    DISABLE_ULLONG_64 | DISABLE_ULLONG_128 | DISABLE_ULLONG_256 | 
	    DISABLE_ULLONG_512,
    },
    {
	description: "number_sub() - basic functionality",
	func: test043,
	disabled: DISABLE_USHORT | DISABLE_ULONG | DISABLE_ULLONG,
    },
    {
	description: "number_sub() - advanced functionality",
	func: test044,
	disabled: DISABLE_USHORT | DISABLE_ULONG | DISABLE_ULLONG,
    },
    {
	description: "number_sub() - subtacting from zero",
	func: test045,
	disabled: DISABLE_USHORT | DISABLE_ULONG | DISABLE_ULLONG,
    },
    {
	description: "negative numbers",
	func: test046,
	disabled: DISABLE_USHORT | DISABLE_ULONG | DISABLE_ULLONG,
    },
    {
	description: "number_absolute_value()",
	func: test047,
	disabled: DISABLE_USHORT | DISABLE_ULONG | DISABLE_ULLONG,
    },
    {
	description: "negative and absolute numbers",
	func: test048,
	disabled: DISABLE_USHORT | DISABLE_ULONG | DISABLE_ULLONG,
    },
    /* number devision */
    {
	description: "number_dev() - basic functionality",
	func: test051,
	disabled: DISABLE_USHORT | DISABLE_ULONG | DISABLE_ULLONG,
    },
    {
	description: "number_dev()",
	func: test052,
	disabled: DISABLE_USHORT | DISABLE_ULONG | DISABLE_ULLONG,
    },
    {
	description: "number_dev() - deviding a number by a larger number",
	func: test053,
	disabled: DISABLE_USHORT | DISABLE_ULONG | DISABLE_ULLONG,
    },
    {
	description: "deviding a 475 bit number by 29",
	func: test054,
	disabled: DISABLE_UCHAR | DISABLE_USHORT | DISABLE_ULONG | 
	    DISABLE_ULLONG_64 | DISABLE_ULLONG_128 | DISABLE_ULLONG_256 | 
	    DISABLE_ULLONG_512,
    },
    {
	description: "number_mod() sanity test",
	func: test055,
	disabled: DISABLE_UCHAR | DISABLE_USHORT | DISABLE_ULONG,
    },
    {
	description: "number_extended_euclid_gcd()",
	func: test056,
	disabled: DISABLE_UCHAR,
    },
    {
	description: "number_modular_multiplicative_inverse()",
	func: test057,
	disabled: DISABLE_UCHAR | DISABLE_USHORT | DISABLE_ULONG,
    },
    /* finding most significant bit */
    {
	description: "number_find_most_significant_set_bit()",
	func: test061,
	disabled: DISABLE_USHORT | DISABLE_ULONG | DISABLE_ULLONG,
    },
    {
	description: "number_find_most_significant_set_bit()",
	func: test062,
	disabled: DISABLE_UCHAR | DISABLE_USHORT | DISABLE_ULONG,
    },
    /* naive modular multiplication */
    {
	description: "number_modular_multiplication_naive()",
	func: test063,
	disabled: DISABLE_USHORT | DISABLE_ULONG | DISABLE_ULLONG,
    },
    {
	description: "naive modular multiplication and exponentiation",
	func: test064,
	disabled: DISABLE_UCHAR | DISABLE_ULONG | DISABLE_ULLONG,
    },
    /* naive modular exponentiation */
    {
	description: "number_modular_exponentiation_naive() - basic "
	    "functionality",
	func: test066,
	disabled: DISABLE_USHORT | DISABLE_ULONG | DISABLE_ULLONG,
    },
    {
	description: "number_modular_exponentiation_naive() - advanced",
	func: test067,
	disabled: DISABLE_USHORT | DISABLE_ULONG | DISABLE_ULLONG,
    },
    {
	description: "number_modular_exponentiation_naive()",
	func: test068,
	disabled: DISABLE_UCHAR,
    },
    {
	description: "number_modular_exponentiation_naive() - large power of 2",
	func: test069,
	disabled: DISABLE_UCHAR | DISABLE_USHORT | DISABLE_ULONG,
    },
    /* setting montgomery factor: 2^(2(encryption_level+2)) */
    {
	description: "number_montgomery_factor_set()",
	func: test071,
	disabled: DISABLE_UCHAR | DISABLE_USHORT | DISABLE_ULONG | 
	    DISABLE_ULLONG_64 | DISABLE_ULLONG_128  | DISABLE_ULLONG_256 | 
	    DISABLE_ULLONG_512,
    },
    {
	description: "number_montgomery_factor_set() - for a random number",
	func: test072,
	disabled: DISABLE_UCHAR,
    },
    /* montgomery modular multiplication */
    {
	description: "number_modular_multiplication_montgomery()",
	func: test076,
	disabled: DISABLE_UCHAR,
    },
    {
	description: "number_modular_multiplication_montgomery()",
	func: test077,
	disabled: DISABLE_UCHAR,
    },
    /* montgomery modular exponentiation */
    {
	description: "number_modular_exponentiation_montgomery()",
	func: test081,
	disabled: DISABLE_UCHAR,
    },
    {
	description: "number_modular_exponentiation_montgomery()",
	func: test082,
	disabled: DISABLE_UCHAR,
    },
    {
	description: "number_modular_exponentiation_montgomery()",
	func: test083,
	disabled: DISABLE_UCHAR,
    },
    {
	description: "number_modular_exponentiation_montgomery()",
	func: test084,
	disabled: DISABLE_UCHAR,
    },
    {
	description: "number_modular_exponentiation_montgomery()",
	func: test085,
	disabled: DISABLE_UCHAR,
    },
    {
	description: "exponentiation modolo a larg number",
	func: test086,
	disabled: DISABLE_UCHAR | DISABLE_USHORT | DISABLE_ULONG | 
	    DISABLE_ULLONG_64 | DISABLE_ULLONG_128 | DISABLE_ULLONG_256 | 
	    DISABLE_ULLONG_512,
    },
    {
	description: "2^(encryption_level - 1)",
	func: test087,
	disabled: DISABLE_UCHAR | DISABLE_USHORT | DISABLE_ULONG | 
	    DISABLE_TIME_FUNCTIONS,
    },
    /* primality testing */
    {
	description: "number_witness() - basic functionality",
	func: test091,
	disabled: DISABLE_USHORT | DISABLE_ULONG | DISABLE_ULLONG,
    },
    {
	description: "number_is_prime(7) - basic functionality",
	func: test092,
	disabled: DISABLE_UCHAR | DISABLE_ULONG | DISABLE_ULLONG,
    },
    {
	description: "number_is_prime(9)",
	func: test093,
	disabled: DISABLE_UCHAR | DISABLE_ULONG | DISABLE_ULLONG,
    },
    {
	description: "number_is_prime(17) - basic functionality",
	func: test094,
	disabled: DISABLE_UCHAR | DISABLE_ULONG | DISABLE_ULLONG,
    },
    {
	description: "number_is_prime(99991)",
	func: test095,
	disabled: DISABLE_UCHAR | DISABLE_ULONG | DISABLE_ULLONG,
    },
    {
	description: "number_is_prime() primes in [3, 999]",
	func: test096,
	disabled: DISABLE_UCHAR | DISABLE_ULONG | DISABLE_ULLONG_64 | 
	    DISABLE_ULLONG_256 | DISABLE_ULLONG_512 | DISABLE_ULLONG_1024,
    },
    {
	description: "number_is_prime the 100000th prime)",
	func: test097,
	disabled: DISABLE_UCHAR | DISABLE_USHORT
    },
    {
	description: "number_is_prime(10,726,904,659) - large prime",
	func: test098,
	disabled: DISABLE_UCHAR,
    },
    {
	description: "number_is_prime(55,350,776,431,903,243) - very large "
	    "prime",
	func: test099,
	disabled: DISABLE_UCHAR,
    },
    {
	description: "number_is_prime(94R(71)7) - 475 bit non prime",
	func: test100,
	disabled: DISABLE_UCHAR | DISABLE_USHORT | DISABLE_ULONG | 
	    DISABLE_ULLONG_64 | DISABLE_ULLONG_128 | DISABLE_ULLONG_256 | 
	    DISABLE_ULLONG_512 | DISABLE_TIME_FUNCTIONS,
    },
    {
	description: "number_is_prime(94R(71)9) - 475 bit prime",
	func: test101,
	disabled: DISABLE_UCHAR | DISABLE_USHORT | DISABLE_ULONG | 
	    DISABLE_ULLONG_64 | DISABLE_ULLONG_128 | DISABLE_ULLONG_256 | 
	    DISABLE_ULLONG_512 | DISABLE_TIME_FUNCTIONS,
    },
    {
	description: "number_is_prime("
	    "2,285,760,293,497,823,444,790,323,455,592,340,983,477) - very "
	    "large non prime",
	func: test102,
	disabled: DISABLE_UCHAR | DISABLE_USHORT | DISABLE_ULONG,
    },
    /* RSA key generation, encryption and decryption */
    {
	description: "coprimality testing",
	func: test106,
	disabled: DISABLE_UCHAR | DISABLE_USHORT | DISABLE_ULONG,
    },
    {
	description: "number_find_prime()",
	func: test107,
	disabled: DISABLE_UCHAR | DISABLE_USHORT | DISABLE_ULONG,
    },
    {
	description: "encryption - decryption with length(n=p1xp2)=1024 bits",
	func: test108,
	disabled: DISABLE_UCHAR | DISABLE_USHORT | DISABLE_ULONG | 
	    DISABLE_ULLONG_64 | DISABLE_ULLONG_128 | DISABLE_ULLONG_256 | 
	    DISABLE_ULLONG_512,
    },
    {
	description: "encryption - decryption: overflow during "
	    "num_montgomery_factor cration",
	func: test109,
	disabled: DISABLE_UCHAR | DISABLE_USHORT | DISABLE_ULONG | 
	    DISABLE_ULLONG_64 | DISABLE_ULLONG_256 | DISABLE_ULLONG_512 | 
	    DISABLE_ULLONG_1024,
    },
    {
	description: "number_str2num()",
	func: test110,
	disabled: DISABLE_UCHAR | DISABLE_USHORT | DISABLE_ULONG | 
	    DISABLE_ULLONG_64 | DISABLE_ULLONG_256 | DISABLE_ULLONG_512 | 
	    DISABLE_ULLONG_1024,
    },
    {
	description: "mul, add and shift",
	func: test112,
	disabled: DISABLE_UCHAR | DISABLE_USHORT | DISABLE_ULONG | 
	    DISABLE_ULLONG_64 | DISABLE_ULLONG_256 | DISABLE_ULLONG_512 | 
	    DISABLE_ULLONG_1024,
    },
    {
	description: "multiple encryption",
	func: test116,
	disabled: DISABLE_UCHAR | DISABLE_USHORT | DISABLE_ULONG | 
	    DISABLE_ULLONG_64 | DISABLE_ULLONG_256 | DISABLE_ULLONG_512,
    },
    {
	description: "complete RSA test - key generation, encryption and "
	    "decryption",
	func: test117,
	disabled: DISABLE_UCHAR | DISABLE_USHORT | DISABLE_ULONG | 
	    DISABLE_TIME_FUNCTIONS,
    },
    {
	description: "multiple RSA key generation (" MULTIPLE_RSA 
	    " iterations)",
	func: test118,
	disabled: DISABLE_UCHAR | DISABLE_USHORT | DISABLE_ULONG | 
	    DISABLE_ULLONG_64 | DISABLE_ULLONG_256 | DISABLE_ULLONG_512 | 
	    DISABLE_ULLONG_1024 | DISABLE_TIME_FUNCTIONS,
    },
    /* symmetric/asymmetric key combination */
    {
	description: "complete RSA + symmetric key test - key generation, "
	    "encryption and decryption",
	func: test120,
	disabled: DISABLE_UCHAR | DISABLE_USHORT | DISABLE_ULONG | 
	    DISABLE_TIME_FUNCTIONS,
    },
    {
	description: "multiple encryption using symmetric/asymmetric key "
	    "combination",
	func: test125,
	disabled: DISABLE_UCHAR | DISABLE_USHORT | DISABLE_ULONG | 
	    DISABLE_ULLONG_64 | DISABLE_ULLONG_256 | DISABLE_ULLONG_512,
    },

    /* RSA io */
    {
	description: "test fread() and fwrite()",
	known_issue: "wrong result for sizeof(test58_t)",
	func: test130,
	disabled: DISABLE_UCHAR | DISABLE_USHORT | DISABLE_ULONG,
    },
#if 0
    {
	description: "encryption - decryption test, keys read from files",
	known_issue: "missing input files",
	func: test135,
#ifndef ULLONG
	disabled: 1,
#endif
    },
#endif
    {0},
};

/*
static test_t tests[] = 
{
    { "encryption - decryption test", test118, DISABLED },
    { "montgomery multiplication of large numbers", test119, DISABLED },
    { }
};
*/

static char *p_u64_type(void)
{
    static char u64_type_str[25];

    sprintf(u64_type_str, "%s", "u64 = ");
    strcat(u64_type_str, 
#if defined UCHAR
    "unsigned char"
#elif defined USHORT
    "unsigned short"
#elif defined ULONG
    "unsigned long"
#else
    "unsigned long long"
#endif
    );

    return u64_type_str;
}

static void rsa_tests_init(int argc, char *argv[])
{
#if defined(UCHAR) || defined(USHORT) || defined(ULONG)
    block_sz_u1024 = 16;
    encryption_level = bit_sz_u64 * block_sz_u1024;
#else
    number_enclevl_set(ENC_LEVEL);
#endif
}

static void rsa_pre_test(void)
{
    init_reset = 1;
    number_random_seed = 0;
}

static int rsa_is_disabled(int flags)
{
#if defined TIME_FUNCTIONS
    if (flags & DISABLE_TIME_FUNCTIONS)
	return 1;
#endif
#if defined(UCHAR)
    return flags & DISABLE_UCHAR;
#elif defined(USHORT)
    return flags & DISABLE_USHORT;
#elif defined(ULONG)
    return flags & DISABLE_ULONG;
#else /* ULLONG */
    switch (encryption_level)
    {
    case 64:
	return flags & DISABLE_ULLONG_64;
    case 128:
	return flags & DISABLE_ULLONG_128;
    case 256:
	return flags & DISABLE_ULLONG_256;
    case 512:
	return flags & DISABLE_ULLONG_512;
    case 1024:
	return flags & DISABLE_ULLONG_1024;
    default:
	return 1;
    }
#endif
}

int main(int argc, char *argv[])
{
    unit_test_t tests;
    char *comment = p_u64_type();

    tests.arr = rsa_tests;
    tests.size = ARRAY_SZ(rsa_tests);
    tests.list_comment = comment;
    tests.summery_comment = comment;
    tests.tests_init = rsa_tests_init;
    tests.is_disabled = rsa_is_disabled;
    tests.pre_test = rsa_pre_test;

    return unit_test(argc, argv, &tests);
}

