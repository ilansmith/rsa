#include "rsa.h"
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <sys/time.h>

typedef void (* test_func_t)(void);
typedef struct {
    char *func_desc;
    test_func_t func;
    int enabled;
} test_t;

static void test01(void)
{
    printf("sizeof(u1024_t) = %d * 8 = %d bits\n", sizeof(u1024_t), 
	    sizeof(u1024_t) * 8);
}

static void test02(void)
{
    u1024_t a;

    if (number_init_str(&a,
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
		))
    {
	printf("initializing a failed\n");
    }
    else
	printf("initializing of a succeeded\n");
}

static void test03(void)
{
    u1024_t b;

    if (number_init_random(&b))
	printf("number_init_random(&b) failed\n");
    else
	printf("number_init_random(&b) succcedded\n");
}

static void test05(void)
{
    u1024_t a, b, c;

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
	))
    {
	printf("initializing a or b failed\n");
	return;
    }

    number_add(&c, &a, &b);
    return;
}

static void test06(void)
{
    u1024_t a, b, c;

    number_small_dec2num(&a, (u64)115);
    number_small_dec2num(&b, (u64)217);
    number_add(&c, &a, &b);
    return;
}

static void test07(void)
{
    u1024_t a, b, c;

    if (number_init_random(&a) || number_init_random(&b))
	return;
    number_add(&c, &a, &b);
    return;
}

static void test08(void)
{
    u1024_t a;

    if (number_init_str(&a,
	"11000001"
	"10111100"
	"11010011"
	"01111000"
	"00001101"
	"01110111"
	"10001110"
	"00100110"
	))
    {
	printf("initializing a failed\n");
    }

    number_shift_left(&a, 2);
    return;
}

static void test09(void)
{
    u1024_t a, b;

    if (number_init_str(&a,
		"11111111"
		"11111111"
		"11111111"
		"11111111"
		"11111111"
		"11111111"
		"11111111"
		"11111111"
		))
    {
	printf("initializing a failed\n");
    }

    if (number_init_random(&b))
    {
	printf("initializing b failed\n");
    }

    number_shift_left(&a, 1);
    number_shift_left(&b, 3);
    return;
}

static void test10(void)
{
    u1024_t a, b, c;

    if (number_init_str(&a, 
	"1101"
	) || number_init_str(&b, 
	"101"
	))
    {
	printf("initializing a or b failed\n");
	return;
    }

    number_mul(&c, &a, &b);
    return;
}

static void test11(void)
{
    u1024_t a, b, c;

    if (number_init_str(&a, 
	"1101"
	) || number_init_str(&b, 
	"101101"
	))
    {
	printf("initializing a or b failed\n");
	return;
    }

    number_mul(&c, &a, &b);
    return;
}
static void test12(void)
{
    u1024_t a, b, c;

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
	))
    {
	printf("initializing a or b failed\n");
	return;
    }

    number_mul(&c, &a, &b);
    return;
}

static void test13(void)
{
    u1024_t a;

    number_dec2bin(&a, "00235102352");
    return;
}

static void test14(void)
{
    u1024_t a;
    char str[256];

    memset(str, 0, 256);
    snprintf(str, 256, "%llu", 18446744073709551615ULL);

    printf("%s\n", str);
    number_dec2bin(&a, str);
    return;
}

static void test15(void)
{
    u1024_t a, b;

    number_dec2bin(&a, "18446744073709551615");
    number_dec2bin(&b, "18446744073709551616");
    return;
}

static void test16(void)
{
    u1024_t a, b;

    number_dec2bin(&a, "255");
    number_dec2bin(&b, "256");
    return;
}

static void test17(void)
{
    u1024_t a;

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
		))
    {
	printf("initializing a failed\n");
    }
    else
	number_shift_right(&a, 1);
    return;
}

static void test18(void)
{
    u1024_t a;
    u64 *seg, mask;

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
    }
    else
	number_find_most_significant_set_bit(&a, &seg, &mask);
    return;
}

static void test19(void)
{
    u1024_t a, b, n, res;

    number_dec2bin(&a, "3");
    number_dec2bin(&b, "2");
    number_dec2bin(&n, "4");
    number_modular_multiplication_naive(&res, &a, &b, &n);
    return;
}

static void test20(void)
{
    u1024_t a, b, c;

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
	"1"
	))
    {
	printf("initializing a or b failed\n");
	return;
    }

    number_sub(&c, &a, &b);
    return;
}

static void test21(void)
{
    u1024_t a, b, c;

    if (number_init_str(&a, 
	"1000100011" /* 547 */
	) || number_init_str(&b, 
	"11111100" /* 252 */
	))
    {
	printf("initializing a or b failed\n");
	return;
    }

    number_sub(&c, &a, &b);
    return; /* 100100111 */
}

static void test22(void)
{
    u1024_t a, b, q, r;

    if (number_init_str(&a, 
	"100" /* 4 */
	) || number_init_str(&b, 
	"10" /* 2 */
	))
    {
	printf("initializing a or b failed\n");
	return;
    }

    number_dev(&q, &r, &a, &b);
    return; /* 100100111 */
}
static void test23(void)
{
    u1024_t a, b, q, r;

    if (number_init_str(&a, 
	"1000100011" /* 547 */
	) || number_init_str(&b, 
	"11111100" /* 252 */
	))
    {
	printf("initializing a or b failed\n");
	return;
    }

    number_dev(&q, &r, &a, &b);
    return; /* 100100111 */
}

static void test24(void)
{
    u1024_t res, a, b, n;

    if (number_dec2bin(&a, "3") || number_dec2bin(&b, "3"), 
	number_dec2bin(&n, "7"))
    {
	printf("initializing a, b or n failed\n");
	return;
    }

    number_modular_exponentiation_naive(&res, &a, &b, &n);
    return;
}

static void test25(void)
{
    u1024_t res, a, b, n;

    if (number_dec2bin(&a, "289") || number_dec2bin(&b, "276"), 
	number_dec2bin(&n, "258"))
    {
	printf("initializing a, b or n failed\n");
	return;
    }

    number_modular_exponentiation_naive(&res, &a, &b, &n);
    return;
}

static void test26(void)
{
    u1024_t a, n;

    if (number_dec2bin(&a, "2") || number_dec2bin(&n, "5"))
    {
	printf("initializing a, n failed\n");
	return;
    }

    printf("number_witness(&a, &n) = %i\n", number_witness(&a, &n));
    return;
}

static void test27(void)
{
    u1024_t num_n;
    char str[5];
    int i = 3;

	snprintf(str, 5, "%i", i);
	number_dec2bin(&num_n, str);
	printf("%i is %sprime\n", i, number_is_prime(&num_n) ? "" : "not ");
    return;
}

static void test28(void)
{
    u1024_t num_n;
    int i;
    char str[5];

    for (i = 3; i < 1000; i++)
    {
	snprintf(str, 5, "%i", i);
	number_dec2bin(&num_n, str);
	if (number_is_prime(&num_n))
	{
	    printf("%i, ", i);
	    fflush(stdout);
	}
    }
    printf("\n");
    return;
}

static void test29(void)
{
    u1024_t num_n;

    number_dec2bin(&num_n, "10726904659");
    printf("10726904659 is %sprime\n", number_is_prime(&num_n) ? "" : "not ");
    return;
}

static void test30(void)
{
    u1024_t num_n;

    number_dec2bin(&num_n, "55350776431903243");
    printf("55350776431903243 is %sprime\n", number_is_prime(&num_n) ? "" : 
	"not ");
    return;
}

static void test31(void)
{
    u1024_t num_n;
#ifndef TIME_FUNCTIONS
    struct timeval tv1, tv2;

    tv1.tv_sec = 0;
    tv1.tv_usec = 0;
    tv2.tv_sec = 0;
    tv2.tv_usec = 0;
    
    gettimeofday(&tv1, NULL);
#else
    functions_stat_reset();
#endif
    number_find_prime(&num_n);
#ifndef TIME_FUNCTIONS
    gettimeofday(&tv2, NULL);
    printf("found prime in: %i sec.\n", 
	(int)(tv2.tv_sec - tv1.tv_sec));
#else
    functions_stat();
#endif
    return;
}

static void test32(void)
{
    u1024_t num_n;

#ifdef TIME_FUNCTIONS
    functions_stat_reset();
#endif
    number_dec2bin(&num_n, "2285760293497823444790323455592340983477");
    printf("2285760293497823444790323455592340983477 is %sprime\n", 
	number_is_prime(&num_n) ? "" : "not ");
#ifdef TIME_FUNCTIONS
    functions_stat();
#endif
}

static void test33(void)
{
    u1024_t num_n;
    char prime[143];
    int i, is_prime;

#ifndef TIME_FUNCTIONS
    struct timeval tv1, tv2;

    tv1.tv_sec = 0;
    tv1.tv_usec = 0;
    tv2.tv_sec = 0;
    tv2.tv_usec = 0;
#endif

    for (i = 0; i < 142; i = i + 2)
    {
	prime[i] = '9';
	prime[i + 1] = '4';
    }
    prime[142] = '9';
    prime[143] = 0;

    /* 475 bits */
    number_dec2bin(&num_n, prime);
#ifdef TIME_FUNCTIONS
    functions_stat_reset();
#else
    gettimeofday(&tv1, NULL);
#endif
    is_prime = number_is_prime(&num_n);
#ifdef TIME_FUNCTIONS
    functions_stat();
#else
    gettimeofday(&tv2, NULL);
    printf("computation time (475 bits): %i sec.\n", 
	(int)(tv2.tv_sec - tv1.tv_sec));
#endif
    printf("94R(71)9 is %sprime.\n", is_prime ? "" : "not ");
    return;
}

static void test34(void)
{
    u1024_t num_n, num_m;

    number_small_dec2num(&num_n, 163);
    number_radix(&num_m, &num_n);
    return;
}

static void test35(void)
{
    u1024_t num_n, num_base, num_exp, num_res;

    number_small_dec2num(&num_n, 163);
    number_small_dec2num(&num_base, 2);
    number_small_dec2num(&num_exp, 260);
    number_modular_exponentiation_naive(&num_res, &num_base, &num_exp, &num_n);
    return;
}

/* compile: DEBUG=y U64=USHORT */
static void test36(void)
{
    u1024_t num_93, num_64, num_163, num_134, num_16, num_res;

    number_small_dec2num(&num_93, (u64)93);
    number_small_dec2num(&num_64, (u64)64);
    number_small_dec2num(&num_163, (u64)163);
    number_small_dec2num(&num_16, (u64)16);

    number_modular_exponentiation_naive(&num_134, &num_93, &num_64, &num_163);
    number_modular_multiplication_naive(&num_res, &num_134, &num_16, &num_163);
    return;
}

static void test37(void)
{
    u1024_t num_n, num_res;

    number_init_random(&num_n);
    number_radix(&num_res, &num_n);
    return;
}

/* compile: DEBUG=y U64=ULLONG */
static void test38(void)
{
    u1024_t num_r, num_2, num_516, num_9;

    number_small_dec2num(&num_2, (u64)2);
    number_small_dec2num(&num_516, (u64)516);
    number_small_dec2num(&num_9, (u64)9);

    number_modular_exponentiation_naive(&num_r, &num_2, &num_516, &num_9);
    return;
}

/* compile: DEBUG=y U64=USHORT */
static void test39(void)
{
    u1024_t num_res, num_a, num_b, num_n;

    number_small_dec2num(&num_a, (u64)5);
    number_small_dec2num(&num_b, (u64)8);
    number_small_dec2num(&num_n, (u64)9);
    number_modular_multiplication_montgomery(&num_res, &num_a, &num_b, &num_n);
    return;
}

/* compile: DEBUG=y U64=USHORT */
static void test40(void)
{
    u1024_t num_res, num_a, num_b, num_n;

    number_small_dec2num(&num_a, (u64)594);
    number_small_dec2num(&num_b, (u64)1019);
    number_small_dec2num(&num_n, (u64)117);
#ifdef TIME_FUNCTIONS
    functions_stat_reset();
#endif
    number_modular_multiplication_montgomery(&num_res, &num_a, &num_b, &num_n);
#ifdef TIME_FUNCTIONS
    functions_stat();
#endif

    return;
}

/* USHORT */
static void test41(void)
{
    u1024_t n;
    char *dec = "99991";

    number_dec2bin(&n, dec);
    printf("%s is %sprime\n", dec, number_is_prime(&n) ? "" : "not ");
    return;
}

static void test42(void)
{
    u1024_t a, b, n;

    number_dec2bin(&a, "4294960000");
    number_dec2bin(&b, "8000");
    number_add(&n, &a, &b);
    return;
}

static void test43(void)
{
    u1024_t num_n, num_29, num_res, num_rem;
    char prime[143];
    int i;

#ifndef TIME_FUNCTIONS
    struct timeval tv1, tv2;

    tv1.tv_sec = 0;
    tv1.tv_usec = 0;
    tv2.tv_sec = 0;
    tv2.tv_usec = 0;
#endif

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
#ifdef TIME_FUNCTIONS
    functions_stat_reset();
#else
    gettimeofday(&tv1, NULL);
#endif
    number_dev(&num_res, &num_rem, &num_n, &num_29);
#ifdef TIME_FUNCTIONS
    functions_stat();
#else
    gettimeofday(&tv2, NULL);
    printf("computation time (475 bits): %i sec.\n", 
	(int)(tv2.tv_sec - tv1.tv_sec));
#endif
    return;

}

static void test44(void)
{
    u1024_t num_2, num_3, num_5, num_7, num_11, num_13, num_17, num_19, 
	num_23, num_29, num_31, num_37, num_41;
    u1024_t num_res, num_a, num_a_pow2, num_a_pow10, num_b;

#ifdef TIME_FUNCTIONS
    functions_stat_reset();
#else
    struct timeval tv1, tv2;

    tv1.tv_sec = 0;
    tv1.tv_usec = 0;
    tv2.tv_sec = 0;
    tv2.tv_usec = 0;

    gettimeofday(&tv1, NULL);
#endif

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

#ifdef TIME_FUNCTIONS
    functions_stat();
#else
    gettimeofday(&tv2, NULL);
    printf("computation completed in: %i sec.\n", 
	(int)(tv2.tv_sec - tv1.tv_sec));
#endif
    return;
}

static void test45(void)
{
    u1024_t num_a, num_b;
    int i;
    static u64 first_1000_primes[1000] = 
    {
	2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
	31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
	73, 79, 83, 89, 97, 101, /* <-- 26th prime */103, 107, 109, 113,
	127, 131, 137, 139, 149, 151, 157, 163, 167, 173,
	179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
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
    };

#ifdef TIME_FUNCTIONS
    functions_stat_reset();
#else
    struct timeval tv1, tv2;

    tv1.tv_sec = 0;
    tv1.tv_usec = 0;
    tv2.tv_sec = 0;
    tv2.tv_usec = 0;

    gettimeofday(&tv1, NULL);
#endif

    number_small_dec2num(&num_a, (u64)1);
    for (i = 0; i < 75; i++)
    {
	number_small_dec2num(&num_b, first_1000_primes[i]);
	number_mul(&num_a, &num_a, &num_b);
    }
    number_small_dec2num(&num_b, (u64)101);
	number_mul(&num_a, &num_a, &num_b);

#ifdef TIME_FUNCTIONS
    functions_stat();
#else
    gettimeofday(&tv2, NULL);
    printf("computation completed in: %i sec.\n", 
	(int)(tv2.tv_sec - tv1.tv_sec));
#endif
    return;
}

static void test46(void)
{
    u1024_t num_c, num_inc, num_mod1, num_mod2, num_0, num_1;
    u1024_t primes[13];
    int i = 0;

    number_small_dec2num(&num_0, (u64)0);
    number_small_dec2num(&num_1, (u64)1);

    number_small_dec2num(&primes[0], (u64)2);
    number_small_dec2num(&primes[1], (u64)3);
    number_small_dec2num(&primes[2], (u64)5);
    number_small_dec2num(&primes[3], (u64)7);
    number_small_dec2num(&primes[4], (u64)11);
    number_small_dec2num(&primes[5], (u64)13);
    number_small_dec2num(&primes[6], (u64)17);
    number_small_dec2num(&primes[7], (u64)19);
    number_small_dec2num(&primes[8], (u64)23);
    number_small_dec2num(&primes[9], (u64)29);
    number_small_dec2num(&primes[10], (u64)31);
    number_small_dec2num(&primes[11], (u64)37);
    number_small_dec2num(&primes[12], (u64)41);

    number_generate_coprime(&num_c, &num_inc);
    /* sanity */
//    number_add(&num_n, &num_n, &num_1);

    for (; i < 13; i++)
    {
	number_mod(&num_mod1, &num_c, &primes[i]);
	number_mod(&num_mod2, &num_inc, &primes[i]);
	printf("num_c is%s relatively prime to %llu, but num_inc is%s\n", 
	    number_is_equal(&num_mod1, &num_0) ? " not" : "", 
	    *((u64 *)&primes[i]),
	    number_is_equal(&num_mod2, &num_0) ? " not" : "");
    }
    return;
}

static void test47(void)
{
    u1024_t num_c, num_inc;
    u64 primes[13] = {(u64)2, (u64)3, (u64)5, (u64)7, (u64)11, (u64)13, 
	(u64)17, (u64)19, (u64)23, (u64)29, (u64)31, (u64)37, (u64)41};
    u64 seed;
    u1024_t num_primes[13];
    int i;

    for (i = 0; i < 13; i++)
	number_small_dec2num(&num_primes[i], primes[i]);

    number_generate_coprime(&num_c, &num_inc);

    printf("seed = *((u64 *)&num_c) = %llu\n", seed = *((u64 *)&num_c));
    for (i = 0; i < 13; i++)
    {
	printf("seed is %sco-prime to %llu\n", seed % primes[i] ? "" : "not ", 
	    primes[i]);
    }
    return;
}

static void test48(void)
{
    u1024_t num_c, num_inc, num_mod, num_0;
    u64 primes[13] = {(u64)2, (u64)3, (u64)5, (u64)7, (u64)11, (u64)13, 
	(u64)17, (u64)19, (u64)23, (u64)29, (u64)31, (u64)37, (u64)41};
    u64 seed;
    u1024_t num_primes[13];
    int i, ret = 0;

    number_small_dec2num(&num_0, (u64)0);
    for (i = 0; i < 13; i++)
	number_small_dec2num(&num_primes[i], primes[i]);

    number_generate_coprime(&num_c, &num_inc);

    seed = *((u64 *)&num_c);
    for (i = 0; i < 13; i++)
    {
	number_reset(&num_mod);
	number_mod(&num_mod, &num_c, &num_primes[i]);
	if ((seed % primes[i]) && number_is_equal(&num_mod, &num_0))
	{
	    ret = 1;
	    break;
	}
	if (!(seed % primes[i]) && !number_is_equal(&num_mod, &num_0))
	{
	    ret = 2;
	    break;
	}
    }

    switch (ret)
    {
    case 0:
	printf("comparison is ok\n");
	break;
    case 1:
	printf("%llu %% %llu != 0\n", seed, primes[i]);
	printf("number_is_equal(&num_mod, &num_0) == 1 (true)\n");
	break;
    case 2:
	printf("%llu %% %llu == 0\n", seed, primes[i]);
	printf("number_is_equal(&num_mod, &num_0) == 0 (false)\n");
	break;
    }
    return;
}

static void test49(void)
{
    u1024_t num_0, num_big, num_5, num_mod;
    char *big_num_str = "10098841051971095635";
/*    char *big_num_str = "6788835914016483306";
 */

    number_small_dec2num(&num_0, (u64)0);
    number_small_dec2num(&num_5, (u64)5);
    number_dec2bin(&num_big, big_num_str);
    number_mod(&num_mod, &num_big, &num_5);

    printf("%s %% 5 = %llu\n", big_num_str, *((u64 *)&num_mod));
    printf("%s is %sco-prime to 5\n", big_num_str, 
	number_is_equal(&num_mod, &num_0) ? "not " : "");
    return;
}

static void test52(void)
{
    u1024_t num_0, num_1, num_4, num_x;
    
    number_small_dec2num(&num_0, (u64)0);
    number_small_dec2num(&num_1, (u64)1);
    number_small_dec2num(&num_4, (u64)4);

    number_sub(&num_x, &num_0, &num_4);
    number_sub(&num_x, &num_1, &num_x);
    return;
}

static void test53(void)
{
    u1024_t a, b, n, axb;
    u64 i, prime = 11;

    number_small_dec2num(&n, (u64)prime);

    for (i = (u64)1; i < (u64)prime; i++)
    {
	number_small_dec2num(&b, (u64)i);
	number_modular_multiplicative_inverse(&a, &b, &n);
	//number_modular_multiplication_naive(&axb, &a, &b, &n);
	number_mul(&axb, &a, &b);
	number_mod(&axb, &axb, &n);
	printf("b = %llu, a = %llu, ab mod(%llu) = %llu\n", *(u64 *)&b, 
	    *(u64 *)&a, prime, *(u64 *)&axb);
    }
    return;
}

static void test54(void)
{
    u1024_t num_a, num_abs, num_5;

    number_small_dec2num(&num_5, (u64)5);
    number_small_dec2num(&num_a, (u64)0);

    number_sub(&num_a, &num_a, &num_5);
    number_absolute_value(&num_abs, &num_a);
}

static void test55(void)
{
    u1024_t x, a, y, b, d, xa, yb, sum, abs_y, mod_y;
    u64 i, prime = 11;

    number_small_dec2num(&a, (u64)prime);
    for (i = 1; i < prime; i++)
    {
	u1024_t tmp_x;

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

	printf("x = %s%llu, a = %llu, y = %s%llu, b = %llu, gcd = %llu, "
	    "xa + yb = %llu, y mod(%llu) = %llu\n", 
	    number_is_equal(&tmp_x, &x) ? "" : "-", 
	    *(u64*)&x, *(u64*)&a, number_is_equal(&y, &abs_y) ? "" : "-", 
	    *(u64*)&abs_y, *(u64*)&b, *(u64*)&d, *(u64*)&sum, prime, 
	    *(u64*)&mod_y);
    }
    return;
}

static void test56(void)
{
    u1024_t num_min, num_abs, num_0, num_1;

    number_small_dec2num(&num_0, (u64)0);
    number_small_dec2num(&num_1, (u64)1);
    number_sub(&num_min, &num_0, &num_1);

    printf("1 %s 0\n", number_is_greater(&num_1, &num_0) ? ">" :"<");
    printf("-1 %s 0\n", number_is_greater(&num_min, &num_0) ? ">" :"<");
    number_absolute_value(&num_abs, &num_min);
    printf("|-1| %s 0\n", number_is_greater(&num_abs, &num_0) ? ">" : "<");
    return;
}

static void test57a(void)
{
    u1024_t p1, p2, n, e, d, phi, montgomery_converter;
#if 0
    struct timeval tv1, tv2;

    tv1.tv_sec = 0;
    tv1.tv_usec = 0;
    tv2.tv_sec = 0;
    tv2.tv_usec = 0;
    
    gettimeofday(&tv1, null);
#endif
    number_find_prime(&p1);
#if 0
    gettimeofday(&tv2, NULL);
    printf("found prime1 in: %i sec.\n", (int)(tv2.tv_sec - tv1.tv_sec));
    fflush(stdout);

    tv1.tv_sec = 0;
    tv1.tv_usec = 0;
    tv2.tv_sec = 0;
    tv2.tv_usec = 0;

    gettimeofday(&tv1, NULL);
#endif
    number_find_prime(&p2);
#if 0
    gettimeofday(&tv2, NULL);
    printf("found prime2 in: %i sec.\n", (int)(tv2.tv_sec - tv1.tv_sec));
    fflush(stdout);
#endif

    number_mul(&n, &p1, &p2);
    number_sub1(&p1);
    number_sub1(&p2);
    number_mul(&phi, &p1, &p2);

#if 0
    tv1.tv_sec = 0;
    tv1.tv_usec = 0;
    tv2.tv_sec = 0;
    tv2.tv_usec = 0;

    gettimeofday(&tv1, NULL);
#endif
    number_init_random_coprime(&e, &phi);
#if 0
    gettimeofday(&tv2, NULL);
    printf("found exp1 in: %i sec.\n", (int)(tv2.tv_sec - tv1.tv_sec));
    fflush(stdout);

    tv1.tv_sec = 0;
    tv1.tv_usec = 0;
    tv2.tv_sec = 0;
    tv2.tv_usec = 0;

    gettimeofday(&tv1, NULL);
#endif

    number_modular_multiplicative_inverse(&d, &e, &phi);
#if 0
    gettimeofday(&tv2, NULL);
    printf("found exp2 in: %i sec.\n", (int)(tv2.tv_sec - tv1.tv_sec));
    fflush(stdout);
#endif
    number_radix(&montgomery_converter, &n);
}
static void test57(void)
{
#define MAX 20

    int i = 0, arr[MAX];
    struct timeval tv1, tv2;

    tv1.tv_sec = 0;
    tv1.tv_usec = 0;
    tv2.tv_sec = 0;
    tv2.tv_usec = 0;
    
    for (; i < MAX; i++)
    {
	gettimeofday(&tv1, NULL);
	test57a();
	gettimeofday(&tv2, NULL);
	arr[i] = (int)(tv2.tv_sec - tv1.tv_sec);
    }

    for (i = 0; i < MAX; i++)
	i+= arr[i];

    printf("average key generation time is %i sec.\n", i / MAX);
	    
}

static test_t tests[] = 
{
    { "sizeof(u1024_t)", test01, DISSABLED },
    { "number_init_str()", test02, DISSABLED },
    { "number_init_random()", test03, DISSABLED },
    { "number_add() - edge conditions", test05, DISSABLED },
    { "number_add() - functionality", test06, DISSABLED },
    { "number_add() - random numbers", test07, DISSABLED },
    { "number_shift_left() - functionality", test08, DISSABLED },
    { "number_shift_left() - edge conditions, random numbers", test09, 
	DISSABLED },
    { "number_mul() - multiplicand > multiplier", test10, DISSABLED },
    { "number_mul() - multiplicand < multiplier", test11, DISSABLED },
    { "number_mul() - big numbers", test12, DISSABLED },
    { "number_dec2bin()", test13, DISSABLED },
    { "number_dec2bin() - edge conditions", test14, DISSABLED },
    { "number_dec2bin() - max size number (UCHAR)", test15, DISSABLED },
    { "number_dec2bin() - more edge conditions", test16, DISSABLED },
    { "number_shift_right()", test17, DISSABLED },
    { "number_find_most_significant_set_bit()", test18, DISSABLED },
    { "number_modular_multiplication_naive()", test19, DISSABLED },
    { "number_sub() - basic functionality", test20, DISSABLED },
    { "number_sub()", test21, DISSABLED },
    { "number_dev() - basic functionality", test22, DISSABLED },
    { "number_dev()", test23, DISSABLED },
    { "number_modular_exponentiation_naive() - basic functionality", test24, 
	DISSABLED },
    { "number_modular_exponentiation_naive()", test25, DISSABLED },
    { "number_witness() - basic functionality", test26, DISSABLED },
    { "number_is_prime() - basic functionality", test27, DISSABLED },
    { "number_is_prime() primes in [3, 1000]", test28, DISSABLED },
    { "number_is_prime() - large prime", test29, DISSABLED },
    { "number_is_prime()", test30, DISSABLED },
    { "number_find_prime()", test31, DISSABLED },
    { "number_is_prime() - very large non prime", test32, DISSABLED },
    { "number_is_prime() - 475 bit prime", test33, DISSABLED },
    { "number_radix()", test34, DISSABLED },
    { "number_modular_exponentiation_naive() - large power of 2", test35, 
	DISSABLED },
    { "number_modular_exponentiation_naive & "
	"number_modular_multiplication_naive", test36, DISSABLED },
    { "number_radix() - for random number", test37, DISSABLED },
    { "number_modular_exponentiation_naive() (ULLONG)", test38, DISSABLED },
    { "number_modular_multiplication_montgomery() (USHORT)", test39, 
	DISSABLED },
    { "number_modular_multiplication_montgomery() (USHORT)", test40, 
	DISSABLED },
    { "number_is_prime() (USHORT)", test41, DISSABLED },
    { "number_add() - testing new implementation", test42, DISSABLED },
    { "number_dev() - deviding a 475 bit number by 29", test43, DISSABLED },
    { "512 bits: (2x3x5x7x11x13x17x19x23x29x31x37x41)^10 x5x7x23x29x31x37x41", 
	test44, DISSABLED },
    { "512 bits: multiply the first 170 primes", test45, DISSABLED },
    { "co-primality testing - method 1", test46, DISSABLED },
    { "co-primality testing - method 2", test47, DISSABLED },
    { "comparing x %% y to number_is_equal(&num_mod, &num_0)", test48, 
	DISSABLED },
    { "number_mod() sanity test", test49, DISSABLED },
    { "negative numbers", test52, DISSABLED },
    { "number_modular_multiplicative_inverse()", test53, DISSABLED },
    { "number_absolute_value()", test54, DISSABLED },
    { "number_extended_euclid_gcd()", test55, DISSABLED },
    { "number_is_greater_signed()", test56, DISSABLED },
    { "create rsa key", test57, ENABLED },
    { }
};

int main(int argc, char *argv[])
{
    test_t *current_test = tests;

    while (current_test->func_desc)
    {
	if (current_test->enabled == DISSABLED)
	{
	    current_test++;
	    continue;
	}
	printf("test description: %s\n", current_test->func_desc);
	fflush(stdout);
	current_test->func();
	current_test++;
    }

    return 0;
}
