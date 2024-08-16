/*
* p4_tc_template.c                P4 TC Template Management
*
*         This program is free software; you can distribute it and/or
*         modify it under the terms of the GNU General Public License
*         as published by the Free Software Foundation; either version
*         2 of the License, or (at your option) any later version.
*
* Copyright (c) 2022-2024, Mojatatu Networks
* Copyright (c) 2022-2024, Intel Corporation.
* Authors:     Jamal Hadi Salim <jhs@mojatatu.com>
*              Victor Nogueira <victor@mojatatu.com>
*              Pedro Tammela <pctammela@mojatatu.com>
*/

#include "p4_types.h"
#include <stdio.h>
#include <limits.h>

#define BITSZ_IRRELEVANT 0

static struct hlist_head types_list = {};

static char *extact_mask_str_num_type(const char *arg)
{
	char *slash;

	slash = strchr(arg, '/');
	if (slash) {
		*slash = 0;
		return slash + 1;
	}

	return NULL;
}

static bool is_hexadecimal(const char *str) {
	char *endptr;

	if (str[0] != '0' && str[1] != 'x')
		return false;

	strtol(str, &endptr, 16);

	return (*str != '\0' && *endptr == '\0');
}

static bool mask_is_hex(const char *arg)
{
	char *slash;

	slash = strchr(arg, '/');
	if (slash) {
		slash++;
		return is_hexadecimal(slash);
	}

	return false;
}

#define ULL(X) X##ULL
#define UL(X) X##UL

#define BIT_ULL(nr)		(ULL(1) << (nr))
#define BIT_MASK(nr)		(UL(1) << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)		((nr) / BITS_PER_LONG)
#define BIT_ULL_MASK(nr)	(ULL(1) << ((nr) % BITS_PER_LONG_LONG))
#define BIT_ULL_WORD(nr)	((nr) / BITS_PER_LONG_LONG)
#define BITS_PER_BYTE		8
#define BITS_PER_LONG 64

#define BUILD_BUG_ON_ZERO(e) (0)

#define GENMASK_INPUT_CHECK(h, l) \
		(BUILD_BUG_ON_ZERO(__builtin_choose_expr( \
				   __is_constexpr((l) > (h)), (l) > (h), 0)))
#define __GENMASK(h, l) \
		(((~UL(0)) - (UL(1) << (l)) + 1) & \
			 (~UL(0) >> (BITS_PER_LONG - 1 - (h))))

#define GENMASK(h, l) \
		(GENMASK_INPUT_CHECK(h, l) + __GENMASK(h, l))

#define __BUILD_MASK_NUM_TYPE(imask, mask_str, typ) \
	do { \
		if (get_##typ((imask), mask_str, 16)) { \
			fprintf(stderr, "Invalid mask %s for bit%u\n", \
				mask_str, val->bitsz); \
			return -1; \
		} \
	} while(0);

#define BUILD_MASK_NUM_TYPE(imask, mask_str, val, typ) \
	do {\
		if (val->mask) { \
			if (mask_str) { \
				__BUILD_MASK_NUM_TYPE(imask, mask_str, typ); \
			} else { \
				*(imask) = GENMASK(val->bitsz - 1, 0); \
			} \
		} \
	} while(0);

static int build_mask_be64(__be64 *newmask, const char *mask_str,
			   struct p4_type_value *val)
{
	if (newmask) {
		if (mask_str)
			__BUILD_MASK_NUM_TYPE(newmask, mask_str, be64)
		else
			*newmask = htonll(GENMASK(val->bitsz - 1, 0));
	}

	return 0;
}

static int build_mask_be32(__be32 *newmask, const char *mask_str,
			   struct p4_type_value *val)
{
	if (newmask) {
		if (mask_str)
			__BUILD_MASK_NUM_TYPE(newmask, mask_str, be32)
		else
			*newmask = htonl((__u32)GENMASK(val->bitsz - 1, 0));
	}

	return 0;
}

static int build_mask_be16(__be16 *newmask, const char *mask_str,
			   struct p4_type_value *val)
{
	if (newmask) {
		if (mask_str)
			__BUILD_MASK_NUM_TYPE(newmask, mask_str, be16)
		else
			*newmask = htons((__u16)GENMASK(val->bitsz - 1, 0));
	}

	return 0;
}

#define VALIDATE_NUM_VAL(ival, bitsz) \
	if (ival > GENMASK(bitsz - 1, 0)) { \
		fprintf(stderr, "Value doesn't fit in bitsz\n"); \
		return -1; \
	}

#define VALIDATE_MASK_NUM_TYPE(imask, bitsz) \
	if (imask && *(imask) > GENMASK(bitsz - 1, 0)) { \
		fprintf(stderr, "Mask doesn't fit in bitsz\n"); \
		return -1; \
	}

static int parse_p4t_u8_val(struct p4_type_value *val, const char *arg, int base)
{
	__u8 *newval = val->value;
	__u8 *newmask = val->mask;
	char *mask_str;
	__u8 ival;

	mask_str = extact_mask_str_num_type(arg);

	if (get_u8(&ival, arg, base))
		return -1;

	BUILD_MASK_NUM_TYPE(newmask, mask_str, val, u8)

	if (val->bitsz < 8) {
		VALIDATE_NUM_VAL(ival, val->bitsz);
		VALIDATE_MASK_NUM_TYPE(newmask, val->bitsz);
	}

	*newval = ival;
	return 0;
}

static int parse_p4t_s8_val(struct p4_type_value *val, const char *arg, int base)
{
	__s8 *newval = val->value;
	__s8 ival;

	if (get_s8(&ival, arg, base))
		return -1;

	if (val->bitsz < 8) {
		if ((__u8)ival > (1 << (val->bitsz)) - 1) {
			fprintf(stderr, "Value doesn't fit in bitsz\n");
			return -1;
		}
	}

	*newval = ival;
	return 0;
}

static int parse_p4t_u16_val(struct p4_type_value *val, const char *arg,
			     int base)
{
	__u16 *newval = val->value;
	__u16 *newmask = val->mask;
	char *mask_str;
	__u16 ival;

	mask_str = extact_mask_str_num_type(arg);

	if (get_u16(&ival, arg, base))
		return -1;

	BUILD_MASK_NUM_TYPE(newmask, mask_str, val, u16)

	if (val->bitsz < 16) {
		VALIDATE_NUM_VAL(ival, val->bitsz);
		VALIDATE_MASK_NUM_TYPE(newmask, val->bitsz);
	}

	*newval = ival;
	return 0;
}

static int parse_p4t_s16_val(struct p4_type_value *val, const char *arg,
			     int base)
{
	__s16 *newval = val->value;
	__s16 ival;

	if (get_s16(&ival, arg, base))
		return -1;

	*newval = ival;
	return 0;
}

static int parse_p4t_be16_val(struct p4_type_value *val, const char *arg,
			      int base)
{
	__be16 *newval = val->value;
	__be16 *newmask = val->mask;
	char *mask_str;
	__be16 ival;

	mask_str = extact_mask_str_num_type(arg);

	if (get_be16(&ival, arg, base))
		return -1;

	if (build_mask_be16(newmask, mask_str, val) < 0)
		return -1;

	if (val->bitsz < 16) {
		VALIDATE_NUM_VAL(ntohs(ival), val->bitsz);

		if (newmask && *newmask > htons(GENMASK(val->bitsz - 1, 0))) {
			fprintf(stderr, "Value doesn't fit in bitsz\n");
			return -1;
		}
	}

	*newval = ival;
	return 0;
}

static int parse_p4t_s32_val(struct p4_type_value *val, const char *arg,
			     int base)
{
	__s32 *newval = val->value;
	__s32 ival;

	if (get_s32(&ival, arg, base))
		return -1;

	*newval = ival;
	return 0;
}

static int __parse_p4t_u64_val(struct p4_type_value *val, __u64 ival,
			       __u64 *newmask, char *mask_str)
{
	if (val->bitsz < 64) {
		if (ival > (1UL << val->bitsz) - 1) {
			fprintf(stderr, "Value doesn't fit in bitsz\n");
			return -1;
		}

		BUILD_MASK_NUM_TYPE(newmask, mask_str, val, u64)

		VALIDATE_MASK_NUM_TYPE(newmask, val->bitsz);
	} else {
		if (newmask)
			*newmask = ~0UL;
	}

	return 0;
}

static int parse_p4t_u64_val(struct p4_type_value *val, const char *arg,
			     int base)
{
	__u64 *newval = val->value;
	__u64 *newmask = val->mask;
	char *mask_str;
	__u64 ival;
	int ret;

	mask_str = extact_mask_str_num_type(arg);

	if (get_u64(&ival, arg, base))
		return -1;

	ret = __parse_p4t_u64_val(val, ival, newmask, mask_str);

	*newval = ival;

	return ret;
}

static int parse_p4t_rate_val(struct p4_type_value *val, const char *arg,
			      int base)
{
	__u64 *newval = val->value;
	__u64 *newmask = val->mask;
	char *mask_str;
	__u64 ival;

	mask_str = extact_mask_str_num_type(arg);

	if (get_rate64(&ival, arg)) {
		fprintf(stderr, "Invalid rate %s\n", arg);
		return -1;
	}

	__parse_p4t_u64_val(val, ival, newmask, mask_str);

	*newval = ival;

	return 0;
}

static int parse_p4t_u32_val(struct p4_type_value *val, const char *arg,
			     int base)
{
	__u32 *newval = val->value;
	__u32 *newmask = val->mask;
	char *mask_str;
	__u32 ival;

	mask_str = extact_mask_str_num_type(arg);

	if (get_u32(&ival, arg, base))
		return -1;

	BUILD_MASK_NUM_TYPE(newmask, mask_str, val, u32)

	if (val->bitsz < 32) {
		VALIDATE_NUM_VAL(ival, val->bitsz);
		VALIDATE_MASK_NUM_TYPE(newmask, val->bitsz);
	}

	*newval = ival;
	return 0;
}

static int parse_p4t_bool_val(struct p4_type_value *val, const char *arg,
			      int base)
{
	__u32 *newval = val->value;

	if (strcmp(arg, "true") == 0) {
		*newval = true;
	} else if (strcmp(arg, "false") == 0) {
		*newval = false;
	} else {
		fprintf(stderr, "Unknown boolean value %s\n", arg);
		return -1;
	}

	return 0;
}

static int parse_p4t_be32_val(struct p4_type_value *val, const char *arg,
			      int base)
{
	__be32 *newval = val->value;
	__be32 *newmask = val->mask;
	char *mask_str;
	__be32 ival;

	mask_str = extact_mask_str_num_type(arg);

	if (get_be32(&ival, arg, base))
		return -1;

	if (build_mask_be32(newmask, mask_str, val) < 0)
		return -1;

	if (val->bitsz < 32) {
		VALIDATE_NUM_VAL(ntohl(ival), val->bitsz);

		if (newmask && *newmask > htonl(GENMASK(val->bitsz - 1, 0))) {
			fprintf(stderr, "Value doesn't fit in bitsz\n");
			return -1;
		}
	}

	*newval = ival;
	return 0;
}

static int parse_p4t_be64_val(struct p4_type_value *val, const char *arg,
			      int base)
{
	__be64 *newval = val->value;
	__be64 *newmask = val->mask;
	char *mask_str;
	__be64 ival;

	mask_str = extact_mask_str_num_type(arg);

	if (get_be64(&ival, arg, base))
		return -1;

	if (build_mask_be64(newmask, mask_str, val) < 0)
		return -1;

	if (val->bitsz < 64) {
		VALIDATE_NUM_VAL(ntohll(ival), val->bitsz);

		if (newmask && *newmask > htonll(GENMASK(val->bitsz - 1, 0))) {
			fprintf(stderr, "Value doesn't fit in bitsz\n");
			return -1;
		}
	}

	*newval = ival;
	return 0;
}

static int parse_p4t_u128_val(struct p4_type_value *val, const char *arg,
			      int base)
{
	__u8 *newval = val->value;
        char higher_str[17] = {};
        char lower_str[17] = {};
        size_t arg_len;
        __u64 higher = 0;
        __u64 lower = 0;

	if (val->bitsz != 128) {
		fprintf(stderr, "bit128 bit splicing is not supported\n");
		return -1;
	}

        if (!is_hexadecimal(arg)) {
                fprintf(stderr, "bit128's value must be in hexadecimal format\n");
                return -1;
        }

	arg += 2;
        arg_len = strnlen(arg, 33);
	if (arg_len == 33) {
		fprintf(stderr, "bit128 value string is too long\n");
		return -1;
	}

        strncpy(higher_str, arg, 16);

	higher = strtoul(higher_str, NULL, 16);
	if (arg_len > 16) {
		strncpy(lower_str, arg + 16, arg_len - 16);
		lower = strtoul(lower_str, NULL, 16);
		lower = lower << ((32 - arg_len) * 4);
	} else {
		higher = higher << ((16 - arg_len) * 4);
	}
	higher = htonll(higher);
	lower = htonll(lower);

	memcpy(newval, &higher, sizeof(higher));
	memcpy(&newval[8], &lower, sizeof(lower));

	return 0;
}

static int parse_p4t_ipv4_ternary(struct p4_type_value *val, const char *arg,
				  int base)
{
	__u32 *newaddr = val->value;
	__u32 *newmask = val->mask;
	inet_prefix iaddr;
	char *mask_str;

	mask_str = extact_mask_str_num_type(arg);

	if (get_addr_1(&iaddr, (char *)arg, AF_INET))
		return -1;

	if (build_mask_be32(newmask, mask_str, val) < 0)
		return -1;

	memcpy(newaddr, iaddr.data, sizeof(__u32));

	return 0;
}

static int parse_p4t_ipv4_val(struct p4_type_value *val, const char *arg,
			      int base)
{
	__u32 *newaddr = val->value;
	__u32 *new_mask = val->mask;
	__be32 parsed_ipv4;
	inet_prefix iaddr;

	if (mask_is_hex(arg))
		return parse_p4t_ipv4_ternary(val, arg, base);

	/* Check whether user specified numeric IPv4 instead */
	if (get_be32(&parsed_ipv4, arg, 0) == 0) {
		__be32 *addr_32 = val->value;

		*addr_32 = parsed_ipv4;
		return 0;
	}

	if (get_prefix_1(&iaddr, (char *)arg, AF_INET))
		return -1;

	memcpy(newaddr, iaddr.data, sizeof(__u32));
	if (new_mask) {
#if __BYTE_ORDER == __LITTLE_ENDIAN
		*new_mask = ~((__u32)(GENMASK(31, iaddr.bitlen)));
#else
		*new_mask = ~((__u32)(GENMASK(31, 31 - iaddr.bitlen - 1)));
#endif
	}

	return 0;
}

static int parse_p4t_ipv6_ternary(struct p4_type_value *val, const char *arg,
				  int base)
{
	__u8 *newaddr = val->value;
	__u8 *newmask = val->mask;
	inet_prefix iaddr;
	char *mask_str;
	int i;

	mask_str = extact_mask_str_num_type(arg);

	if (get_addr_1(&iaddr, (char *)arg, AF_INET6))
		return -1;

	memcpy(newaddr, iaddr.data, 16);

	if (newmask && mask_str) {
		__u8 imask[16];

		/* Skip "0x" */
		mask_str += 2;
		for (i = 0; i < 16; i++) {
			char mask_str_tmp[4] = {0};

			memcpy(mask_str_tmp, &mask_str[i << 1], 2);
			imask[i] = strtol(mask_str_tmp, NULL, 16);
		}
		memcpy(newmask, imask, 16);
	}

	return 0;
}

static int parse_p4t_ipv6_val(struct p4_type_value *val, const char *arg,
			      int base)
{
	__u8 *newaddr = val->value;
	__u8 *newmask = val->mask;
	inet_prefix iaddr;
	int i;

	if (mask_is_hex(arg))
		return parse_p4t_ipv6_ternary(val, arg, base);

	if (get_prefix_1(&iaddr, (char *)arg, AF_INET6))
		return -1;

	memcpy(newaddr, iaddr.data, 16);

	if (newmask) {
		memset(newmask, 0, 16);

		for (i = 0; i < iaddr.bitlen; i += 8) {
			if (i + 7 < iaddr.bitlen)
				newmask[i >> 3] = 0xFF;
			else if (i < iaddr.bitlen)
				newmask[i >> 3] =
					(0xFF << (7 - (iaddr.bitlen - i - 1)));
			else
				newmask[i >> 3] = 0;
		}
	}

	return 0;
}

static int parse_p4t_dev_val(struct p4_type_value *val, const char *arg,
			     int base)
{
	const char *devname = arg;
	__u32 *newval = val->value;
	__u32 parsed_idx;
	int idx;

	/* Check whether user specified ifindex instead */
	if (get_u32(&parsed_idx, arg, 0) == 0) {
		*newval = parsed_idx;
		return 0;
	}

	idx = ll_name_to_index(devname);
	if (!idx) {
		fprintf(stderr, "Invalid dev %s\n", devname);
		return -1;
	}

	*newval = idx;

	return 0;
}

static int parse_p4t_mac_val(struct p4_type_value *val, const char *arg,
			     int base)
{
	__be64 max_mask = htonll(0xFFFFFFFFFFFF0000);
	__be64 *newmask = val->mask;
	char *newval = val->value;
	__be64 parsed_macaddr;
	char *mask_str;

	mask_str = extact_mask_str_num_type(arg);

	/* Check whether user specified numeric Mac Address instead */
	if (get_be64(&parsed_macaddr, arg, 0) == 0) {
		__be64 *addr_64 = val->value;
		*addr_64 = parsed_macaddr;
		return 0;
	}

	if (ll_addr_a2n(newval, ETH_ALEN, arg) < 0) {
		fprintf(stderr, "mac is invalid %s\n", newval);
		return -1;
	}

	BUILD_MASK_NUM_TYPE(newmask, mask_str, val, be64);
	if (newmask) {
		if (mask_str) {
			if (get_be64(newmask, mask_str, 16)) {
				fprintf(stderr, "Invalid mask %s for bit%u\n",
					mask_str, val->bitsz);
				return -1;
			}
#if __BYTE_ORDER == __LITTLE_ENDIAN
			*newmask >>= 16;
#else
			*newmask <<= 16;
#endif
			if (*newmask > max_mask) {
				fprintf(stderr, "Mask is too big for macaddr\n");
				return -1;
			}
		} else {
			*newmask = max_mask;
		}
	}

	return 0;
}

#define __PRINT_NUM_TYPE(name, json_name, ival, imask, fmt, mask_fmt) \
	do { \
		SPRINT_BUF(buf1); \
		strlcpy(buf1, name, SPRINT_BSIZE - 1); \
		if (imask) { \
			SPRINT_BUF(buf2); \
			snprintf(buf1, sizeof(buf1), " %s ", name); \
			strcat(buf1, "%s"); \
			snprintf(buf2, sizeof(buf2), mask_fmt, \
				 *ival, *imask); \
			print_string(PRINT_ANY, json_name, buf1, buf2); \
		} else { \
			snprintf(buf1, sizeof(buf1), " %s %s", name, fmt); \
			print_uint(PRINT_ANY, json_name, buf1, *ival); \
		} \
	} while (0);

#define PRINT_NUM_TYPE(name, json_name, ival, imask) \
	__PRINT_NUM_TYPE(name, json_name, ival, imask, "%u", "%u/0x%x")

#define PRINT_NUM_TYPE_64(name, json_name, ival, imask) \
	__PRINT_NUM_TYPE(name, json_name, ival, imask, "%llu", "%llu/0x%llx")

static void print_p4t_u8_val(const char *name, const char *json_name,
			     struct p4_type_value *val, FILE *f)
{
	__u8 *ival = val->value;
	__u8 *imask = val->mask;

	PRINT_NUM_TYPE(name, json_name, ival, imask)
}

static void print_p4t_u16_val(const char *name, const char *json_name,
			      struct p4_type_value *val, FILE *f)
{
	__u16 *ival = val->value;
	__u16 *imask = val->mask;

	PRINT_NUM_TYPE(name, json_name, ival, imask)
}

static void print_p4t_be16_val(const char *name, const char *json_name,
			       struct p4_type_value *val, FILE *f)
{
	__be16 *ival = val->value;
	__be16 *imask = val->mask;

	*ival = htons(*ival);

	if (imask)
		*imask = htons(*imask);

	PRINT_NUM_TYPE(name, json_name, ival, imask)
}

static void print_p4t_u32_val(const char *name, const char *json_name,
			      struct p4_type_value *val, FILE *f)
{
	__u32 *ival = val->value;
	__u32 *imask = val->mask;

	PRINT_NUM_TYPE(name, json_name, ival, imask)
}

static void print_p4t_bool_val(const char *name, const char *json_name,
			       struct p4_type_value *val, FILE *f)
{
	bool *ival = val->value;
	SPRINT_BUF(buf);

	strlcpy(buf, name, SPRINT_BSIZE - 1);
	strncat(buf, " %s", SPRINT_BSIZE - 1);

	print_string(PRINT_ANY, json_name, buf, *ival ? "true" : "false");
}

static void print_p4t_s32_val(const char *name, const char *json_name,
			      struct p4_type_value *val, FILE *f)
{
	__s32 *ival = val->value;
	SPRINT_BUF(buf);

	strlcpy(buf, name, SPRINT_BSIZE - 1);
	strncat(buf, " %d", SPRINT_BSIZE - 1);

	print_int(PRINT_ANY, json_name, buf, *ival);
}

static void print_p4t_be32_val(const char *name, const char *json_name,
			       struct p4_type_value *val, FILE *f)
{
	__be32 *ival = val->value;
	__be32 *imask = val->mask;

	*ival = htonl(*ival);

	if (imask)
		*imask = htonl(*imask);

	PRINT_NUM_TYPE(name, json_name, ival, imask)
}

static void print_p4t_u64_val(const char *name, const char *json_name,
			      struct p4_type_value *val, FILE *f)
{
	__u64 *ival = val->value;
	__u64 *imask = val->mask;

	PRINT_NUM_TYPE_64(name, json_name, ival, imask)
}

static void convert_rate(char *buf, __u64 rate, __u64 *mask)
{
	static char *units[5] = {"", "K", "M", "G", "T"};
	unsigned long kilo = use_iec ? 1024 : 1000;
	const char *str = use_iec ? "i" : "";
	int i;

	rate <<= 3; /* bytes/sec -> bits/sec */

	for (i = 0; i < ARRAY_SIZE(units) - 1; i++)  {
		if (rate < kilo)
			break;
		if (((rate % kilo) != 0) && rate < 1000 * kilo)
			break;
		rate /= kilo;
	}

	if (mask)
		snprintf(buf, SPRINT_BSIZE - 1,
			 "%.0f%s%sbit/%llx", (double)rate, units[i],
			 i > 0 ? str : "", *mask);
	else
		snprintf(buf, SPRINT_BSIZE - 1, "%.0f%s%sbit",
			 (double)rate, units[i], i > 0 ? str : "");
}

static void print_p4t_rate_val(const char *name, const char *json_name,
			       struct p4_type_value *val, FILE *f)
{
	__u64 *ival = val->value;
	__u64 *imask = val->mask;
	SPRINT_BUF(buf1);
	SPRINT_BUF(buf2);

	snprintf(buf1, SPRINT_BSIZE - 1, " %s %s", name, "%s");
	convert_rate(buf2, *ival, imask);
	print_string(PRINT_ANY, json_name, buf1, buf2);
}

static void print_p4t_u128_val(const char *name, const char *json_name,
			       struct p4_type_value *val, FILE *f)
{
	__u64 *ival = val->value;
	SPRINT_BUF(buf2);
	SPRINT_BUF(buf);
	__u64 higher;
	__u64 lower;

	higher = htonll(ival[0]);
	lower = htonll(ival[1]);

	strlcpy(buf, name, SPRINT_BSIZE - 1);
	strncat(buf, " %s", SPRINT_BSIZE - 1);

	snprintf(buf2, SPRINT_BSIZE - 1, "0x%016llx%016llx", higher, lower);

	print_string(PRINT_ANY, json_name, buf, buf2);
}

static void print_p4t_be64_val(const char *name, const char *json_name,
			       struct p4_type_value *val, FILE *f)
{
	__be64 *ival = val->value;
	__be64 *imask = val->mask;

	*ival = htonll(*ival);
	*imask = htonll(*imask);

	PRINT_NUM_TYPE_64(name, json_name, ival, imask)
}

static void print_p4t_dev_val(const char *name, const char *json_name,
			      struct p4_type_value *val, FILE *f)
{
	const __u32 *ifindex = val->value;
	const char *ifname = ll_index_to_name(*ifindex);
	SPRINT_BUF(buf);

	if (!ifname) {
		print_uint(PRINT_ANY, NULL, "Unknown ifindex %", *ifindex);
		return;
	}

	strlcpy(buf, name, SPRINT_BSIZE - 1);
	strncat(buf, " %s", SPRINT_BSIZE - 1);

	print_string(PRINT_ANY, json_name, buf, ifname);
}

static void print_p4t_mac_val(const char *name, const char *json_name,
			      struct p4_type_value *val, FILE *f)
{
	unsigned char *mac_val = val->value;
	__u64 mac_mask_u64 = 0;
	SPRINT_BUF(b1);
	SPRINT_BUF(buf);

	strlcpy(buf, name, SPRINT_BSIZE - 1);
	strncat(buf, " %s", SPRINT_BSIZE - 1);

	ll_addr_n2a(mac_val, ETH_ALEN, 0, b1, sizeof(b1));
	if (val->mask) {
		char buf2[128];

		memcpy(&mac_mask_u64, val->mask, ETH_ALEN);
#if __BYTE_ORDER == __LITTLE_ENDIAN
		mac_mask_u64 <<= 16;
#else
		mac_mask_u64 >>= 16;
#endif
		mac_mask_u64 = ntohll(mac_mask_u64);
		snprintf(buf2, sizeof(buf2), "%s/0x%llx",
			 b1, mac_mask_u64);
		print_string(PRINT_ANY, json_name, buf, buf2);
	} else {
		print_string(PRINT_ANY, json_name, buf, b1);
	}
}

static int check_ffs_128(__u8 *mask_val)
{
	bool found_zero = false;
	__u8 ffs = 0;
	int i;

	for (i = 0; i < 16; i++) {
		__u8 mask_tmp = mask_val[i];
		__u32 mask_1 = 0x80;
		__u8 ffs_byte = 0;

		if (!mask_tmp)
			continue;

		while (mask_tmp & mask_1) {
			if (found_zero)
				return -1;
			mask_1 >>= 1;
			ffs_byte++;
		}

		if (ffs_byte < 8) {
			if (found_zero || ((__u8)(mask_tmp << ffs_byte)) != 0)
				return -1;
			found_zero = true;
		}
		ffs += ffs_byte;
	}

	return ffs;
}

#if __BYTE_ORDER == __LITTLE_ENDIAN
static int check_fls(__u32 mask_val)
{
	__u8 *mask_u8 = (__u8 *)&mask_val;
	__u8 fls = 0;
	int i;

	for (i = 0; i < sizeof(__u32); i++) {
		__u32 mask_tmp = mask_u8[i];
		__u32 mask_1 = 0x1;
		__u8 fls_byte = 0;

		if (!mask_tmp) {
			if (fls)
				return -1;

			continue;
		}

		while (mask_tmp & mask_1) {
			mask_1 <<= 1;
			fls_byte++;
		}

		if (fls_byte < 8)
			if (fls || (mask_tmp >> fls_byte))
				return -1;
		fls += fls_byte;
	}

	return fls;
}
#else
static int check_ffs(__u32 mask_val)
{
	__u32 mask_tmp;
	__u8 ffs_ret;
	int i;

	ffs_ret = ffs(mask_val);

	if (mask_val >> ffs_ret)
		return -1;

	return ffs_ret ? 33 - ffs_ret : 0;
}
#endif

static void print_p4t_ipv4_val(const char *name, const char *json_name,
			       struct p4_type_value *val, FILE *f)
{
	__u8 *addr = val->value;
	SPRINT_BUF(buf1);
	SPRINT_BUF(buf2);
	SPRINT_BUF(buf);
	int len;

	strlcpy(buf, name, SPRINT_BSIZE - 1);
	strncat(buf, " %s", SPRINT_BSIZE - 1);

	if (val->mask) {
		__be32 mask_val = htonl((*(__be32 *)val->mask));

#if __BYTE_ORDER == __LITTLE_ENDIAN
		len = check_fls(mask_val);
#else
		len = check_ffs(mask_val);
#endif
		if (len >= 0)
			snprintf(buf2, sizeof(buf2), "%s/%d",
				 format_host_r(AF_INET, 4, addr, buf1, sizeof(buf1)),
				 len);
		else
			snprintf(buf2, sizeof(buf2), "%s/%x",
				 format_host_r(AF_INET, 4, addr, buf1, sizeof(buf1)),
				 mask_val);
	} else {
		snprintf(buf2, sizeof(buf2), "%s",
			 format_host_r(AF_INET, 4, addr, buf1, sizeof(buf1)));
	}

	print_string(PRINT_ANY, json_name, buf, buf2);
}

static void build_p4t_ipv6_val_mask(char *buf, __u8 *mask)
{
	int i;

	for (i = 0; i < 16; i++) {
		char buf_tmp[4] = {0};

		snprintf(buf_tmp, 3, "%02x", mask[i]);
		memcpy(&buf[i << 1], buf_tmp, 2);
	}
}

static void print_p4t_ipv6_val(const char *name, const char *json_name,
			       struct p4_type_value *val, FILE *f)
{
	__u8 *addr = val->value;
	char buf2[128] = {0};
	SPRINT_BUF(buf1);
	SPRINT_BUF(buf);

	strlcpy(buf, name, SPRINT_BSIZE - 1);
	strncat(buf, " %s", SPRINT_BSIZE - 1);

	if (val->mask) {
		int len = check_ffs_128(val->mask);

		if (len >= 0) {
			snprintf(buf2, sizeof(buf2), "%s/%d",
				 format_host_r(AF_INET6, 16, addr, buf1, sizeof(buf1)),
				 len);
		} else {
			char buf_tmp[80] = {0};

			build_p4t_ipv6_val_mask(buf_tmp, val->mask);
			snprintf(buf2, sizeof(buf2), "%s/%s",
				 format_host_r(AF_INET6, 16, addr, buf1, sizeof(buf1)),
				 buf_tmp);
		}
	} else {
		snprintf(buf2, sizeof(buf2), "%s",
			 format_host_r(AF_INET6, 16, addr, buf1, sizeof(buf1)));
	}

	print_string(PRINT_ANY, json_name, buf, buf2);
}

struct p4_type_s *get_p4type_byid(int id)
{
	struct hlist_node *t, *tmp_child;

	hlist_for_each_safe(t, tmp_child, &types_list) {
		struct p4_type_s *type;

		type = container_of(t, struct p4_type_s, hlist);
		if (type->containid == id)
			return type;
	}

	return NULL;
}

struct p4_type_s *get_p4type_bysize(int sz, __u8 flags)
{
	struct hlist_node *t, *tmp_child;

	hlist_for_each_safe(t, tmp_child, &types_list) {
		struct p4_type_s *type;

		type = container_of(t, struct p4_type_s, hlist);
		if (type->bitsz == sz && (flags & type->flags))
			return type;
	}

	return NULL;
}

struct p4_type_s *get_p4type_byname(const char *name)
{
	struct hlist_node *t, *tmp_child;

	hlist_for_each_safe(t, tmp_child, &types_list) {
		struct p4_type_s *type;

		type = container_of(t, struct p4_type_s, hlist);
		if (strcasecmp(type->name, name) == 0)
			return type;
	}

	return NULL;
}

struct p4_type_s *get_p4type_byarg(const char *argv, __u32 *bitsz)
{
	struct p4_type_s *p4_type;
	int rc;

	/* fix-size integer */
	if (strncmp("bit", argv, 3) == 0 || strncmp("int", argv, 3) == 0 ||
	    strncmp("be", argv, 2) == 0) {
		__u8 flags = P4TC_T_TYPE_BIT;
		__u8 containersz;

		rc = sscanf(argv, "bit%u", bitsz);
		if (rc != 1) {
			rc = sscanf(argv, "int%u", bitsz);
			if (rc != 1) {
				rc = sscanf(argv, "be%u", bitsz);
				if (rc != 1) {
					fprintf(stderr, "Invalid type %s\n",
						argv);
					return NULL;
				}
				flags = P4TC_T_TYPE_BIGENDIAN;
			} else {
				flags = P4TC_T_TYPE_INT;
			}
		}
		if (*bitsz <= 8) {
			containersz = 8;
		} else if (*bitsz <= 16) {
			containersz = 16;
		} else if (*bitsz <= 32) {
			containersz = 32;
		} else if (*bitsz <= 64) {
			containersz = 64;
		} else if (*bitsz <= 128) {
			containersz = 128;
		} else {
			fprintf(stderr, "bad size %d\n", *bitsz);
			return NULL;
		}

		p4_type = get_p4type_bysize(containersz, flags);
	/* Something else */
	} else {
		p4_type = get_p4type_byname(argv);
		if (!p4_type) {
			fprintf(stderr, "Unknown p4 type %s\n", argv);
			return NULL;
		}
		*bitsz = p4_type->bitsz;
	}

	return p4_type;
}

static struct p4_type_s u8_typ = {
	.containid = P4TC_T_U8,
	.bitsz = 8,
	.startbit = 0,
	.endbit = 7,
	.parse_p4t = parse_p4t_u8_val,
	.print_p4t = print_p4t_u8_val,
	.name = "bit8",
	.flags = P4TC_T_TYPE_BIT | P4TC_T_TYPE_HAS_MASK | P4TC_T_TYPE_UNSIGNED,
};
static struct p4_type_s u16_typ = {
	.containid = P4TC_T_U16,
	.bitsz = 16,
	.startbit = 0,
	.endbit = 15,
	.parse_p4t = parse_p4t_u16_val,
	.print_p4t = print_p4t_u16_val,
	.name = "bit16",
	.flags = P4TC_T_TYPE_BIT | P4TC_T_TYPE_HAS_MASK | P4TC_T_TYPE_UNSIGNED,
};

static struct p4_type_s u32_typ = {
	.containid = P4TC_T_U32,
	.bitsz = 32,
	.startbit = 0,
	.endbit = 31,
	.parse_p4t = parse_p4t_u32_val,
	.print_p4t = print_p4t_u32_val,
	.name = "bit32",
	.flags = P4TC_T_TYPE_BIT | P4TC_T_TYPE_HAS_MASK | P4TC_T_TYPE_UNSIGNED,
};

static struct p4_type_s dev_typ = {
	.containid = P4TC_T_DEV,
	.bitsz = 32,
	.startbit = 0,
	.endbit = 31,
	.parse_p4t = parse_p4t_dev_val,
	.print_p4t = print_p4t_dev_val,
	.name = "dev",
};

static struct p4_type_s be32_typ = {
	.containid = P4TC_T_BE32,
	.bitsz = 32,
	.startbit = 0,
	.endbit = 31,
	.parse_p4t = parse_p4t_be32_val,
	.print_p4t = print_p4t_be32_val,
	.name = "be32",
	.flags = P4TC_T_TYPE_BIGENDIAN | P4TC_T_TYPE_HAS_MASK,
};

static struct p4_type_s u64_typ = {
	.containid = P4TC_T_U64,
	.bitsz = 64,
	.startbit = 0,
	.endbit = 63,
	.parse_p4t = parse_p4t_u64_val,
	.print_p4t = print_p4t_u64_val,
	.name = "bit64",
	.flags = P4TC_T_TYPE_BIT | P4TC_T_TYPE_HAS_MASK | P4TC_T_TYPE_UNSIGNED,
};

static struct p4_type_s rate_typ = {
	.containid = P4TC_T_RATE,
	.bitsz = 64,
	.startbit = 0,
	.endbit = 63,
	.parse_p4t = parse_p4t_rate_val,
	.print_p4t = print_p4t_rate_val,
	.name = "rate",
	.flags = P4TC_T_TYPE_UNSIGNED | P4TC_T_TYPE_HAS_MASK,
};

static struct p4_type_s be64_typ = {
	.containid = P4TC_T_BE64,
	.bitsz = 64,
	.startbit = 0,
	.endbit = 63,
	.parse_p4t = parse_p4t_be64_val,
	.print_p4t = print_p4t_be64_val,
	.name = "be64",
	.flags = P4TC_T_TYPE_BIGENDIAN | P4TC_T_TYPE_HAS_MASK,
};

static struct p4_type_s u128_typ = {
	.containid = P4TC_T_U128,
	.parse_p4t = parse_p4t_u128_val,
	.print_p4t = print_p4t_u128_val,
	.bitsz = 128,
	.startbit = 0,
	.endbit = 127,
	.name = "bit128",
	.flags = P4TC_T_TYPE_BIT | P4TC_T_TYPE_UNSIGNED,
};

static struct p4_type_s s8_typ = {
	.containid = P4TC_T_S8,
	.bitsz = 8,
	.startbit = 0,
	.endbit = 7,
	.parse_p4t = parse_p4t_s8_val,
	.print_p4t = NULL,
	.name = "int8",
	.flags = P4TC_T_TYPE_INT | P4TC_T_TYPE_SIGNED,
};

static struct p4_type_s s16_typ = {
	.containid = P4TC_T_S16,
	.bitsz = 16,
	.startbit = 0,
	.endbit = 15,
	.parse_p4t = parse_p4t_s16_val,
	.print_p4t = NULL,
	.name = "int16",
	.flags = P4TC_T_TYPE_INT | P4TC_T_TYPE_SIGNED,
};

static struct p4_type_s be16_typ = {
	.containid = P4TC_T_BE16,
	.bitsz = 16,
	.startbit = 0,
	.endbit = 15,
	.parse_p4t = parse_p4t_be16_val,
	.print_p4t = print_p4t_be16_val,
	.name = "be16",
	.flags = P4TC_T_TYPE_BIGENDIAN | P4TC_T_TYPE_HAS_MASK,
};

static struct p4_type_s s32_typ = {
	.containid = P4TC_T_S32,
	.bitsz = 32,
	.startbit = 0,
	.endbit = 31,
	.parse_p4t = parse_p4t_s32_val,
	.print_p4t = print_p4t_s32_val,
	.name = "int32",
	.flags = P4TC_T_TYPE_INT | P4TC_T_TYPE_SIGNED,
};

static struct p4_type_s s64_typ = {
	.containid = P4TC_T_S64,
	.bitsz = 64,
	.startbit = 0,
	.endbit = 63,
	.name = "int64",
	.flags = P4TC_T_TYPE_INT | P4TC_T_TYPE_SIGNED,
};

static struct p4_type_s s128_typ = {
	.containid = P4TC_T_S128,
	.bitsz = 128,
	.startbit = 0,
	.endbit = 127,
	.name = "int128",
	.flags = P4TC_T_TYPE_INT | P4TC_T_TYPE_SIGNED,
};

static struct p4_type_s string_typ = {
	.containid = P4TC_T_STRING,
	.bitsz = P4TC_T_MAX_STR_SZ * 8,
	.startbit = BITSZ_IRRELEVANT,
	.endbit = BITSZ_IRRELEVANT,
	.name = "strn"
};

static struct p4_type_s mac_typ = {
	.containid = P4TC_T_MACADDR,
	.parse_p4t = parse_p4t_mac_val,
	.print_p4t = print_p4t_mac_val,
	.bitsz = 48,
	.startbit = 0,
	.endbit = 47,
	.name = "macaddr",
	.flags = P4TC_T_TYPE_HAS_MASK,
};

static struct p4_type_s ipv4_typ = {
	.containid = P4TC_T_IPV4ADDR,
	.parse_p4t = parse_p4t_ipv4_val,
	.print_p4t = print_p4t_ipv4_val,
	.bitsz = 32,
	.startbit = 0,
	.endbit = 31,
	.name = "ipv4",
	.flags = P4TC_T_TYPE_HAS_MASK,
};

static struct p4_type_s ipv6_typ = {
	.containid = P4TC_T_U128,
	.parse_p4t = parse_p4t_ipv6_val,
	.print_p4t = print_p4t_ipv6_val,
	.bitsz = 128,
	.startbit = 0,
	.endbit = 127,
	.name = "ipv6",
	.flags = P4TC_T_TYPE_HAS_MASK,
};

static struct p4_type_s bool_typ = {
	.containid = P4TC_T_BOOL,
	.bitsz = 1,
	.startbit = 0,
	.endbit = 0,
	.parse_p4t = parse_p4t_bool_val,
	.print_p4t = print_p4t_bool_val,
	.name = "bool",
};

static struct p4_type_s key_typ = {
	.containid = P4TC_T_KEY,
	.bitsz = P4TC_MAX_KEYSZ,
	.startbit = 0,
	.endbit = P4TC_MAX_KEYSZ - 1,
	.name = "key",
};

void register_p4_types(void)
{
	hlist_add_head(&u8_typ.hlist, &types_list);
	hlist_add_head(&u16_typ.hlist, &types_list);
	hlist_add_head(&u32_typ.hlist, &types_list);
	hlist_add_head(&bool_typ.hlist, &types_list);
	hlist_add_head(&u64_typ.hlist, &types_list);
	hlist_add_head(&rate_typ.hlist, &types_list);
	hlist_add_head(&u128_typ.hlist, &types_list);
	hlist_add_head(&s8_typ.hlist, &types_list);
	hlist_add_head(&s16_typ.hlist, &types_list);
	hlist_add_head(&s32_typ.hlist, &types_list);
	hlist_add_head(&s64_typ.hlist, &types_list);
	hlist_add_head(&s128_typ.hlist, &types_list);
	hlist_add_head(&be16_typ.hlist, &types_list);
	hlist_add_head(&be32_typ.hlist, &types_list);
	hlist_add_head(&be64_typ.hlist, &types_list);
	hlist_add_head(&string_typ.hlist, &types_list);
	hlist_add_head(&mac_typ.hlist, &types_list);
	hlist_add_head(&ipv4_typ.hlist, &types_list);
	hlist_add_head(&ipv6_typ.hlist, &types_list);
	hlist_add_head(&dev_typ.hlist, &types_list);
	hlist_add_head(&key_typ.hlist, &types_list);
}

void unregister_p4_types(void)
{
	hlist_del(&u8_typ.hlist);
	hlist_del(&u16_typ.hlist);
	hlist_del(&u32_typ.hlist);
	hlist_del(&bool_typ.hlist);
	hlist_del(&u64_typ.hlist);
	hlist_del(&u128_typ.hlist);
	hlist_del(&s8_typ.hlist);
	hlist_del(&s16_typ.hlist);
	hlist_del(&s32_typ.hlist);
	hlist_del(&s64_typ.hlist);
	hlist_del(&s128_typ.hlist);
	hlist_del(&be16_typ.hlist);
	hlist_del(&be32_typ.hlist);
	hlist_del(&string_typ.hlist);
	hlist_del(&mac_typ.hlist);
	hlist_del(&ipv4_typ.hlist);
	hlist_del(&ipv6_typ.hlist);
	hlist_del(&dev_typ.hlist);
	hlist_del(&key_typ.hlist);
}
