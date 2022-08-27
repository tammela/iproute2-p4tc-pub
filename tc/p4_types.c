#include "p4_types.h"

#define P4TC_T_TYPE_UNSIGNED 0x1
#define P4TC_T_TYPE_SIGNED 0x2
#define P4TC_T_TYPE_BIGENDIAN 0x4

#define BITSZ_IRRELEVANT 0

static struct hlist_head types_list = {};

static int parse_p4t_u8_val(struct p4_type_value *val, const char *arg, int base)
{
	__u8 *newval = val->value;
	__u8 ival;


	if (get_u8(&ival, arg, base))
		return -1;

	if (val->bitsz < 8) {
		if (ival > (1 << val->bitsz) - 1) {
			fprintf(stderr, "Value doesn't fit in bitsz\n");
			return -1;
		}
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
	__u16 ival;

	if (get_u16(&ival, arg, base))
		return -1;

	if (val->bitsz < 16) {
		if (ival > (1 << val->bitsz) - 1) {
			fprintf(stderr, "Value doesn't fit in bitsz\n");
			return -1;
		}
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

	if (val->bitsz < 16) {
		if ((__u16)ival > (1 << (val->bitsz)) - 1) {
			fprintf(stderr, "Value doesn't fit in bitsz\n");
			return -1;
		}
	}

	*newval = ival;
	return 0;
}

static int parse_p4t_be16_val(struct p4_type_value *val, const char *arg,
			      int base)
{
	__be16 *newval = val->value;
	__be16 ival;

	if (get_be16(&ival, arg, base))
		return -1;

	if (val->bitsz < 16) {
		if (ival > (1 << val->bitsz) - 1) {
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

	if (val->bitsz < 32) {
		if ((__u32)ival > (1 << (val->bitsz)) - 1) {
			fprintf(stderr, "Value doesn't fit in bitsz\n");
			return -1;
		}
	}

	*newval = ival;
	return 0;
}

static int parse_p4t_u64_val(struct p4_type_value *val, const char *arg,
			     int base)
{
	__u64 *newval = val->value;
	__u64 ival;

	if (get_u64(&ival, arg, base))
		return -1;

	if (val->bitsz < 64) {
		if (ival > (1ULL << val->bitsz) - 1) {
			fprintf(stderr, "Value doesn't fit in bitsz\n");
			return -1;
		}
	}

	*newval = ival;
	return 0;
}

static int parse_p4t_u32_val(struct p4_type_value *val, const char *arg,
			     int base)
{
	__u32 *newval = val->value;
	__u32 ival;

	if (get_u32(&ival, arg, base))
		return -1;

	if (val->bitsz < 32) {
		if (ival > (1 << val->bitsz) - 1) {
			fprintf(stderr, "Value doesn't fit in bitsz\n");
			return -1;
		}
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
	__be32 ival;

	if (get_be32(&ival, arg, base))
		return -1;

	if (val->bitsz < 32) {
		if (ival > (1 << val->bitsz) - 1) {
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
	__be64 ival;

	if (get_be64(&ival, arg, base))
		return -1;

	if (val->bitsz < 64) {
		if (ival > (1 << val->bitsz) - 1) {
			fprintf(stderr, "Value doesn't fit in bitsz\n");
			return -1;
		}
	}

	*newval = ival;
	return 0;
}

// Function to check if a string is hexadecimal using strtol
static bool is_hexadecimal(const char *str) {
    char *endptr;

    if (str[0] != '0' && str[1] != 'x')
	    return false;

    strtol(str, &endptr, 16);

    // Check if the entire string was a valid hexadecimal number
    return (*str != '\0' && *endptr == '\0');
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

static int parse_p4t_ipv4_val(struct p4_type_value *val, const char *arg,
			      int base)
{
	__u32 *newaddr = val->value;
	__u32 *new_mask = val->mask;
	inet_prefix iaddr;

	if (get_prefix_1(&iaddr, (char *)arg, AF_INET))
		return -1;

	memcpy(newaddr, iaddr.data, sizeof(__u32));
#if __BYTE_ORDER == __LITTLE_ENDIAN
	*new_mask = ~((__u32)(GENMASK(31, iaddr.bitlen)));
#else
	*new_mask = ~((__u32)(GENMASK(31, 31 - iaddr.bitlen - 1)));
#endif

	return 0;
}

static int parse_p4t_ipv6_val(struct p4_type_value *val, const char *arg,
			      int base)
{
	__u8 *newaddr = val->value;
	__u8 *newmask = val->mask;
	inet_prefix iaddr;
	int i;

	if (get_prefix_1(&iaddr, (char *)arg, AF_INET6))
		return -1;

	memcpy(newaddr, iaddr.data, 16);
	memset(val->mask, 0, 16);

	for (i = 0; i < iaddr.bitlen; i += 8) {
		if (i + 7 < iaddr.bitlen)
			newmask[i >> 3] = 0xFF;
		else if (i < iaddr.bitlen)
			 newmask[i >> 3] = (0xFF << (7 - (iaddr.bitlen - i)));
		else
			newmask[i >> 3] = 0;
	}

	return 0;
}

static int parse_p4t_dev_val(struct p4_type_value *val, const char *arg,
			     int base)
{
	const char *devname = arg;
	__u32 *newval = val->value;
	int idx;

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
	char *newval = val->value;

	if (ll_addr_a2n(newval, ETH_ALEN, arg) < 0) {
		fprintf(stderr, "mac is invalid %s\n", newval);
		return -1;
	}

	return 0;
}

static void print_p4t_u8_val(const char *name, const char *json_name,
			     struct p4_type_value *val, FILE *f)
{
	__u8 *ival = val->value;
	SPRINT_BUF(buf);

	strlcpy(buf, name, SPRINT_BSIZE - 1);
	strncat(buf, " %u", SPRINT_BSIZE - 1);

	print_uint(PRINT_ANY, json_name, buf, *ival);
}

static void print_p4t_u16_val(const char *name, const char *json_name,
			      struct p4_type_value *val, FILE *f)
{
	__u16 *ival = val->value;
	SPRINT_BUF(buf);

	strlcpy(buf, name, SPRINT_BSIZE - 1);
	strncat(buf, " %u", SPRINT_BSIZE - 1);

	print_uint(PRINT_ANY, json_name, buf, *ival);
}

static void print_p4t_be16_val(const char *name, const char *json_name,
			       struct p4_type_value *val, FILE *f)
{
	__be16 *ival = val->value;
	SPRINT_BUF(buf);

	strlcpy(buf, name, SPRINT_BSIZE - 1);
	strncat(buf, " %u", SPRINT_BSIZE - 1);

	print_uint(PRINT_ANY, json_name, buf, htons(*ival));
}

static void print_p4t_u32_val(const char *name, const char *json_name,
			      struct p4_type_value *val, FILE *f)
{
	__u32 *ival = val->value;
	SPRINT_BUF(buf);

	strlcpy(buf, name, SPRINT_BSIZE - 1);
	strncat(buf, " %u", SPRINT_BSIZE - 1);

	print_uint(PRINT_ANY, json_name, buf, *ival);
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
	SPRINT_BUF(buf);

	strlcpy(buf, name, SPRINT_BSIZE - 1);
	strncat(buf, " %u", SPRINT_BSIZE - 1);

	print_uint(PRINT_ANY, json_name, buf, ntohl(*ival));
}

static void print_p4t_u64_val(const char *name, const char *json_name,
			      struct p4_type_value *val, FILE *f)
{
	__u64 *ival = val->value;
	SPRINT_BUF(buf);

	strlcpy(buf, name, SPRINT_BSIZE - 1);
	strncat(buf, " %llu", SPRINT_BSIZE - 1);

	print_lluint(PRINT_ANY, json_name, buf, *ival);
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
	SPRINT_BUF(buf);

	strlcpy(buf, name, SPRINT_BSIZE - 1);
	strncat(buf, " %llu", SPRINT_BSIZE - 1);

	print_lluint(PRINT_ANY, json_name, buf, ntohll(*ival));
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
	SPRINT_BUF(b1);
	SPRINT_BUF(buf);

	strlcpy(buf, name, SPRINT_BSIZE - 1);
	strncat(buf, " %s", SPRINT_BSIZE - 1);

	ll_addr_n2a(mac_val, ETH_ALEN, 0, b1, sizeof(b1));
	print_string(PRINT_ANY, json_name, buf, b1);
}

static __u8 fls(__u32 mask_val)
{
	__u8 *mask_u8 = (__u8 *)&mask_val;
	__u8 ffl = 0;
	int i;

	for (i = 0; i < sizeof(__u32); i++) {
		__u32 mask_tmp = mask_u8[i];

		while (mask_tmp) {
			mask_tmp >>= 1;
			ffl++;
		}
	}

	return ffl;
}

static __u8 fls_128(__u8 *mask_val)
{
	__u8 fls = 0;
	int i;

	for (i = 0; i < 16; i++) {
		__u8 mask_tmp = mask_val[i];

		while (mask_tmp) {
			mask_tmp >>= 1;
			fls++;
		}
	}

	return fls;
}

#if __BYTE_ORDER == __BIG_ENDIAN
static __u8 ffs_128(__u8 *mask_val)
{
	int i;
	__u8 ffs = 0;

	for (i = 15; i >= 0; i++) {
		__u8 mask_tmp = mask_val[i];

		while (mask_tmp) {
			mask_tmp >>= 1;
			ffs++;
		}
	}

	return ffs;
}
#endif

static void print_p4t_ipv4_val(const char *name, const char *json_name,
			       struct p4_type_value *val, FILE *f)
{
	__u8 *addr = val->value;
	SPRINT_BUF(buf1);
	SPRINT_BUF(buf2);
	__be32 mask_val;
	SPRINT_BUF(buf);
	int len;

	strlcpy(buf, name, SPRINT_BSIZE - 1);
	strncat(buf, " %s", SPRINT_BSIZE - 1);

	mask_val = htonl((*(__be32 *)val->mask));

#if __BYTE_ORDER == __LITTLE_ENDIAN
	len = fls(mask_val);
#else
	len = ffs(mask_val);
#endif
	snprintf(buf2, sizeof(buf2), "%s/%d",
		 format_host_r(AF_INET, 4, addr, buf1, sizeof(buf1)),
		 len);

	print_string(PRINT_ANY, json_name, buf, buf2);
}

static void print_p4t_ipv6_val(const char *name, const char *json_name,
			       struct p4_type_value *val, FILE *f)
{
	__u8 *addr = val->value;
	SPRINT_BUF(buf1);
	SPRINT_BUF(buf2);
	SPRINT_BUF(buf);
	int len;

	strlcpy(buf, name, SPRINT_BSIZE - 1);
	strncat(buf, " %s", SPRINT_BSIZE - 1);

#if __BYTE_ORDER == __LITTLE_ENDIAN
	len = fls_128(val->mask);
#else
	len = ffs_128(val->mask);
#endif
	snprintf(buf2, sizeof(buf2), "%s/%d",
		 format_host_r(AF_INET6, 16, addr, buf1, sizeof(buf1)),
		 len);

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
	if (strncmp("bit", argv, 3) == 0 || strncmp("int", argv, 3) == 0) {
		__u8 flags = P4TC_T_TYPE_UNSIGNED;
		__u8 containersz;

		rc = sscanf(argv, "bit%u", bitsz);
		if (rc != 1) {
			rc = sscanf(argv, "int%u", bitsz);
			if (rc != 1) {
				fprintf(stderr, "Invalid type %s\n", argv);
				return NULL;
			}
			flags = P4TC_T_TYPE_SIGNED;
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
	.flags = P4TC_T_TYPE_UNSIGNED,
};
static struct p4_type_s u16_typ = {
	.containid = P4TC_T_U16,
	.bitsz = 16,
	.startbit = 0,
	.endbit = 15,
	.parse_p4t = parse_p4t_u16_val,
	.print_p4t = print_p4t_u16_val,
	.name = "bit16",
	.flags = P4TC_T_TYPE_UNSIGNED,
};

static struct p4_type_s u32_typ = {
	.containid = P4TC_T_U32,
	.bitsz = 32,
	.startbit = 0,
	.endbit = 31,
	.parse_p4t = parse_p4t_u32_val,
	.print_p4t = print_p4t_u32_val,
	.name = "bit32",
	.flags = P4TC_T_TYPE_UNSIGNED,
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
	.flags = P4TC_T_TYPE_BIGENDIAN,
};

static struct p4_type_s u64_typ = {
	.containid = P4TC_T_U64,
	.bitsz = 64,
	.startbit = 0,
	.endbit = 63,
	.parse_p4t = parse_p4t_u64_val,
	.print_p4t = print_p4t_u64_val,
	.name = "bit64",
	.flags = P4TC_T_TYPE_UNSIGNED,
};

static struct p4_type_s be64_typ = {
	.containid = P4TC_T_BE64,
	.bitsz = 64,
	.startbit = 0,
	.endbit = 63,
	.parse_p4t = parse_p4t_be64_val,
	.print_p4t = print_p4t_be64_val,
	.name = "be64",
	.flags = P4TC_T_TYPE_BIGENDIAN,
};

static struct p4_type_s u128_typ = {
	.containid = P4TC_T_U128,
	.parse_p4t = parse_p4t_u128_val,
	.print_p4t = print_p4t_u128_val,
	.bitsz = 128,
	.startbit = 0,
	.endbit = 127,
	.name = "bit128",
	.flags = P4TC_T_TYPE_UNSIGNED,
};

static struct p4_type_s s8_typ = {
	.containid = P4TC_T_S8,
	.bitsz = 8,
	.startbit = 0,
	.endbit = 7,
	.parse_p4t = parse_p4t_s8_val,
	.print_p4t = NULL,
	.name = "int8",
	.flags = P4TC_T_TYPE_SIGNED,
};

static struct p4_type_s s16_typ = {
	.containid = P4TC_T_S16,
	.bitsz = 16,
	.startbit = 0,
	.endbit = 15,
	.parse_p4t = parse_p4t_s16_val,
	.print_p4t = NULL,
	.name = "int16",
	.flags = P4TC_T_TYPE_SIGNED,
};

static struct p4_type_s be16_typ = {
	.containid = P4TC_T_BE16,
	.bitsz = 16,
	.startbit = 0,
	.endbit = 15,
	.parse_p4t = parse_p4t_be16_val,
	.print_p4t = print_p4t_be16_val,
	.name = "be16",
	.flags = P4TC_T_TYPE_BIGENDIAN,
};

static struct p4_type_s s32_typ = {
	.containid = P4TC_T_S32,
	.bitsz = 32,
	.startbit = 0,
	.endbit = 31,
	.parse_p4t = parse_p4t_s32_val,
	.print_p4t = print_p4t_s32_val,
	.name = "int32",
	.flags = P4TC_T_TYPE_SIGNED,
};

static struct p4_type_s s64_typ = {
	.containid = P4TC_T_S64,
	.bitsz = 64,
	.startbit = 0,
	.endbit = 63,
	.name = "int64",
	.flags = P4TC_T_TYPE_SIGNED,
};

static struct p4_type_s s128_typ = {
	.containid = P4TC_T_S128,
	.bitsz = 128,
	.startbit = 0,
	.endbit = 127,
	.name = "int128",
	.flags = P4TC_T_TYPE_SIGNED,
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
	.name = "macaddr"
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
