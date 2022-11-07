/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef __LINUX_P4TC_EXT_H
#define __LINUX_P4TC_EXT_H

#include <linux/types.h>
#include <linux/pkt_sched.h>

#define P4TC_EXT_NAMSIZ 64
#define P4TC_EXT_MAX_PRIO 32

/* Extern attributes */
enum {
	P4TC_EXT_UNSPEC,
	P4TC_EXT_INST_NAME,
	P4TC_EXT_KIND,
	P4TC_EXT_PARAMS,
	P4TC_EXT_FCNT,
	P4TC_EXT_PAD,
	P4TC_EXT_FLAGS,
	P4TC_EXT_HW_STATS,
	P4TC_EXT_USED_HW_STATS,
	P4TC_EXT_IN_HW_COUNT,
	__P4TC_EXT_MAX
};

#define P4TC_EXT_ID_DYN 0x01
#define P4TC_EXT_ID_MAX 1023

/* See other P4TC_EXT_FLAGS_ * flags in include/net/act_api.h. */
#define P4TC_EXT_FLAGS_NO_PERCPU_STATS (1 << 0) /* Don't use percpu allocator for
						* externs stats.
						*/
#define P4TC_EXT_FLAGS_SKIP_HW	(1 << 1) /* don't offload action to HW */
#define P4TC_EXT_FLAGS_SKIP_SW	(1 << 2) /* don't use action in SW */

#define TCA_FLAG_LARGE_DUMP_ON		(1 << 0)
#define P4TC_EXT_FLAG_LARGE_DUMP_ON	TCA_FLAG_LARGE_DUMP_ON
#define P4TC_EXT_FLAG_TERSE_DUMP		(1 << 1)

/* tca HW stats type
 * When user does not pass the attribute, he does not care.
 * It is the same as if he would pass the attribute with
 * all supported bits set.
 * In case no bits are set, user is not interested in getting any HW statistics.
 */
#define P4TC_EXT_HW_STATS_IMMEDIATE (1 << 0) /* Means that in dump, user
					     * gets the current HW stats
					     * state from the device
					     * queried at the dump time.
					     */
#define P4TC_EXT_HW_STATS_DELAYED (1 << 1) /* Means that in dump, user gets
					   * HW stats that might be out of date
					   * for some time, maybe couple of
					   * seconds. This is the case when
					   * driver polls stats updates
					   * periodically or when it gets async
					   * stats update from the device.
					   */

#define P4TC_EXT_MAX __P4TC_EXT_MAX
#define P4TC_EXT_OLD_COMPAT (P4TC_EXT_MAX+1)
#define P4TC_EXT_MAX_PRIO 32

#define TC_ACT_UNSPEC	(-1)
#define TC_ACT_OK		0
#define TC_ACT_RECLASSIFY	1
#define TC_ACT_SHOT		2
#define TC_ACT_PIPE		3
#define TC_ACT_STOLEN		4
#define TC_ACT_QUEUED		5
#define TC_ACT_REPEAT		6
#define TC_ACT_REDIRECT		7
#define TC_ACT_TRAP		8 /* For hw path, this means "trap to cpu"
				   * and don't further process the frame
				   * in hardware. For sw path, this is
				   * equivalent of TC_ACT_STOLEN - drop
				   * the skb and ext like everything
				   * is alright.
				   */
#define TC_ACT_VALUE_MAX	TC_ACT_TRAP

/* There is a special kind of externs called "extended externs",
 * which need a value parameter. These have a local opcode located in
 * the highest nibble, starting from 1. The rest of the bits
 * are used to carry the value. These two parts together make
 * a combined opcode.
 */
#define __TC_ACT_EXT_SHIFT 28
#define __TC_ACT_EXT(local) ((local) << __TC_ACT_EXT_SHIFT)
#define TC_ACT_EXT_VAL_MASK ((1 << __TC_ACT_EXT_SHIFT) - 1)
#define TC_ACT_EXT_OPCODE(combined) ((combined) & (~TC_ACT_EXT_VAL_MASK))
#define TC_ACT_EXT_CMP(combined, opcode) (TC_ACT_EXT_OPCODE(combined) == opcode)

#define TC_ACT_JUMP __TC_ACT_EXT(1)
#define TC_ACT_GOTO_CHAIN __TC_ACT_EXT(2)
#define TC_ACT_EXT_OPCODE_MAX	TC_ACT_GOTO_CHAIN

#endif
