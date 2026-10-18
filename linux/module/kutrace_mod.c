/*
 * kutrace_mod.c
 *
 * Author: Richard Sites <dick.sites@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Signed-off-by: Richard Sites <dick.sites@gmail.com>
 */

/*
 * A module that implements kernel/user tracing
 * dsites 2024.05.29
 *
 * See include/linux/kutrace.h for struct definitions
 *
 * Most patches will be something like
 *   kutrace1(event, arg) which calls trace_1 here
 *
 */


/*
 * kutrace.c -- kernel/user tracing implementation
 * dsites 2019.02.14 Reworked for the 4.19 kernel, from dclab_trace.c 
 * dsites 2020.02.04 fixed getclaim(n) bug for n > 1 
 * dsites 2020.10.30 Add packet trace parameters
 *  use something like 
 *  sudo insmod kutrace_mod.ko tracemb=20 pktmask=0x0000000f pktmatch=0xd1c517e5
 *  default is the above
 *  pktmask=0 traces nothing, pktmask=-1 traces all (no pktmatch needed)
 * dsites 2023.02.13 Add fast 4KB trace buffer extraction
 * dsites 2023.02.13 Change module version number to 4
 * dsites 2023.02.16 Merge in TSDELTA code from FreeBSD version
 *
 * dsites 2023.06.22 Trace LLC misses instead of IPC per timespan
 * dsites 2023.06.25 Extend LLC range by 4x
 * dsites 2024.05.29 Combine to do either/both IPC and LLC
 * 2026.10 Add arm64 server support (NVIDIA Grace / Neoverse V2):
 *   - time base is CNTVCT_EL0, scaled down to <= 64 MHz (Grace: 1 GHz >> 4)
 *   - inst_retired/cycles/LLC misses via perf-reserved PMUv3 counters,
 *     read directly with mrs on the hot path
 *   - CPU frequency from the AMU core/constant cycle counters
 *
 */

#include <linux/kutrace.h>

#include <linux/capability.h>
#include <linux/compiler.h>	/* for unlikely() */
#include <linux/cpufreq.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/types.h>	/* u64, among others */
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <asm/atomic.h>
#include <asm/uaccess.h>

#include <linux/perf_event.h>
#include <linux/perf/arm_pmuv3.h>
#include <asm/arm_pmuv3.h>
#include <asm/cpufeature.h>
#include <asm/sysreg.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Richard L Sites");
MODULE_DESCRIPTION("KUtrace kernel/user transition tracing");

// Added 2023.02.13. Move these into the kernel at next build
#ifndef KUTRACE_CMD_SET4KB
#define KUTRACE_CMD_SET4KB 12
#endif

#ifndef KUTRACE_CMD_GET4KB
#define KUTRACE_CMD_GET4KB 13
#endif

#ifndef KUTRACE_CMD_GETIPC4KB
#define KUTRACE_CMD_GETIPC4KB 14
#endif

#ifndef KUTRACE_TSDELTA
#define KUTRACE_TSDELTA         0x21D  /* Delta to advance timestamp */
#endif

/* int hack_count = 0; */

/* NVIDIA Grace (Neoverse V2, arm64) only */
typedef long long int int64;
typedef long long unsigned int uint64;
#define FLX "%016llx"
#define FLD "%lld"
#define FUINTPTRX "%016lx"
#define CL(x) x##LL
#define CLU(x) x##LLU
#define ATOMIC_READ atomic64_read
#define ATOMIC_SET atomic64_set
#define ATOMIC_ADD_RETURN atomic64_add_return



/* Forward declarations */
static u64 kutrace_control(u64 command, u64 arg);
static int __init kutrace_mod_init(void);

/* Incoming arg to do_reset from kutrace_control  */
#define DO_IPC 1
#define DO_WRAP 2
#define DO_LLC 4

/*Outgoing flags byte in each traceblock[1] */
#define IPC_Flag CLU(0x80)
#define WRAP_Flag CLU(0x40)
#define LLC_Flag CLU(0x20)

/* Module parameter: default how many MB of kernel trace memory to reserve */
/* This is for the standalone, non-module version */
/* static const long int kTraceMB = 32; */

/* Version number of this kernel tracing code */
/* 2023.02.13 Incremented to 4 for fast 4KB trace buffer extraction */
static const u64 kModuleVersionNumber = 4;


/* A few global variables */

/* IPC Instructions per cycle flag */
static bool do_ipc;	/* Initially false */

/* LLC cache misses flag */
static bool do_llc;	/* Initially false */

static bool do_neither;		/* !do_ipc and !do_llc */
static bool do_both;		/* do_ipc and do_llc */
static bool do_ipc_only;	/* do_ipc and !do_llc */

/* Wraparound tracing vs. stop when buffer is full */
static bool do_wrap;	/* Initially false */

/* Current offset to use for fast 4KB trace buffer extraction get4kb and getipc4kb */
/* Set by KUTRACE_CMD_SET4KB call */
static u64 get4kb_subscr;	/* Initially zero */

/* Module parameter: default how many MB of kernel trace memory to reserve */
static long int tracemb = 2;
static long int check = 1;	/* require PTRACE permission by default */

/* Module parameters: packet filtering. Initially match just dclab RPC markers */
static long int pktmask  = 0x0000000f;
static long int pktmatch = 0xd1c517e5;

module_param(tracemb, long, S_IRUSR);
MODULE_PARM_DESC(tracemb, "MB of kernel trace memory to reserve (2)");
module_param(check, long, S_IRUSR);
MODULE_PARM_DESC(check, "0: no checking, 1: require PTRACE capability for DoControl (1)");
module_param(pktmask, long, S_IRUSR);
MODULE_PARM_DESC(pktmask, "Bit-per-byte of which bytes to use in hash");
module_param(pktmatch, long, S_IRUSR);
MODULE_PARM_DESC(pktmatch, "Matching hash value");


/* These four are exported by our patched kernel. 
 * See linux-4.19.19/kernel/kutrace/kutrace.c
 */
extern bool kutrace_tracing;
extern struct kutrace_ops kutrace_global_ops;
extern u64* kutrace_pid_filter;
DECLARE_PER_CPU(struct kutrace_traceblock, kutrace_traceblock_per_cpu);


/*
 * Individual trace entries are at least one u64, with this format:
 *
 *  +-------------------+-----------+-------+-------+-------+-------+
 *  | timestamp         | event     | delta | retval|      arg0     |
 *  +-------------------+-----------+-------+-------+-------+-------+
 *           20              12         8       8           16
 *
 * timestamp: low 20 bits of some free-running time counter in the
 *   10-40 MHz range. For ARM, this is the 32 MHz cntvct_el0.
 * event: traced event number, syscall N, sysreturn N, etc.
 *   See user-mode kutrace_lib.h for the full set.
 *   matching call and return events differ just in one event bit.
 * delta: for optimized call-return, return timestamp - call timestamp,
 *   else zero.
 * retval: for optimized call-return, the low 8 bits of the return value,
 *   else zero.
 * arg0: for syscall, the low 16 bits of the first argument to the syscall,
 *   else zero.
 *
 * Multi-u64 entries have a count 1-8 in the middle 4 bits of event.
 *   These events are all in the range 0x000 to 0x1ff with the middle
 *   four bits non-zero.
 *
 * The first word of each 64KB block has this format:
 *  +-------+-------------------------------------------------------+
 *  |  cpu# |  full timestamp                                       |
 *  +-------+-------------------------------------------------------+
 *        56                                                       0
 *
 * The second word of each 64KB block has this format:
 *  +-------+-------------------------------------------------------+
 *  | flags |  gettimeofday() value to be filled in by user code    |
 *  +-------+-------------------------------------------------------+
 *        56                                                       0
 *
 */

#define ARG_MASK       CLU(0x00000000ffffffff)
#define ARG0_MASK      CLU(0x000000000000ffff)
#define RETVAL_MASK    CLU(0x0000000000ff0000)
#define DELTA_MASK     CLU(0x00000000ff000000)
#define EVENT_MASK     CLU(0x00000fff00000000)
#define TIMESTAMP_MASK CLU(0xfffff00000000000)
#define EVENT_DELTA_RETVAL_MASK (EVENT_MASK | DELTA_MASK | RETVAL_MASK)
#define EVENT_RETURN_BIT        CLU(0x0000020000000000)
#define EVENT_LENGTH_FIELD_MASK CLU(0x000000000000000f)

#define UNSHIFTED_RETVAL_MASK CLU(0x00000000000000ff)
#define UNSHIFTED_DELTA_MASK  CLU(0x00000000000000ff)
#define UNSHIFTED_EVENT_MASK  CLU(0x0000000000000fff)
#define UNSHIFTED_TIMESTAMP_MASK   CLU(0x00000000000fffff)
#define UNSHIFTED_EVENT_RETURN_BIT CLU(0x0000000000000200)
#define UNSHIFTED_EVENT_HAS_RETURN_MASK CLU(0x0000000000000c00)

#define MIN_EVENT_WITH_LENGTH CLU(0x010)
#define MAX_EVENT_WITH_LENGTH CLU(0x1ff)
#define MAX_DELTA_VALUE 255
#define MAX_PIDNAME_LENGTH 16

#define RETVAL_SHIFT 16
#define DELTA_SHIFT 24
#define EVENT_SHIFT 32
#define TIMESTAMP_SHIFT 44
#define EVENT_LENGTH_FIELD_SHIFT 4

#define FULL_TIMESTAMP_MASK CLU(0x00ffffffffffffff)
#define CPU_NUMBER_SHIFT 56

#define GETTIMEOFDAY_MASK   CLU(0x00ffffffffffffff)
#define FLAGS_SHIFT 56

/* For deciding that large timestamp advance is really a late store */
/* with backward time. */
static const u64 kLateStoreThresh = 0x00000000000e0000LLU;

/*
 * Trace memory is consumed backward, high to low
 * This allows valid test for full block even if an interrupt routine
 * switches to a new block mid-test. The condition tracebase == NULL
 * means that initialization needs to be called.
 *
 * Per-CPU trace blocks are 64KB, contining 8K u64 items. A trace entry is
 * 1-8 items. Trace entries do not cross block boundaries.
 *
 */
char *tracebase;	/* Initially NULL address of kernel trace memory */
u64 *traceblock_high;		/* just off high end of trace memory */
u64 *traceblock_limit;		/* at low end of trace memory */
u64 *traceblock_next;		/* starts at high, moves down to limit */
bool did_wrap_around;

/*
 * Trace memory layout without IPC/LLC tracing.
 *  tracebase
 *  traceblock_limit          traceblock_next                traceblock_high
 *  |                               |                                |
 *  v                               v                                v
 *  +-------+-------+------+--------+-------+-------+-------+-------+
 *  | / / / / / / / / / / / / / / / |                               |
 *  +-------+-------+------+--------+-------+-------+-------+-------+
 *                                  <==== allocated blocks grow down
 *
 *
 * Trace memory layout with IPC/LLCtracing. IPC/LLC bytes go into lower 1/8.
 *  tracebase
 *  |    traceblock_limit     traceblock_next                traceblock_high
 *  |       |                       |                                |
 *  v       v                       v                                v
 *  +-------+-------+------+--------+-------+-------+-------+-------+
 *  |////|  | / / / / / / / / / / / |                               |
 *  +-------+-------+------+--------+-------+-------+-------+-------+
 *       <==                        <==== allocated blocks grow down
 *       IPC/LLC bytes
 */

DEFINE_RAW_SPINLOCK(kutrace_lock);

/* Trace block size in bytes = 64KB */
#define KUTRACEBLOCKSHIFT (16)
#define KUTRACEBLOCKSIZE (1 << KUTRACEBLOCKSHIFT)

/* Trace block size in u64 words */
#define KUTRACEBLOCKSHIFTU64 (KUTRACEBLOCKSHIFT - 3)
#define KUTRACEBLOCKSIZEU64 (1 << KUTRACEBLOCKSHIFTU64)

/* IPC/LLC block size in u8 bytes */
#define KUIPCBLOCKSHIFTU8 (KUTRACEBLOCKSHIFTU64 - 3)
#define KUIPCBLOCKSIZEU8 (1 << KUIPCBLOCKSHIFTU8)

/* IPC design */
/* Map IPC * 8 [0.0 .. 3.75] into sorta-log value */
static const u64 kIpcMapping[64] = {
  0,1,2,3, 4,5,6,7, 8,8,9,9, 10,10,11,11, 
  12,12,12,12, 13,13,13,13, 14,14,14,14, 15,15,15,15,
  15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15,
  15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15
};

/* Just pick off 0, 8, 64, 1024 misses (0,512,4K,32K+) for 2 bits */
static const u64 kLlcSmall[16] = {
  0,0,1,1, 1,2,2,2, 3,3,3,3, 3,3,3,3 
};

/* Map IPC= inst_retired / cycles to sorta-log four bits */
/* NOTE: delta_cycles is in increments of cycles/64. The arithmetic */
/*       below compensates for this. */
/* 0, 1/8, 1/4, 3/8,  1/2, 5/8, 3/4, 7/8,  1, 5/4, 3/2, 7/4,  2, 5/2, 3, 7/2 */
static inline u64 get_granular_ipc(u64 delta_inst, u64 delta_cycles) {
  u32 del_inst, del_cycles, ipc;
  if ((delta_cycles & ~1) == 0) return 0; /* Too small to matter; avoid zdiv */
  /* Do 32-bit divide to save ~10 CPU cycles vs. 64-bit */
  /* With ~20ms guaranteed max interval, no overflow problems */
  del_inst = (u32)delta_inst;

  del_cycles = (u32)(delta_cycles << 3);  /* cycles/64 to cycles/8 */

  ipc = del_inst / del_cycles;	          /* gives IPC*8 */
  return kIpcMapping[ipc & 0x3F];	  /* Truncate unexpected IPC >= 8.0 */
}

/*  
 * Convert delta LLC miss count into floor(log2(delta))-1 for 8 <= delta < 64K
 *   i.e. 0=>0 1..7=>1, 8..15=>2, 16..31=>3 ... 32K..64K-1=>14 64K+=>15
 * Note that we map 2**0, 2**1, and 2**2 all to the same result, using the
 * missing two code points instead to extend our range to 64K+ misses 
 * (i.e. 4MB with 64-byte cache lines)
 */
static inline u64 get_granular_llc(u64 delta_llc) {
  u64 retval;
  if (delta_llc == 0) return 0;			/* common case, we hope */
  if ((delta_llc & ~CLU(0x7)) == 0) return 1;		/* 1..7 */
  if ((delta_llc & ~CLU(0xFFFF)) != 0) return 15;	/* 64K+ */ 
  /* 1 + floor(log2(delta)) */
  retval = 0;
  if ((delta_llc & CLU(0xFF00)) != 0) {
    delta_llc >>= 8;
    retval += 8;
  }
  if ((delta_llc & CLU(0x00F0)) != 0) {
    delta_llc >>= 4;
    retval += 4;
  }
  if ((delta_llc & CLU(0x000C)) != 0) {
    delta_llc >>= 2;
    retval += 2;
  }
  if ((delta_llc & CLU(0x0002)) != 0) {
    retval += 1;
  }
  return retval - 1;
}


/* arm64 server state                                                         */
/*----------------------------------------------------------------------------*/

/* Neoverse V2 PMUv3 event numbers. See tools/perf/pmu-events/arch/arm64/   */
/* arm/neoverse-n2-v2/ and the Neoverse V2 TRM.                             */
#define ARM_INST_RETIRED	0x08
#define ARM_CPU_CYCLES		0x11
#define ARM_L2D_CACHE_REFILL	0x17
#define ARM_LL_CACHE_MISS_RD	0x37	/* Grace: SCF (system level cache) read misses */

/* Module parameter: PMU event used for "LLC misses". 0x37 needs firmware to */
/* set CPUECTLR_EL1.EXTLLC; if it reads as all zeros use 0x17 instead.       */
static long int llc_event = ARM_LL_CACHE_MISS_RD;
module_param(llc_event, long, S_IRUSR);
MODULE_PARM_DESC(llc_event, "arm64 PMU event number counted as LLC misses (0x37)");

/* Shift applied to CNTVCT_EL0 so the trace time base is <= 64 MHz */
/* Grace CNTFRQ is 1 GHz, so shift 4 gives 62.5 MHz (16 ns)       */
/* The user-mode kutrace_lib.cc computes exactly the same shift    */
static u32 ku_cntvct_shift;
static u64 ku_cntfrq_mhz;

/* True if this CPU has the Activity Monitors with core+const counters on */
static bool ku_have_amu;

/* Per-CPU module-private state, kept out of include/linux/kutrace.h */
struct ku_arm_pcpu {
	struct perf_event *inst_ev;	/* INST_RETIRED */
	struct perf_event *cyc_ev;	/* CPU_CYCLES */
	struct perf_event *llc_ev;	/* llc_event */
	u64 prior_cpu_cycles;		/* real core cycles, for IPC */
	u64 prior_amu_core;		/* AMU frequency sampling */
	u64 prior_amu_const;
};
static DEFINE_PER_CPU(struct ku_arm_pcpu, ku_arm_pcpu);

/* Read the PMU counter that perf assigned to this event on this CPU.       */
/* perf owns the counter (no clash with the NMI watchdog or perf users) and */
/* it is 64-bit (attr.config1 "long"), but we read it with a single mrs.    */
/* hw.idx is re-read each time because perf may reschedule pinned events.  */
static inline u64 ku_read_pmu(struct perf_event *ev)
{
	int idx;

	if (unlikely(ev == NULL))
		return 0;
	idx = READ_ONCE(ev->hw.idx);
	if (idx == ARMV8_PMU_CYCLE_IDX)
		return read_pmccntr();
	if (idx == ARMV8_PMU_INSTR_IDX)
		return read_pmicntr();
	if ((idx >= 0) && (idx < ARMV8_PMU_CYCLE_IDX))
		return read_pmevcntrn(idx);
	return 0;	/* event not currently scheduled on a counter */
}

static struct perf_event *ku_make_counter(int cpu, u64 event_num)
{
	struct perf_event *ev;
	struct perf_event_attr attr = {
		.type		= PERF_TYPE_RAW,
		.size		= sizeof(struct perf_event_attr),
		.config		= event_num,
		.config1	= 1,	/* "long": 64-bit counter, no overflow reprogramming */
		.pinned		= 1,
		.disabled	= 0,
		/* Count EL0 and kernel. On a VHE host (Grace) the kernel runs at */
		/* EL2; perf sets PMEVTYPER.NSH for us when exclude_kernel == 0   */
		.exclude_user	= 0,
		.exclude_kernel	= 0,
		.exclude_hv	= 0,
	};

	ev = perf_event_create_kernel_counter(&attr, cpu, NULL, NULL, NULL);
	if (IS_ERR(ev)) {
		printk(KERN_INFO "  kutrace_mod cpu %d: perf event 0x%llx failed %ld\n",
		       cpu, event_num, PTR_ERR(ev));
		return NULL;
	}
	return ev;
}

static void ku_release_counter(struct perf_event **evp)
{
	if (*evp) {
		perf_event_release_kernel(*evp);
		*evp = NULL;
	}
}

/* Process context only (kutrace_control reset, module init/exit). May sleep. */
static void ku_release_pmu(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		struct ku_arm_pcpu *p = per_cpu_ptr(&ku_arm_pcpu, cpu);

		ku_release_counter(&p->inst_ev);
		ku_release_counter(&p->cyc_ev);
		ku_release_counter(&p->llc_ev);
	}
}

/* Process context only. Returns false if any counter could not be had */
static bool ku_reserve_pmu(bool want_ipc, bool want_llc)
{
	int cpu;
	bool ok = true;

	ku_release_pmu();
	for_each_online_cpu(cpu) {
		struct ku_arm_pcpu *p = per_cpu_ptr(&ku_arm_pcpu, cpu);

		if (want_ipc) {
			p->inst_ev = ku_make_counter(cpu, ARM_INST_RETIRED);
			p->cyc_ev  = ku_make_counter(cpu, ARM_CPU_CYCLES);
			ok &= (p->inst_ev != NULL) && (p->cyc_ev != NULL);
		}
		if (want_llc) {
			p->llc_ev = ku_make_counter(cpu, (u64)llc_event);
			ok &= (p->llc_ev != NULL);
		}
		p->prior_cpu_cycles = 0;
	}
	return ok;
}

static void ku_check_amu_one(void *info)
{
	/* Bit 0: core cycles, bit 1: constant cycles. Firmware/kernel must enable */
	u64 en = read_sysreg_s(SYS_AMCNTENSET0_EL0);
	if ((en & 3) != 3)
		ku_have_amu = false;
}

static void ku_setup_arm64(void)
{
	u64 cntfrq = read_sysreg(cntfrq_el0);

	ku_cntfrq_mhz = cntfrq / 1000000;
	ku_cntvct_shift = 0;
	while ((cntfrq >> ku_cntvct_shift) > 64000000)
		++ku_cntvct_shift;
	printk(KERN_INFO "  kutrace_mod CNTFRQ %llu Hz, time base shift %u\n",
	       cntfrq, ku_cntvct_shift);

	/* Only touch AMU registers if the CPU feature was detected, else UNDEF */
	preempt_disable();	/* this_cpu_has_cap() warns if preemptible */
	ku_have_amu = this_cpu_has_cap(ARM64_HAS_AMU_EXTN);
	preempt_enable();
	if (ku_have_amu)
		on_each_cpu(ku_check_amu_one, NULL, 1);
	printk(KERN_INFO "  kutrace_mod AMU frequency sampling %s\n",
	       ku_have_amu ? "on" : "off (using cpufreq policy->cur)");
}



/* Read a time counter */
/* This is performance critical -- every trace entry  */
/* Ideally, this counts at a constant rate of 16-32 nsec per count.           */
/*----------------------------------------------------------------------------*/
static inline u64 ku_get_timecount(void)
{
	u64 timer_value;
	/* No isb: a few ns of speculation slop is fine here */
	asm volatile("mrs %x0, cntvct_el0" : "=r"(timer_value));
	timer_value >>= ku_cntvct_shift;	/* 1 GHz >> 4 = 62.5 MHz on Grace */

	return timer_value;
}


/* Read instructions retired counter */
/* This is performance critical -- every trace entry if tracking IPC */
/*----------------------------------------------------------------------------*/
static inline u64 ku_get_inst_retired(void)
{
	return ku_read_pmu(this_cpu_read(ku_arm_pcpu.inst_ev));
}

/* Read LLC misses counter */
/* This is performance critical -- every trace entry if tracking LLC */
/*----------------------------------------------------------------------------*/
static inline u64 ku_get_llc_miss(void)
{
	return ku_read_pmu(this_cpu_read(ku_arm_pcpu.llc_ev));
}

/* Read current CPU frequency */
/* Not performance critical -- once every timer interrupt                     */
/*----------------------------------------------------------------------------*/
static inline u64 ku_get_cpu_freq(void) {
	/* Average frequency since the previous timer-interrupt sample, from   */
	/* the AMU: core cycles / constant cycles * CNTFRQ. Both counters stop */
	/* in WFI, so this is the frequency while running, not diluted by idle.*/
	/* Called from the timer IRQ, so preemption is already off.            */
	struct ku_arm_pcpu *p = this_cpu_ptr(&ku_arm_pcpu);
	u64 core, cnst, d_core, d_const, freq = 0;

	if (!ku_have_amu) {
		struct cpufreq_policy *policy = cpufreq_cpu_get_raw(smp_processor_id());
		return policy ? policy->cur / 1000 : 0;	/* kHz to MHz */
	}
	core = read_sysreg_s(SYS_AMEVCNTR0_CORE_EL0);
	cnst = read_sysreg_s(SYS_AMEVCNTR0_CONST_EL0);
	d_core = core - p->prior_amu_core;
	d_const = cnst - p->prior_amu_const;
	/* Need >= ~10 usec of running time for a stable ratio */
	if ((p->prior_amu_const != 0) && (d_const >= 10 * ku_cntfrq_mhz))
		freq = div64_u64(d_core * ku_cntfrq_mhz, d_const);
	p->prior_amu_core = core;
	p->prior_amu_const = cnst;
	return freq;
}

/* Return true for large time advance that should be treated as small backward time */
static inline bool LateStoreOrLarge(u64 delta_cycles) {
  return delta_cycles > kLateStoreThresh;
}

/* Make sure name length fits in 1..8 u64's */
//* Return true if out of range */
static inline bool is_bad_len(int len)
{
	return (len < 1) | (len > 8);
}

/* Make sure name length fits in 1 + 1..8 u64's */
/* Return true if out of range */
static inline bool is_bad_len_plus(int len)
{
	return (len < 1) | (len > 9);
}

/* Turn off tracing. (We cannot wait here) */
/* Return tracing bit */
static u64 do_trace_off(void)
{
	kutrace_tracing = false;
	return kutrace_tracing;
}

/* Turn on tracing. We can only get here if all is set up */
/* Trace buffer must be allocated and initialized */
/* Return tracing bit */
static u64 do_trace_on(void)
{
	kutrace_tracing = true;
	return kutrace_tracing;
}

/* Flush all partially-filled trace blocks, filling them up */
/* Tracing must be off */
/* Return number of words zeroed */
static u64 do_flush(void)
{
	u64 *p;
	int cpu;
	int zeroed = 0;

	kutrace_tracing = false;	/* Should already be off */
	for_each_online_cpu(cpu)
	{
		struct kutrace_traceblock *tb =
			&per_cpu(kutrace_traceblock_per_cpu, cpu);
		u64 *next_item = (u64 *)ATOMIC_READ(&tb->next);
		u64 *limit_item = tb->limit;

		if (next_item == NULL)
			continue;
		if (limit_item == NULL)
			continue;
		for (p = next_item; p < limit_item; ++p)
		{
			*p = 0;
			++zeroed;
		}

		ATOMIC_SET(&tb->next, (uintptr_t)limit_item);
	}
	return zeroed;
}


/* Return number of filled trace blocks */
/* Next can overshoot limit when we are full */
/* Tracing will usually be on */
/* NOTE: difference of two u64* values is 1/8 of what you might be thinking */
static u64 do_stat(void)
{
	if (did_wrap_around || (traceblock_next < traceblock_limit))
		return (u64)(traceblock_high -
				traceblock_limit) >> KUTRACEBLOCKSHIFTU64;
	else
		return (u64)(traceblock_high -
				traceblock_next) >> KUTRACEBLOCKSHIFTU64;
}

/* Return number of filled trace words */
/* Tracing must be off and flush must have been called */
/* NOTE: difference of two u64* values is 1/8 of what you might be thinking */
static u64 get_count(void)
{
	u64 retval;

	kutrace_tracing = false;
	if (did_wrap_around || (traceblock_next < traceblock_limit))
		retval = (u64)(traceblock_high - traceblock_limit);
	else
		retval = (u64)(traceblock_high - traceblock_next);

	return retval;
}

/* Read and return one u64 word of trace data, working down from top.
 * This is called 1M times to dump 1M trace words (8MB), but it is called
 * by a user program that is writing all this to disk, thus is constrained
 * by disk I/O speed. So we don't care that this is somewhat inefficient
 *
 *  traceblock_limit          traceblock_next                traceblock_high
 *  |                               |                                |
 *  v                               v                                v
 *  +-------+-------+------+--------+-------+-------+-------+-------+
 *  | / / / / / / / / / / / / / / / |   3       2       1       0   |
 *  +-------+-------+------+--------+-------+-------+-------+-------+
 *                                  <==== allocated blocks grow down
 */


/* Read and return one u64 word of trace data, working down from top.
 * This is called 1M times to dump 1M trace words (8MB), but it is called
 * by a user program that is writing all this to disk, so is constrained
 * by disk I/O speed. So we don't care that this is somewhat inefficient
 */
/* Tracing must be off and flush must have been called */
static u64 get_word(u64 subscr)
{
	u64 blocknum, u64_within_block;
	u64 *blockp;

	kutrace_tracing = false;	/* Should already be off */
	if (subscr >= get_count()) return 0;
	blocknum = subscr >> KUTRACEBLOCKSHIFTU64;
	u64_within_block = subscr & ((1 << KUTRACEBLOCKSHIFTU64) - 1);
	blockp = traceblock_high - ((blocknum + 1) << KUTRACEBLOCKSHIFTU64);
/* printk(KERN_INFO "get_word[%lld] %016llx\n", subscr, blockp[u64_within_block]); */
	return blockp[u64_within_block];
}

/* Read and return one u64 word of IPC data, working down from top.
 *
 * Trace memory layout with IPC tracing. IPC bytes go into lower 1/8.
 *  tracebase
 *  |    traceblock_limit     traceblock_next                traceblock_high
 *  |       |                       |                                |
 *  v       v                       v                                v
 *  +-------+-------+------+--------+-------+-------+-------+-------+
 *  |////|  | / / / / / / / / / / / |                               |
 *  +-------+-------+------+--------+-------+-------+-------+-------+
 *       <==                        <==== allocated blocks grow down
 *       IPC bytes
 */

/* Tracing must be off and flush must have been called */
/* We map linear IPCword numbers 0..get_count-1 to IPC block and offset, */
/* with blocks growing downward. If mains trace blocks are 64KB, */
/* IPC blocks are 8KB */
/* Even though they are byte entries, we read them out as u64's */
static u64 get_ipc_word(u64 subscr)
{
	u64 blocknum, u64_within_block;
	u64 *blockp;

	kutrace_tracing = false;
	/* IPC word count is 1/8 of main trace count */
	if (subscr >= (get_count() >> 3))
		return 0;
	blocknum = subscr >> KUIPCBLOCKSHIFTU8;
	u64_within_block = subscr & ((1 << KUIPCBLOCKSHIFTU8) - 1);
	/* IPC blocks count down from traceblock_limit */
	blockp = traceblock_limit - ((blocknum + 1) << KUIPCBLOCKSHIFTU8);
	return blockp[u64_within_block];
}

/*
 * Fast 4KB trace buffer extraction: Copies 4KB at once to user space.
 * Because the syscall that gets here supplies only one argument, we use it as
 * the user-space target buffer address. For the kernel-space buffer offset we
 * use get4kb_subscr. 
 *
 * Caller must do KUTRACE_CMD_SET4KB to initialize this
 * and then must do KUTRACE_CMD_GET4KB and optionally KUTRACE_CMD_GETIPC4KB
 * for every block of 4KB/sizeof(traceword) = 512 words.
 * 
 * 4KB extraction is measured to be about 165x faster than 8B extraction per 
 * 64KB traceblock. Including buffered writes toward disk/SSD, this achieves  
 * about 1400MB/s vs 25MB/s overall on an Intel i3 at 3.9 GHz, so about 55  
 * times faster, i.e. 55x less CPU time during extraction.
 *
 * Calls to the 4KB commands when run against an older module will return ~0.
 * It is up to the caller to detect this and use the word-at-a-time routines.
 *
 */

/* Read and return one 4KB block of trace data, working down from top,
 * then increment get4kb_subscr by 4KB/sizeof(traceword) = 512.
 * This is called 1M/512 = 2K times to dump 1M trace words (8MB).
 * Returns 0 for success, ~0 for unimplemented, and 1..4096 for partial copy.
 * Tracing must be off and flush must have been called 
 */
static u64 get_4kb(u64 arg)
{
	u64 blocknum, u64_within_block;
	u64 *blockp;
	void __user *to_user_ptr;
	const void *from_kernel_ptr;

	if (get4kb_subscr >= get_count())
		return 4096;

	blocknum = get4kb_subscr >> KUTRACEBLOCKSHIFTU64;
	u64_within_block = get4kb_subscr & ((1 << KUTRACEBLOCKSHIFTU64) - 1);
	blockp = traceblock_high - ((blocknum + 1) << KUTRACEBLOCKSHIFTU64);
/* printk(KERN_INFO "get_4kb[%lld] %016llx\n", get4kb_subscr, blockp[u64_within_block]); */
	to_user_ptr = (void __user *)arg;
	from_kernel_ptr = (const void *)(&blockp[u64_within_block]);
	return copy_to_user(to_user_ptr, from_kernel_ptr, 4096);
}

/* Read and return one 4KB block of IPC data, working down from top. 
 * This is called 1M/512 = 2K times to dump 1M IPC words (8MB).
 * Returns 0 for success, ~0 for unimplemented, and 1..4096 for partial copy.
 * Tracing must be off and flush must have been called
 */
static u64 get_ipc_4kb(u64 arg)
{
	u64 blocknum, u64_within_block;
	u64 *blockp;
	void __user *to_user_ptr;
	const void *from_kernel_ptr;

	/* IPC word count is 1/8 of main trace count */
	if (get4kb_subscr >= (get_count() >> 3))
		return 4096;

	blocknum = get4kb_subscr >> KUIPCBLOCKSHIFTU8;
	u64_within_block = get4kb_subscr & ((1 << KUIPCBLOCKSHIFTU8) - 1);
	/* IPC blocks count down from traceblock_limit */
	blockp = traceblock_limit - ((blocknum + 1) << KUIPCBLOCKSHIFTU8);
	to_user_ptr = (void __user *)arg;
	from_kernel_ptr = (const void *)(&blockp[u64_within_block]);
	return copy_to_user(to_user_ptr, from_kernel_ptr, 4096);
}



/* We are called with preempt disabled */
/* We are called with interrupts disabled */
/* We are called holding the lock that guards traceblock_next */
/* Cannot do printf or anything else here that could block */
static u64 *initialize_trace_block(u64 *init_me, bool very_first_block,
	struct kutrace_traceblock *tb)
{
	u64 *myclaim = NULL;
	u64 cpu = smp_processor_id();

	/* For every traceblock, insert current process ID and name. This */
	/* gives the proper context when wraparound is enabled */
	struct task_struct *curr = current;

	/* First word is the time counter with CPU# placed in top byte */
	u64 block_init_counter = ku_get_timecount();
	init_me[0] = (block_init_counter & FULL_TIMESTAMP_MASK) |
		(cpu << CPU_NUMBER_SHIFT);

	/* Second word is going to be corresponding gettimeofday(), */
	/* filled in via postprocessing */
	/* We put some flags in the top byte, though. 0x80 = do_ipc bit, etc. */
	/* NOTE: This could all be pre-calculated in do_reset() */
	init_me[1] = 0;
	if (do_ipc)
		init_me[1] |= (IPC_Flag << FLAGS_SHIFT);
	if (do_llc)
		init_me[1] |= (LLC_Flag << FLAGS_SHIFT);
	if (do_wrap)
		init_me[1] |= (WRAP_Flag << FLAGS_SHIFT);
	/* We don't know if we actually wrapped until the end. */
	/* See KUTRACE_CMD_GETCOUNT */

	/* For very first trace block, also insert six NOPs at [2..7]. */
	/* The dump to disk code will overwrite the first pair with */
	/* start timepair and the next with stop timepair. [6..7] currently unused */
	if (very_first_block) {
		init_me[2] = CLU(0);
		init_me[3] = CLU(0);
		init_me[4] = CLU(0);
		init_me[5] = CLU(0);
		init_me[6] = CLU(0);
		init_me[7] = CLU(0);
		myclaim = &init_me[8];
	} else {
		myclaim = &init_me[2];
	}

	/* Every block has PID and pidname at the front */
	/* This requires a change for V3 in postprocessing */
	/* I feel like I should burn one more word here to make 4, */
	/* so entire front is 12/6 entries instead of 11/5... */
	myclaim[0] = curr->pid;
	myclaim[1] = 0;
	memcpy(&myclaim[2], curr->comm, MAX_PIDNAME_LENGTH);
	myclaim += 4;

	/* Next len words are the claimed space for an entry */

	/* Last 8 words of a block set to NOPs (0) */
	init_me[KUTRACEBLOCKSIZEU64 - 8] = 0;
	init_me[KUTRACEBLOCKSIZEU64 - 7] = 0;
	init_me[KUTRACEBLOCKSIZEU64 - 6] = 0;
	init_me[KUTRACEBLOCKSIZEU64 - 5] = 0;
	init_me[KUTRACEBLOCKSIZEU64 - 4] = 0;
	init_me[KUTRACEBLOCKSIZEU64 - 3] = 0;
	init_me[KUTRACEBLOCKSIZEU64 - 2] = 0;
	init_me[KUTRACEBLOCKSIZEU64 - 1] = 0;

	/* Very first traceblock for this CPU: record its cpufreq MHz in the */
	/* high half of myclaim[-4]; rawtoevent turns it into a -freq- event */
	if (tb->prior_cycles == 0) {
		struct cpufreq_policy *policy = cpufreq_cpu_get_raw(cpu);

		tb->prior_cycles = 1;	/* mark it as initialized */
		if (policy) {
			u64 cpu_freq_mhz = policy->cur / 1000;	/* kHz to MHz */
			myclaim[-4] |= (cpu_freq_mhz << 32);
		}
	}

	return myclaim;
}

/* We are called with preempt disabled */
/* We are called with interrupts disabled */
/* We are called holding the lock that guards traceblock_next */
static u64 *really_get_slow_claim(int len, struct kutrace_traceblock *tb)
{
	u64 *myclaim = NULL;
	bool very_first_block = (traceblock_next == traceblock_high);

	/* Allocate a new traceblock. Allocations grow downward. */
	traceblock_next -= KUTRACEBLOCKSIZEU64;

	if (traceblock_next < traceblock_limit) {
		if (do_wrap) {
			/* Wrap to traceblock[1], not [0] */
			did_wrap_around = true;
			traceblock_next = traceblock_high -
				2 * KUTRACEBLOCKSIZEU64;
			/* Clear pid filter. */
			/* It is unfortunate to do this while holding a */
			/* lock and also holding off interrupts... */
			memset(kutrace_pid_filter, 0, 1024 * sizeof(u64));
		} else {
			/* All full. Stop and get out. */
			kutrace_tracing = false;
			return myclaim;
		}
	}

	/* Need to do this before setting next/limit if same CPU could get */
	/* an interrupt and use uninitilized block */
	/* It is unfortunate to do this while holding a lock and also */
	/* holding off interrupts... */
	/* Most of the cost is two cache misses, so maybe 200 nsec */
	myclaim = initialize_trace_block(traceblock_next, very_first_block, tb);

	/* Set up the next traceblock pointers, reserving */
	/* first N + len words */
	ATOMIC_SET(&tb->next, (uintptr_t)(myclaim + len));
	tb->limit = traceblock_next + KUTRACEBLOCKSIZEU64;
	return myclaim;
}

/* Reserve space for one entry of 1..9 u64 words */
/* If trace buffer is full, return NULL or wrap around */
/* We allow this to be used with tracing off so we can initialize a trace file */
/* In that case, tb->next and tb->limit are NULL */
/* We are called with preempt disabled */
static u64 *get_slow_claim(int len, struct kutrace_traceblock *tb)
{
	unsigned long flags;
	u64 *limit_item;
	u64 *myclaim = NULL;

	if (unlikely(is_bad_len(len))) {
		kutrace_tracing = false;
printk(KERN_INFO "is_bad_len 1\n");
		return NULL;
	}

	/* This gets the lock that protects traceblock_next and */
	/* disables interrupts */
	raw_spin_lock_irqsave(&kutrace_lock, flags);
	/* Nothing else can be touching tb->limit now */
	limit_item = tb->limit;
	/* add_return returns the updated pointer; we want the prior */
	/* so subtract len */
	myclaim = ((u64 *)ATOMIC_ADD_RETURN(len * sizeof(u64), &tb->next)) -
			 len;
	/* FIXED BUG: myclaim + len */
	if (((myclaim + len) >= limit_item) || (limit_item == NULL)) {
		/* Normal case: */
		/* the claim we got still doesn't fit in its block */
		myclaim = really_get_slow_claim(len, tb);
	}
	/* Rare: If some interrupt already allocated a new traceblock, */
	/* fallthru to here */
	/* Free lock; re-enable interrupts if they were enabled on entry */
	raw_spin_unlock_irqrestore(&kutrace_lock, flags);

	return myclaim;
}


/* Reserve space for one entry of 1..9 u64 words, normally lockless */
/* If trace buffer is full, return NULL. Caller MUST check */
/* We allow this to be used with tracing off so we can initialize a trace file */
/* We are called with preempt disabled */
static u64 *get_claim(int len, struct kutrace_traceblock* tb)
{
	u64 *limit_item = NULL;
	u64 *limit_item_again = NULL;
	u64 *myclaim = NULL;

	if (unlikely(is_bad_len_plus(len))) {
		kutrace_tracing = false;
		return NULL;
	}

	/* Fast path */
	/* We may get interrupted at any point here and the interrupt routine
	 * may create a trace entry, and it may even allocate a new
	 * traceblock.
	 * This code must carefully either reserve an exclusive area to use or
	 * must call the slow path.
	 */

	/* Note that next and limit may both be NULL at initial use. */
	/* If they are, take the slow path without accessing. */
	do {
		limit_item = tb->limit;
		if (unlikely(limit_item == NULL))
			break;

		/* add_return returns the updated pointer; we want the */
		/* prior so subtract len */
		myclaim = 
		((u64 *)ATOMIC_ADD_RETURN(len * sizeof(u64), &tb->next)) - len;
		limit_item_again = tb->limit;

		if (limit_item == limit_item_again)
			break;	/* All is good */
		/* An interrupt occurred *and* changed blocks */
		if ((myclaim < limit_item_again) &&
			((limit_item_again - KUTRACEBLOCKSIZEU64) <= myclaim))
			/* Claim is in new block -- use it */
			break;
		/* Else claim is at end of old block -- abandon it, and try again */
	} while (true);

	/* Make sure the entire allocation fits */
	if (unlikely((myclaim + len) >= limit_item_again)) {
	    /* Either this is the first claim for a CPU */
	    /*   with limit_item, limit_item_again, and myclaim all null, or */
		/* the claim we got doesn't fit in its block. Allocate a new block. */
		myclaim = get_slow_claim(len, tb);
	}
	return myclaim;
}


/*
 * In recording a trace event, it is possible for an interrupt to happen after 
 * KUtrace code takes the event timestamp and before it claims the storage location.
 * In this case, the interupt handling will recursively record several events 
 * before returning to the original KUtrace path, which then claims a location
 * and stores the original event with its earlier timestamp. This is called a
 * "late store." When that happens, the reconstruciton in rawtoevent needs to
 * decide whether time went forward by almost the entire 20-bit wraparound
 * period, or went backward by some amount.
 * 
 * To resolve this ambiguity, we declare that a time gap of 7/8 of the wraparound
 * period is forward time and the high 1/8 is backward time associated with an
 * otherwise undetectable backward time.
 * 
 * To mark forward time in that 1/8 (and above), we add a TSDELTA entry to the
 * trace. The exact compare for late store must be identical in kutrace_mod.c 
 * and in rawtoevent.cc.
 * 
 */

/* Get a claim. If delta_cycles is large, claim one more word and insert TSDELTA entry */
/* NOTE: tsdelta is bogus for very first entry per CPU. */
/*       First per CPU is indicated by tb->prior_cycles == 0 */
/* We are called with preempt disabled */
static inline u64* get_claim_with_tsdelta(u64 now, u64 delta_cycles,  
                                   int len, struct kutrace_traceblock* tb) {
	u64 *claim;
	/* Check if time between events almost wraps above the 20-bit timestamp */
	if (unlikely(LateStoreOrLarge(delta_cycles) && (tb->prior_cycles != 0))) {
		/* Uncommon case. Add timestamp delta entry before original entry */
		claim = get_claim(1 + len, tb);
		if (claim != NULL) {
			claim[0] = (now << TIMESTAMP_SHIFT) | 
			           ((u64)KUTRACE_TSDELTA << EVENT_SHIFT) | 
                                   (delta_cycles & ARG_MASK);
			++claim;		/* Start of space for original entry */
		}
	} else {
		/* Common case */
		claim = get_claim(len, tb);	/* Start of space for original entry */
	}
	return claim;
}

/* Return prior trace word for this CPU or NULL */
/* We are called with preempt disabled */
inline static u64 *get_prior(struct kutrace_traceblock *tb)
{	
	u64 *next_item;
	u64 *limit_item;

	/* Note that next and limit may both be NULL at initial use. */
	/* If they are, or any other problem, return NULL */
	/* get_cpu_var disables preempt */
////	tb = &get_cpu_var(kutrace_traceblock_per_cpu);
	next_item = (u64 *)ATOMIC_READ(&tb->next);
	limit_item = tb->limit;
////	put_cpu_var(kutrace_traceblock_per_cpu);

	if (next_item < limit_item)
		return next_item - 1;	/* ptr to prior entry */
	return NULL;
}

/* Calculate and insert 4-bit IPC/LLC value. Shift packs in hi part of a byte */
/* If either IPC or LLC is on, store its quantized 4-bit value */
/* If both are on keep just high two bits of each. HTML wrapper displays both */
/* Prioritize do_ipc */
static inline void do_ipcllc_calc(u64 *claim, u64 delta_cycles, 
                        struct kutrace_traceblock* tb, bool shift) {
        u64 inst_ret, delta_inst, ipc;
	u64 llc_miss, delta_miss, llc;
	u64 four_bits;	/* To store into trace: ipc, llc, or two bits of each */
	u8* ipcllc_byte_addr;
	
	/* The incoming delta_cycles is in time-base units (CNTVCT >> shift), */
	/* not CPU cycles, and Grace changes frequency. Use real CPU_CYCLES,  */
	/* in units of cycles/64 as get_granular_ipc() expects.               */
	if (do_ipc) {
		struct ku_arm_pcpu *p = this_cpu_ptr(&ku_arm_pcpu);
		u64 cyc = ku_read_pmu(p->cyc_ev);
		delta_cycles = (cyc - p->prior_cpu_cycles) >> 6;
		p->prior_cpu_cycles = cyc;
	}

	/* There will be random large differences the first time; we don't care. */
	if (do_ipc_only) {
		inst_ret = ku_get_inst_retired();
		delta_inst = inst_ret - tb->prior_inst_retired;
		tb->prior_inst_retired = inst_ret;
		four_bits = get_granular_ipc(delta_inst, delta_cycles);
	}
	else if (do_neither) {
		return;
	}
	else if (do_llc) {
		llc_miss = ku_get_llc_miss();
		delta_miss = llc_miss - tb-> prior_llc_misses;
		tb->prior_llc_misses = llc_miss;
		four_bits = llc = get_granular_llc(delta_miss);
		if (do_both) {
			inst_ret = ku_get_inst_retired();
			delta_inst = inst_ret - tb->prior_inst_retired;
			tb->prior_inst_retired = inst_ret;
			ipc = get_granular_ipc(delta_inst, delta_cycles);
			/* Pack upper two bits only of each counter */
			four_bits = (ipc & 0x0c) | kLlcSmall[llc];
		}
	}

	/* NOTE: pointer arithmetic divides claim by 8, giving the byte offset */
	ipcllc_byte_addr = (u8*)(tracebase) + (claim - (u64*)(tracebase));
	/* Shift saves the value for optimized returns in high 4 bits of byte */
	if (shift)
		ipcllc_byte_addr[0] |= four_bits << 4;
	else
		ipcllc_byte_addr[0] = four_bits;
/* if(++hack_count < 20)  printk(KERN_INFO "  byte %u\n", ipcllc_byte_addr[0]); */
}


/*
 *  arg1: (arrives with timestamp = 0x00000)
 *  +-------------------+-----------+---------------+-------+-------+
 *  | timestamp         | event     | delta | retval|      arg0     |
 *  +-------------------+-----------+---------------+-------+-------+
 *           20              12         8       8           16
 */

/* Insert one u64 trace entry, for current CPU */
/* Tracing may be otherwise off    */
/* Return number of words inserted */
static u64 insert_1(u64 arg1)
{
	u64 *claim;
	struct kutrace_traceblock* tb;
	u64 delta_cycles;
	u64 retval = 0;
	u64 now = ku_get_timecount();

	tb = &get_cpu_var(kutrace_traceblock_per_cpu);	/* hold off preempt */
	delta_cycles = now - tb->prior_cycles;	
	/* Allocate one word */
	claim = get_claim_with_tsdelta(now, delta_cycles, 1, tb);
	/* This update must be after the first getclaim per CPU */
	tb->prior_cycles = now;
	if (likely(claim != NULL)) {
		claim[0] = arg1 | (now << TIMESTAMP_SHIFT);
		/* IPC/LLC option. Changes CPU overhead from ~1/4% to ~3/4% */
		do_ipcllc_calc(claim, delta_cycles, tb, false);
		retval = 1;
	}
	put_cpu_var(kutrace_traceblock_per_cpu);	/* release preempt */
	return retval;
}

/* Insert one u64 Return trace entry with small retval, for current CPU */
/* Optimize by combining with just-previous entry if the matching call */
/* and delta_t fits. The optimization is likely, so we don't worry about */
/* the overhead if we can't optimize */
/* Tracing may be otherwise off    */
/* Return number of words inserted */
static u64 insert_1_retopt(u64 arg1)
{
	struct kutrace_traceblock* tb;
	u64 *prior_entry;
	u64 now = ku_get_timecount();
	
	/* No need to hold off preempt here, but get_cpu/put_cpu do anyway */
	/* It doesn't matter if we get migrated because we are not allocating a new entry */
	tb = &get_cpu_var(kutrace_traceblock_per_cpu);	/* hold off preempt */
	prior_entry = get_prior(tb);
	if (likely(prior_entry != NULL)) {
		/* Want N=matching call, high bytes of return value = 0 */
		u64 diff = (*prior_entry ^ arg1) & EVENT_DELTA_RETVAL_MASK;
		u64 prior_t = *prior_entry >> TIMESTAMP_SHIFT;
		u64 delta_t = (now - prior_t) & UNSHIFTED_TIMESTAMP_MASK;
		/* EVENT_RETURN_BIT distinguishes call from return */
		if ((diff == EVENT_RETURN_BIT) && (delta_t <= MAX_DELTA_VALUE))
		{
			/* Successful optimization tests. Combine ret with call. */
			/* This happens about 90-95% of the time */
			u64 opt_ret;
			/* make sure delta_t is nonzero to flag there is an optimized ret */
			if (unlikely(delta_t == 0))
				delta_t = 1;
			opt_ret = (delta_t << DELTA_SHIFT) |
				((arg1 & UNSHIFTED_RETVAL_MASK) << RETVAL_SHIFT);
			*prior_entry |= opt_ret;
			
			/* IPC/LLC option. Changes CPU overhead from ~1/4% to ~3/4% */
			do_ipcllc_calc(prior_entry, delta_t, tb, true);		
			put_cpu_var(kutrace_traceblock_per_cpu);	/* release preempt */
			return 0;
		}
	} 
	put_cpu_var(kutrace_traceblock_per_cpu);	/* release preempt */

	/* Otherwise, fall into normal insert_1 */
	return insert_1(arg1);
}


/* Insert a two-word u64 trace entry, for current CPU */
/* The entry is exactly a PC_TEMP sample */
/* Tracing may be otherwise off    */
/* Return number of words inserted */
static u64 insert_2(u64 arg1, u64 arg2)
{
	u64 *claim;
	struct kutrace_traceblock* tb;
	u64 delta_cycles;
	u64 now = ku_get_timecount();
	
	tb = &get_cpu_var(kutrace_traceblock_per_cpu);	/* hold off preempt */
	delta_cycles = now - tb->prior_cycles;
	/* Allocate two words */
	claim = get_claim_with_tsdelta(now, delta_cycles, 2, tb);
	/* This update must be after the first getclaim per CPU */
	tb->prior_cycles = now;
	put_cpu_var(kutrace_traceblock_per_cpu);	/* release preempt */

	if (claim != NULL)
	{
		claim[0] = arg1 | (now << TIMESTAMP_SHIFT);
		claim[1] = arg2;
		return 2;
	}
	return 0;
}

/* For event codes 010..1FF, length is middle hex digit. All others 1 */
static u64 entry_len(u64 word)
{
	u64 n = (word >> EVENT_SHIFT) & UNSHIFTED_EVENT_MASK;

	if (n > MAX_EVENT_WITH_LENGTH)
		return 1;
	if (n < MIN_EVENT_WITH_LENGTH)
		return 1;
	return (n >> EVENT_LENGTH_FIELD_SHIFT) & EVENT_LENGTH_FIELD_MASK;
}


/* Insert one trace entry of 1..8 u64 words, for current CPU */
/* word is actually a const u64* pointer to kernel space array of */
/* exactly len u64 */
/* Tracing may be otherwise off */
/* Return number of words inserted */
static u64 insert_n_krnl(u64 word)
{
	const u64 *krnlptr = (const u64 *)word;
	u64 len = entry_len(krnlptr[0]);	/* length in u64, 1..8 */
	u64 *claim;
	struct kutrace_traceblock* tb;
	u64 delta_cycles;
	u64 now = ku_get_timecount();

	tb = &get_cpu_var(kutrace_traceblock_per_cpu);	/* hold off preempt */
	delta_cycles = now - tb->prior_cycles;
	/* Allocate N words */
	claim = get_claim_with_tsdelta(now, delta_cycles, len, tb);
	/* This update must be after the first getclaim per CPU */
	tb->prior_cycles = now;
	put_cpu_var(kutrace_traceblock_per_cpu);	/* release preempt */

	if (claim != NULL) {
		claim[0] = krnlptr[0] | (now << TIMESTAMP_SHIFT);
		memcpy(&claim[1], &krnlptr[1], (len - 1) * sizeof(u64));
		return len;
	}
	return 0;
}

/* Insert one trace entry of 1..8 u64 words, for current CPU */
/* word is actually a const u64* pointer to user space array of */
/* exactly eight u64 */
/* NOTE: Always copies eight words, even if actual length is smaller */
/* Tracing may be otherwise off */
/* Return number of words inserted */
static u64 insert_n_user(u64 word)
{
	const uintptr_t tempword = word;	/* 32- or 64-bit pointer */
	const u64 *userptr = (const u64 *)tempword;
	u64 len;
	u64 *claim;
	struct kutrace_traceblock* tb;
	u64 delta_cycles;
	u64 now;
	u64 uncopied_bytes;
	u64 temp[8];

	/* This call may sleep or otherwise context switch */
	/* It may fail if passed a bad user-space pointer. Don't do that. */
	temp[0] = 0;
	uncopied_bytes = raw_copy_from_user(temp, userptr, 8 * sizeof(u64));
	if (uncopied_bytes > 0)
		return 0;

	len = entry_len(temp[0]);	/* length in u64, 1..8 */
	now = ku_get_timecount();
	
	tb = &get_cpu_var(kutrace_traceblock_per_cpu);	/* hold off preempt */
	delta_cycles = now - tb->prior_cycles;
	/* Allocate N words */
	claim = get_claim_with_tsdelta(now, delta_cycles, len, tb);
	/* This update must be after the first getclaim per CPU */
	tb->prior_cycles = now;
	put_cpu_var(kutrace_traceblock_per_cpu);	/* release preempt */	
	
	if (claim != NULL) {
		temp[0] |= (now << TIMESTAMP_SHIFT);
		memcpy(claim, temp, len * sizeof(u64));
		return len;
	}
	return 0;
}


/*
 * pid filter is an array of 64K bits, arranged as 1024 u64. It
 * cleared. When tracing context switches in kernel/sched/core.c, the
 * intended use is to check if the bit corresponding to next->pid & 0xffff is
 * off and if so put the process name next->comm[TASK_COMM_LEN]; from
 * task_struct into the trace as a pid_name entry, then set the bit.
 */

/* Reset tracing state to start a new clean trace */
/* Tracing must be off. tracebase must be non-NULL */
/* traceblock_next always points *just above* the next block to use */
/* When empty, traceblock_next == traceblock_high */
/* when full, traceblock_next == traceblock_limit */
/* Return 0 */
static u64 do_reset(u64 flags)
{
	int cpu;
/* hack_count = 0; */

	/* printk(KERN_INFO "  kutrace_trace reset(%016llx) called\n", flags); */
	/* Turn off tracing -- should already be off */
	kutrace_tracing = false;	/* Should already be off */
	do_ipc = ((flags & DO_IPC) != 0);
	do_llc = ((flags & DO_LLC) != 0);
	do_wrap = ((flags & DO_WRAP) != 0);
	/* We are in process context (kutrace_control syscall or module init) */
	if (do_ipc || do_llc) {
		if (!ku_reserve_pmu(do_ipc, do_llc))
			printk(KERN_INFO "  kutrace_mod: some PMU counters unavailable; "
			       "their IPC/LLC values will read as 0\n");
	} else {
		ku_release_pmu();
	}
	do_neither = (!do_ipc) & (!do_llc);
	do_both = (do_ipc & do_llc);
	do_ipc_only = (do_ipc & !do_llc);

	/* Clear pid filter */
	memset(kutrace_pid_filter, 0, 1024 * sizeof(u64));

	/* Set up trace buffer into a series of blocks of 64KB each */
	traceblock_high = (u64 *)(tracebase + (tracemb << 20));
	traceblock_limit = (u64 *)(tracebase);
	/* First trace item inserted will cause first new block */
	traceblock_next = traceblock_high;	
	did_wrap_around = false;

	if (do_ipc | do_llc) {
		/* Reserve lower 1/8 of trace buffer for IPC bytes */
		/* Strictly speaking, this should be 1/9. We waste a little space. */
		traceblock_limit = (u64*)(tracebase + (tracemb << (20 - 3)));
	}

	/* Set up spinlock as available */
	raw_spin_lock_init(&kutrace_lock);

	/* Set up per-CPU limits to immediately allocate a block */
	for_each_online_cpu(cpu) {
		struct kutrace_traceblock *tb =
			&per_cpu(kutrace_traceblock_per_cpu, cpu);

		ATOMIC_SET(&tb->next, (uintptr_t)NULL);
		tb->limit = NULL;
		tb->prior_cycles = 0;		// Cycle tracking
		tb->prior_inst_retired = 0;	// IPC tracking
		tb->prior_llc_misses = 0;	// LLC tracking
	}

	return 0;
}


/* Called from kernel patches */
/* Caller is responsible for making sure event fits in 12 bits and */
/*  arg fits in 16 bits for syscall/ret and 32 bits otherwise */
static /*asmlinkage*/ void trace_1(u64 event, u64 arg)
{
////        if (!kutrace_tracing)
////		return;

	/* Check for possible return optimization */
	if (((event & UNSHIFTED_EVENT_RETURN_BIT) != 0) &&
		((event & UNSHIFTED_EVENT_HAS_RETURN_MASK) != 0))
	{
		/* We have a return event 011x, 101x, 111x: 6/7, a/b, e/f */
		if (((arg + 128l) & ~UNSHIFTED_RETVAL_MASK) == 0) {
			/* Signed retval fits into a byte, [-128..127] */
			insert_1_retopt((event << EVENT_SHIFT) | arg);
			return;
		}
	}

	/* Non-optimized insert */
	insert_1((event << EVENT_SHIFT) | (arg & CLU(0xffffffff)));
}

/* Called from kernel patches */
/* ONLY called to insert PC sample at timer interrupt */
/* arg1 is unused (0), arg2 is the 64-bit PC sample */
static void trace_2(u64 event, u64 arg1, u64 arg2)
{
	u64 freq;
	if (!kutrace_tracing)
		return;

/* dsites 2021.04.05 insert CPU frequency */
	freq = ku_get_cpu_freq();
	insert_2((event << EVENT_SHIFT) | freq, arg2);
}

/* Called from kernel patches */
static void trace_many(u64 event, u64 len, const char *arg)
{
	uintptr_t tempptr;	/* 32- or 64-bit address */
	u64 temp[8];

	if (!kutrace_tracing)
		return;
	/* Turn off tracing if bogus length */
	if (is_bad_len(len)) {
		kutrace_tracing = false;
		return;
	}
	memcpy(temp, arg, len * sizeof(u64));
	temp[0] |= (event | (len << EVENT_LENGTH_FIELD_SHIFT)) << EVENT_SHIFT;
	tempptr = (uintptr_t)&temp[0];
	insert_n_krnl((u64)tempptr);
}


/* Syscall from user space via kernel patch */
static u64 kutrace_control(u64 command, u64 arg)
{
/*
 * printk(KERN_INFO "  kutrace_control: %08x %08x %08x %08x\n",
 *   (u32)(command & 0xFFFFFFFF), (u32)(command >> 32),
 *   (u32)(arg & 0xFFFFFFFF), (u32)(arg >> 32));
 */
	if (tracebase == NULL) {
		/* Error! */
		printk(KERN_INFO "  kutrace_control called with no trace buffer.\n");
		kutrace_tracing = false;
		return ~CLU(0);
	}

	/* If checking, disallow calls from tasks without CAP_SYS_PTRACE */
	/* has_capability() is no longer exported in 6.17/7.0; capable() checks current */
	if (check && !capable(CAP_SYS_PTRACE)) 
		return ~CLU(0);

	/* Generally, more likely calls are near the front of this list */
	if (command == KUTRACE_CMD_OFF) {
		return do_trace_off();
	} else if (command == KUTRACE_CMD_INSERT1) {
		/* If not tracing, insert nothing */
		if (!kutrace_tracing)
			return 0;
		return insert_1(arg);
	} else if (command == KUTRACE_CMD_INSERTN) {
		/* If not tracing, insert nothing */
		if (!kutrace_tracing)
			return 0;
		return insert_n_user(arg);
	} else if (command == KUTRACE_CMD_GETWORD) {
		return get_word(arg);
	} else if (command == KUTRACE_CMD_GETIPCWORD) {
		return get_ipc_word(arg);
	} else if (command == KUTRACE_CMD_ON) {
		return do_trace_on();
	} else if (command == KUTRACE_CMD_FLUSH) {
		return do_flush();
	} else if (command == KUTRACE_CMD_RESET) {
		return do_reset(arg);
	} else if (command == KUTRACE_CMD_STAT) {
		return do_stat();
	} else if (command == KUTRACE_CMD_GETCOUNT) {
		if (did_wrap_around) {
			/* Convey that we actually wrapped */
			return ~get_count();
		} else {
			return get_count();
		}
	} else if (command == KUTRACE_CMD_TEST) {
		return kutrace_tracing;	/* Just 0/1 for tracing off/on */
	} else if (command == KUTRACE_CMD_VERSION) {
		return kModuleVersionNumber;
	} else if (command == ~KUTRACE_CMD_INSERT1) {
		/* Allow kutrace_control to insert entries with tracing off */
		return insert_1(arg);
	} else if (command == ~KUTRACE_CMD_INSERTN) {
		/* Allow kutrace_control to insert entries with tracing off */
		return insert_n_user(arg);
	} else if (command == KUTRACE_CMD_SET4KB) {
		/* This returns 0 for success. */
		/* Older module versions will return ~0 for unknown command */
		get4kb_subscr = arg;
		return 0;
	} else if (command == KUTRACE_CMD_GET4KB) {
		return get_4kb(arg);
	} else if (command == KUTRACE_CMD_GETIPC4KB) {
		return get_ipc_4kb(arg);
	}

	/* Else quietly return -1 */
	return ~CLU(0);
}


/*
 * For the compiled-into-the-kernel design, call this at first
 * kutrace_control call to set up trace buffers, etc.
 */
static int __init kutrace_mod_init(void)
{
	printk(KERN_INFO "\nkutrace_trace hello =====================\n");
	kutrace_tracing = false;

	kutrace_pid_filter = (u64 *)vmalloc(1024 * sizeof(u64));
	printk(KERN_INFO "  vmalloc kutrace_pid_filter " FUINTPTRX "\n",
		(uintptr_t)kutrace_pid_filter);
	if (!kutrace_pid_filter)
		return -1;

	tracebase =  vmalloc(tracemb << 20);
	printk(KERN_INFO "  vmalloc kutrace_tracebase(%ld MB) " FUINTPTRX " %s\n",
		tracemb,
		(uintptr_t)tracebase,
		(tracebase == NULL) ? "FAIL" : "OK");
	if (!tracebase) {
		vfree(kutrace_pid_filter);
		return -1;
	}

	/* Set up TCP packet filter */
	/* Filter forms a hash over masked first N=24 bytes of packet payload */
	/* and looks for zero result. The hash is just u32 XOR along with */
	/* an initial value. pktmask gives mask bit-per-byte, and pktmatch */
	/* gives the expected result over those bytes. It is the */
	/* inital hash value, to give a simple zero test at the end. */
	if (pktmask == 0) {
		// Match nothing
		kutrace_net_filter.hash_mask[0] = 0LLU;
		kutrace_net_filter.hash_mask[1] = 0LLU;
		kutrace_net_filter.hash_mask[2] = 0LLU;
		kutrace_net_filter.hash_init = 1;	// hash will always be zero
	} else if (pktmask == -1) {
		// Match everything
		kutrace_net_filter.hash_mask[0] = 0LLU;
		kutrace_net_filter.hash_mask[1] = 0LLU;
		kutrace_net_filter.hash_mask[2] = 0LLU;
		kutrace_net_filter.hash_init = 0;	// hash will always be zero

	} else {
		int i;
		u8 *msk = (u8*)(kutrace_net_filter.hash_mask);
		for (i = 0; i < 24; ++i) {
			if ((pktmask >> i) & 1) {msk[i] = 0xFF;}
			else {msk[i] = 0x00;}
		}
		kutrace_net_filter.hash_init = (u64)(pktmatch);
	}
	printk(KERN_INFO "  mask %016llx", kutrace_net_filter.hash_mask[0]);
	printk(KERN_INFO "  mask %016llx", kutrace_net_filter.hash_mask[1]);
	printk(KERN_INFO "  mask %016llx", kutrace_net_filter.hash_mask[2]);
	printk(KERN_INFO "   ==  %016llx", kutrace_net_filter.hash_init);

	ku_setup_arm64();
	do_reset(0);
	printk(KERN_INFO "  kutrace_tracing = %d\n", kutrace_tracing);

	/* Finally, connect up the routines that can change the state */
	kutrace_global_ops.kutrace_trace_1 = &trace_1;
	kutrace_global_ops.kutrace_trace_2 = &trace_2;
	kutrace_global_ops.kutrace_trace_many = &trace_many;
	kutrace_global_ops.kutrace_trace_control = &kutrace_control;

	printk(KERN_INFO "  &kutrace_global_ops: " FUINTPTRX "\n", (uintptr_t)(&kutrace_global_ops));
	printk(KERN_INFO "  kutrace_trace All done init successfully!\n");
	return 0;
}

static void __exit kutrace_mod_exit(void)
{
	int cpu;
	printk(KERN_INFO "kutrace_mod Winding down =====================\n");
	/* Turn off tracing and quiesce */
	kutrace_tracing = false;
	msleep(20);	/* wait 20 msec for any pending tracing to finish */
	printk(KERN_INFO "  kutrace_tracing=false\n");

	/* Disconnect allthe routiens that can change state */
	kutrace_global_ops.kutrace_trace_1 = NULL;
	kutrace_global_ops.kutrace_trace_2 = NULL;
	kutrace_global_ops.kutrace_trace_many = NULL;
	kutrace_global_ops.kutrace_trace_control = NULL;
	printk(KERN_INFO "  kutrace_global_ops = NULL\n");

	/* Clear out all the pointers to trace data */
	for_each_online_cpu(cpu) {
		struct kutrace_traceblock* tb = &per_cpu(kutrace_traceblock_per_cpu, cpu);
		printk(KERN_INFO "  kutrace_traceblock_per_cpu[%d] = NULL\n", cpu);
		ATOMIC_SET(&tb->next, (uintptr_t)NULL);
		tb->limit = NULL;
		tb->prior_cycles = 0;		// Cycle tracking
		tb->prior_inst_retired = 0;	// IPC tracking
		tb->prior_llc_misses = 0;	// LLC tracking
	}

	traceblock_high = NULL;
	traceblock_limit = NULL;
	traceblock_next = NULL;

	ku_release_pmu();

	/* Now that nothing points to it, free memory */
	if (tracebase) {vfree(tracebase);}
	if (kutrace_pid_filter) {vfree(kutrace_pid_filter);}
	kutrace_pid_filter = NULL;

	printk(KERN_INFO "  kutrace_tracebase = NULL\n");
	printk(KERN_INFO "  kutrace_pid_filter = NULL\n");

	printk(KERN_INFO "kutrace__mod Goodbye\n");
}


module_init(kutrace_mod_init);
module_exit(kutrace_mod_exit);


