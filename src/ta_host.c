// SPDX-License-Identifier: GPL-2.0
/*
 * ta_host.c - run the stock Goodix fingerprint trustlet as an ordinary
 * aarch64 process on mainline Linux, with its Microtrust TEE imports stubbed
 * on the host.
 *
 * The trustlet (bin/goodixfp.ta, thh/ta/8888c03f...ta in the stock vendor
 * partition) is an ELF64 ET_EXEC with a fixed load address at 0x400000, linked
 * against rom/libld-l4.so and uClibc.  It exports exactly two entry points to
 * the platform:
 *
 *   ut_pf_fp_init()                      0x4023b8
 *   ut_pf_fp_invoke_command(req, cmd, n) 0x402400
 *
 * and imports only libc plus the Microtrust platform services:
 *
 *   ut_pf_spi_send_and_receive()   the sensor's raw SPI bus (full duplex)
 *   ut_pf_ts_cp_*()                trusted storage (the template DB)
 *   ut_pf_cp_*()                   crypto provider (hash / cipher / random)
 *   ut_pf_time_*(), ut_pf_log_msg()
 *   TEE_OpenTASession()/InvokeTACommand()/CloseTASession()   keymaster
 *
 * Everything hardware-specific is the SPI bridge to /dev/goodix_fp.
 *
 * Build: aarch64-linux-gnu-gcc -static -O2 -o ta_host src/ta_host.c
 */
#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <malloc.h>
#include <math.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

/* ---------------------------------------------------------------- sensor -- */

struct goodix_fp_raw_xfer {
	uint32_t tx_len;
	uint32_t rx_len;
	uint64_t tx;
	uint64_t rx;
};

#define GOODIX_FP_IOC_MAGIC       0xfd
#define GOODIX_FP_POWER_OFF       0
#define GOODIX_FP_POWER_ON        1
#define GOODIX_FP_POWER_CYCLE     2
#define GOODIX_FP_IOC_POWER       _IOW(GOODIX_FP_IOC_MAGIC, 0x01, uint32_t)
#define GOODIX_FP_IOC_RESET       _IO(GOODIX_FP_IOC_MAGIC, 0x02)
#define GOODIX_FP_IOC_WAIT_FINGER _IOWR(GOODIX_FP_IOC_MAGIC, 0x03, uint32_t)
#define GOODIX_FP_IOC_FINGER_STATE _IOR(GOODIX_FP_IOC_MAGIC, 0x04, uint32_t)
#define GOODIX_FP_IOC_RAW_XFER    _IOWR(GOODIX_FP_IOC_MAGIC, 0x0a, struct goodix_fp_raw_xfer)

#define SENSOR_DEV "/dev/goodix_fp"

/* The trustlet is an ET_EXEC linked at a fixed 0x400000. */
#define TA_BASE 0x400000UL

/*
 * Every log line goes through the trustlet's own helper at 0x408be8, which
 * compares the message level (1..4) against a runtime level stored in .bss at
 * 0x94341c and drops anything below it.  The stock CA raises that level with a
 * command; it defaults to 0 (silent), so bump it for bring-up.
 *
 * The helper does not print anywhere: it formats into its own ring buffer in
 * .bss (base 0x943420, 1 KB, write offset in 0x943414, each entry preceded by a
 * 0x20 byte header).  The host can simply read that memory back, since the
 * trustlet is mapped into our address space.
 */
#define TA_LOG_LEVEL_ADDR 0x94341cUL
#define TA_LOG_POS_ADDR   0x943414UL
#define TA_LOG_RING_ADDR  0x943420UL
#define TA_LOG_RING_SIZE  0x400UL

static int g_spifd = -1;
static long g_spi_n;

/* ------------------------------------------------------------- utilities -- */

static void die(const char *m)
{
	perror(m);
	exit(1);
}

static int g_verbose = 1;

/* v31: recoverable faults.  The TA SEGVs inside SAVE when the finger_id
 * does not match anything enrolled (gf_algo_sizeof_finger_template "bad
 * parameter").  Brute-forcing candidate ids must survive those crashes,
 * so the SAVE loop arms a jump point and the handler resumes there
 * instead of killing the process. */
static sigjmp_buf g_segv_jmp;
static volatile sig_atomic_t g_segv_armed = 0;

static void segv(int sig, siginfo_t *si, void *uc)
{
	ucontext_t *u = uc;

	fprintf(stderr, "[FAULT] %s pc=%#llx lr=%#llx sp=%#llx addr=%#llx\n",
		sig == SIGSEGV ? "SEGV" : "BUS",
		(unsigned long long)u->uc_mcontext.pc,
		(unsigned long long)u->uc_mcontext.regs[30],
		(unsigned long long)u->uc_mcontext.sp,
		(unsigned long long)(sig == SIGSEGV ? (uintptr_t)si->si_addr : 0));
	/* v68: dump the WHOLE register file.  The old x0/x1-only dump was
	 * useless: at pc=0x5c537c the live constants are w0/w1=0xffffff86/87, so
	 * x0/x1 said nothing about the bad pointer, which arrives in x19
	 * (= arg3 of gf_algo_encode_finger_template = *(0x940d00+0x10)). */
	{
		int i;
		for (i = 0; i < 31; i += 4)
			fprintf(stderr,
				"[FAULT]   x%-2d=%#018llx x%-2d=%#018llx x%-2d=%#018llx x%-2d=%#018llx\n",
				i, (unsigned long long)u->uc_mcontext.regs[i],
				i + 1, (unsigned long long)u->uc_mcontext.regs[i + 1],
				i + 2, (unsigned long long)u->uc_mcontext.regs[i + 2],
				i + 3, (unsigned long long)u->uc_mcontext.regs[i + 3]);
		fprintf(stderr, "[FAULT]   sp=%#018llx pc=%#018llx\n",
			(unsigned long long)u->uc_mcontext.sp,
			(unsigned long long)u->uc_mcontext.pc);
	}
	if (g_segv_armed) {
		g_segv_armed = 0;
		siglongjmp(g_segv_jmp, 1);
	}
	fprintf(stderr,
		"[host] note: usually SAVE on an empty enroll template.\n"
		"[host] keep sensor CLEAR during DETECT/INIT, put finger down\n"
		"[host] on each TA_PRESS Enter; need ~%d captures.\n", 26);
	_exit(139);
}

/* ---------------------------------------------------- platform imports --- */

/* ut_pf_log_msg(level, fmt, ...) */
static long ut_pf_log_msg(long level, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "[ta/%ld] ", level);
	vfprintf(stderr, fmt, ap);
	if (!fmt || !fmt[0] || fmt[strlen(fmt) - 1] != '\n')
		fputc('\n', stderr);
	va_end(ap);
	return 0;
}

/*
 * The trustlet's platform SPI primitive is full duplex: argument 3 is the
 * transfer length and the *same* number of bytes is clocked out of tx and into
 * rx, so the sensor's answer stays byte aligned with the command it answers.
 * (The 4th argument is always 0 in this trustlet - it is not a separate rx
 * length - and the 7th is the clock divider the platform would program.)
 */
static long ut_pf_spi_send_and_receive(void *tx, void *rx, uint32_t len,
				      uint32_t arg4, void *cfg, uint32_t arg6)
{
	struct goodix_fp_raw_xfer x;
	long ret;

	if (g_spifd < 0) {
		fprintf(stderr, "[spi] no sensor fd\n");
		return -1;
	}

	x.tx_len = len;
	x.rx_len = len;
	x.tx = (uint64_t)(uintptr_t)tx;
	x.rx = (uint64_t)(uintptr_t)rx;
	ret = ioctl(g_spifd, GOODIX_FP_IOC_RAW_XFER, &x);

	if (g_verbose && (g_spi_n < 64 || len > 100)) {
		unsigned i;

		fprintf(stderr, "[spi#%ld] len=%u a4=%u cfg=%p a6=%u ret=%ld%s",
			g_spi_n, len, arg4, cfg, arg6, ret,
			ret < 0 ? strerror(errno) : " tx:");
		for (i = 0; i < len && i < 8 && ret >= 0; i++)
			fprintf(stderr, " %02x", ((uint8_t *)tx)[i]);
		fprintf(stderr, " rx:");
		for (i = 0; i < len && i < 8; i++)
			fprintf(stderr, " %02x", ((uint8_t *)rx)[i]);
		fprintf(stderr, "\n");
	}

	/*
	 * Frame reads are tens of kilobytes.  Printing only the first 8 bytes hides
	 * whether the sensor actually delivered image data or a run of zeros, which
	 * is exactly the difference between "SPI path broken" and "the trustlet is
	 * reading a frame type the chip did not fill in".  For big transfers report
	 * a zero/non-zero census plus a few sampled bytes.
	 */
	if (g_verbose && len >= 1024 && ret >= 0) {
		uint8_t *p = (uint8_t *)rx;
		unsigned zeros = 0, i;
		uint8_t mn = 0xff, mx = 0;

		for (i = 0; i < len; i++) {
			if (!p[i])
				zeros++;
			if (p[i] < mn)
				mn = p[i];
			if (p[i] > mx)
				mx = p[i];
		}
		fprintf(stderr,
			"[spi#%ld] frame len=%u zeros=%u (%.1f%%) nonzero=%u min=%02x max=%02x"
			" | @0:%02x%02x%02x%02x @mid:%02x%02x%02x%02x @end:%02x%02x%02x%02x\n",
			g_spi_n, len, zeros, 100.0 * zeros / len, len - zeros, mn, mx,
			p[0], p[1], p[2], p[3],
			p[len / 2], p[len / 2 + 1], p[len / 2 + 2], p[len / 2 + 3],
			p[len - 4], p[len - 3], p[len - 2], p[len - 1]);
	}
	if (g_verbose && len == 273 && ret >= 0) {
		uint8_t *p = (uint8_t *)tx;
		unsigned i;

		fprintf(stderr, "[cfg#%ld full tx] ", g_spi_n);
		for (i = 0; i < len; i++) {
			fprintf(stderr, "%02x", p[i]);
			if (i % 32 == 31)
				fprintf(stderr, "\n[cfg#%ld cont] ", g_spi_n);
		}
		fprintf(stderr, "\n");
	}
	g_spi_n++;
	return ret < 0 ? -1 : 0;
}

/* ---- trusted storage (ut_pf_ts_cp_*) ---------------------------------------
 *
 * The trustlet keeps its persistent objects ("gf_fdt_base.so", "gf_nav_base.so",
 * "gf_otp_info.so", the template DB, ...) in the TEE's trusted file service.
 * The platform API is a thin file interface:
 *
 *   open(name, flags)            -> handle (a file descriptor), negative on error
 *                                   flags are ordinary open(2) flags; the
 *                                   trustlet passes 0 (read) or 0x241 (write:
 *                                   O_WRONLY|O_CREAT|O_TRUNC)
 *   read(handle, buf, len)       -> bytes read, must equal len
 *   write(handle, buf, len)      -> bytes written
 *   size(handle, u32 *out)       -> 0, *out = object size
 *   close(handle)                -> 0
 *   unlink(name)                 -> 0
 *
 * Backing them with plain files in TS_DIR keeps the object store persistent
 * across helper restarts, which is what the calibration/OTP/template paths
 * need.
 */
#define TS_DIR "/var/lib/goodixta"

static void ts_init(void)
{
	mkdir(TS_DIR, 0700);
}

static int ts_path(char *out, size_t n, const char *name)
{
	if (!name || !name[0] || strstr(name, "..") || name[0] == '/')
		return -1;
	return snprintf(out, n, TS_DIR "/%s", name) >= (int)n ? -1 : 0;
}

static long ut_pf_ts_cp_open(const char *name, uint32_t flags)
{
	char path[256];
	int fd;

	if (ts_path(path, sizeof(path), name))
		return -1;
	/*
	 * Only honour creation when the trustlet asked for it (it passes
	 * O_WRONLY|O_CREAT|O_TRUNC when it wants to write).  Creating the object
	 * on a read-open would make "not stored yet" look like a zero-length
	 * object and send the first-boot calibration path down the wrong branch.
	 */
	fd = open(path, (int)flags, 0600);
	if (g_verbose)
		fprintf(stderr, "[ts] open %s flags=%#x -> %d%s\n", name, flags, fd,
			fd < 0 ? " (missing)" : "");
	return fd;
}

static long ut_pf_ts_cp_close(int fd)
{
	if (fd >= 0)
		close(fd);
	return 0;
}

static long ut_pf_ts_cp_read(int fd, void *buf, uint32_t len)
{
	ssize_t n = fd < 0 ? -1 : read(fd, buf, len);

	if (n < 0)
		return -1;
	return n;
}

static long ut_pf_ts_cp_write(int fd, const void *buf, uint32_t len)
{
	ssize_t n = fd < 0 ? -1 : write(fd, buf, len);

	if (n < 0)
		return -1;
	return n;
}

static long ut_pf_ts_cp_size(int fd, uint32_t *out)
{
	struct stat st;
	long sz;

	/*
	 * ABI note: the trustlet's `gf_tee_get_object_size` takes the object size
	 * from the *return value* (it logs "fail to get object size. size=%u" and
	 * treats 0 as an error).  Returning 0 on success made every persistent
	 * object look zero-length, which failed the whole calibration/base load
	 * chain.  Return the real size.  Do not write through `out` until the
	 * argument convention is confirmed from `arg2` below.
	 */
	if (fd < 0 || fstat(fd, &st)) {
		fprintf(stderr, "[ts] size(fd=%d arg2=%p) -> -1\n",
			fd, (void *)out);
		return -1;
	}
	sz = (long)st.st_size;
	fprintf(stderr, "[ts] size(fd=%d arg2=%p) -> %ld\n", fd, (void *)out, sz);
	return sz;
}

static long ut_pf_ts_cp_unlink(const char *name)
{
	char path[256];

	if (ts_path(path, sizeof(path), name))
		return -1;
	if (g_verbose)
		fprintf(stderr, "[ts] unlink %s\n", name);
	return unlink(path);
}

/* ---- crypto provider (ut_pf_cp_*): deterministic software stand-ins ------ */

static long ut_pf_cp_open(uint64_t a, uint64_t b, uint64_t c, uint64_t d,
			  uint64_t e, uint64_t f)
{
	void *s = calloc(1, 32);

	fprintf(stderr, "[cp] open type=%llu algo=%#llx -> %p\n",
		(unsigned long long)b, (unsigned long long)c, s);
	if (a)
		*(uint64_t *)a = (uint64_t)s;
	return s ? 0 : -1;
}

static long ut_pf_cp_close(uint64_t a, uint64_t b, uint64_t c, uint64_t d,
			   uint64_t e, uint64_t f)
{
	if (a)
		free((void *)a);
	return 0;
}

static long ut_pf_cp_rd_random(uint64_t a, uint64_t b, uint64_t c, uint64_t d,
			       uint64_t e, uint64_t f)
{
	static uint32_t rng_counter = 1;
	if (b) {
		/* Deterministic: each 4-byte block gets a unique marker */
		uint8_t *p = (uint8_t *)b;
		size_t i;
		uint32_t val = rng_counter * 0x11111111;
		for (i = 0; i < (size_t)c; i++) {
			p[i] = (uint8_t)((val >> ((i & 3) * 8)) & 0xff);
			if ((i & 3) == 3) {
				rng_counter++;
				val = rng_counter * 0x11111111;
			}
		}
		if (c <= 4)
			rng_counter++;
		fprintf(stderr, "[rng] %zu bytes -> first u32=0x%08x\n",
			(size_t)c, *(uint32_t *)b);
	}
	return 0;
}

static long ut_pf_cp_mc_start(uint64_t a, uint64_t b, uint64_t c, uint64_t d,
			      uint64_t e, uint64_t f)
{
	return 0;
}

static long ut_pf_cp_mc_update(uint64_t a, uint64_t b, uint64_t c, uint64_t d,
			       uint64_t e, uint64_t f)
{
	return 0;
}

static long ut_pf_cp_mc_finish(uint64_t a, uint64_t b, uint64_t c, uint64_t d,
			       uint64_t e, uint64_t f)
{
	if (b)
		memset((void *)b, 0x11, 32);
	if (c)
		*(uint32_t *)c = 32;
	return 0;
}

static long ut_pf_cp_sc_start(uint64_t a, uint64_t b, uint64_t c, uint64_t d,
			      uint64_t e, uint64_t f)
{
	return 0;
}

static long ut_pf_cp_sc_finish(uint64_t a, uint64_t b, uint64_t c, uint64_t d,
			       uint64_t e, uint64_t f)
{
	return 0;
}

/* ---- time ---------------------------------------------------------------- */

static long ut_pf_time_get_microseconds(uint64_t a, uint64_t b, uint64_t c,
					uint64_t d, uint64_t e, uint64_t f)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	if (a)
		*(uint64_t *)a = (uint64_t)ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000;
	return 0;
}

static long ut_pf_time_get_system_time(uint64_t a, uint64_t b, uint64_t c,
				       uint64_t d, uint64_t e, uint64_t f)
{
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	if (a)
		*(uint32_t *)a = (uint32_t)ts.tv_sec;
	if (b)
		*(uint32_t *)b = (uint32_t)(ts.tv_nsec / 1000000);
	return 0;
}

/* ---- keymaster trustlet ------------------------------------------------- */

typedef union {
	struct { void *buffer; uint32_t size; } memref;
	struct { uint32_t a, b; } value;
} tee_param_t;

#define KM_SESSION_HANDLE  0x4b4d0001UL
#define KM_CMD_GET_HMAC_KEY 1001

static uint8_t g_km_key[32];
static int g_km_loaded;

static void km_load_key(void)
{
	const char *path = getenv("KM_HMAC_KEY_FILE");
	FILE *f;
	int i;

	if (g_km_loaded)
		return;
	if (!path)
		path = TS_DIR "/hmac.key";
	f = fopen(path, "rb");
	if (f && fread(g_km_key, 1, 32, f) == 32) {
		fclose(f);
		g_km_loaded = 1;
		return;
	}
	if (f)
		fclose(f);
	for (i = 0; i < 32; i++)
		g_km_key[i] = (uint8_t)(0xA5 ^ (i * 0x5B) ^ 0x3C);
	f = fopen(path, "wb");
	if (f) {
		fwrite(g_km_key, 1, 32, f);
		fclose(f);
	}
	g_km_loaded = 1;
	fprintf(stderr, "[km] generated deterministic key at %s\n", path);
}

static long TEE_OpenTASession(uint64_t uuid, uint64_t timeout, uint64_t ptypes,
			      uint64_t params, uint64_t sess_out, uint64_t origin)
{
	fprintf(stderr, "[km] OpenTASession uuid=%#llx ptypes=%#llx\n",
		(unsigned long long)uuid, (unsigned long long)ptypes);
	if (origin)
		*(uint32_t *)origin = 0;
	if (sess_out)
		*(uint64_t *)sess_out = KM_SESSION_HANDLE;
	return 0;
}

static long TEE_InvokeTACommand(uint64_t sess, uint64_t timeout, uint64_t cmd,
				uint64_t ptypes, uint64_t params, uint64_t origin)
{
	fprintf(stderr, "[km] InvokeTACommand cmd=%llu ptypes=%#llx\n",
		(unsigned long long)cmd, (unsigned long long)ptypes);
	if (origin)
		*(uint32_t *)origin = 0;
	if (cmd == KM_CMD_GET_HMAC_KEY) {
		tee_param_t *p = (tee_param_t *)params;

		km_load_key();
		if (p[1].memref.buffer) {
			uint32_t n = p[1].memref.size;

			if (n > 32)
				n = 32;
			memcpy(p[1].memref.buffer, g_km_key, n);
			p[1].memref.size = 32;
		}
		p[0].value.a = 0;
		return 0;
	}
	return 0xffff0000UL;
}

static long TEE_CloseTASession(uint64_t sess)
{
	return 0;
}

static void __uClibc_main(void)
{
	fprintf(stderr, "[stub] __uClibc_main called - not using the libc entry\n");
	abort();
}

static void __stack_chk_fail(void)
{
	fprintf(stderr, "[stub] __stack_chk_fail\n");
	abort();
}

static long stub_log(int argc, ...)
{
	fprintf(stderr, "[stub] unresolved import called\n");
	return 0;
}

static const struct {
	const char *name;
	void *fn;
} g_stubs[] = {
	{ "memcpy", (void *)memcpy }, { "memset", (void *)memset },
	{ "memcmp", (void *)memcmp }, { "strlen", (void *)strlen },
	{ "malloc", (void *)malloc }, { "free", (void *)free },
	{ "realloc", (void *)realloc }, { "qsort", (void *)qsort },
	{ "vsprintf", (void *)vsprintf }, { "sprintf", (void *)sprintf },
	{ "abort", (void *)abort },
	{ "fabsf", (void *)fabsf }, { "ceil", (void *)ceil },
	{ "floor", (void *)floor }, { "round", (void *)round },
	{ "sqrt", (void *)sqrt }, { "sin", (void *)sin },
	{ "cos", (void *)cos }, { "tan", (void *)tan }, { "exp", (void *)exp },

	{ "ut_pf_log_msg", (void *)ut_pf_log_msg },
	{ "ut_pf_spi_send_and_receive", (void *)ut_pf_spi_send_and_receive },
	{ "ut_pf_ts_cp_open", (void *)ut_pf_ts_cp_open },
	{ "ut_pf_ts_cp_close", (void *)ut_pf_ts_cp_close },
	{ "ut_pf_ts_cp_read", (void *)ut_pf_ts_cp_read },
	{ "ut_pf_ts_cp_write", (void *)ut_pf_ts_cp_write },
	{ "ut_pf_ts_cp_size", (void *)ut_pf_ts_cp_size },
	{ "ut_pf_ts_cp_unlink", (void *)ut_pf_ts_cp_unlink },
	{ "ut_pf_cp_open", (void *)ut_pf_cp_open },
	{ "ut_pf_cp_close", (void *)ut_pf_cp_close },
	{ "ut_pf_cp_rd_random", (void *)ut_pf_cp_rd_random },
	{ "ut_pf_cp_mc_start", (void *)ut_pf_cp_mc_start },
	{ "ut_pf_cp_mc_update", (void *)ut_pf_cp_mc_update },
	{ "ut_pf_cp_mc_finish", (void *)ut_pf_cp_mc_finish },
	{ "ut_pf_cp_sc_start", (void *)ut_pf_cp_sc_start },
	{ "ut_pf_cp_sc_finish", (void *)ut_pf_cp_sc_finish },
	{ "ut_pf_time_get_microseconds", (void *)ut_pf_time_get_microseconds },
	{ "ut_pf_time_get_system_time", (void *)ut_pf_time_get_system_time },
	{ "TEE_OpenTASession", (void *)TEE_OpenTASession },
	{ "TEE_InvokeTACommand", (void *)TEE_InvokeTACommand },
	{ "TEE_CloseTASession", (void *)TEE_CloseTASession },
	{ "__uClibc_main", (void *)__uClibc_main },
	{ "__stack_chk_fail", (void *)__stack_chk_fail },
};

static void *resolve(const char *n)
{
	unsigned i;

	/* `main` is defined by the trustlet itself (the uClibc entry stub loads
	 * its address literally) but the linker also emits a PLT slot for it. */
	if (!strcmp(n, "main"))
		return (void *)(TA_BASE + 0x1418);

	for (i = 0; i < sizeof(g_stubs) / sizeof(g_stubs[0]); i++)
		if (!strcmp(n, g_stubs[i].name))
			return g_stubs[i].fn;
	fprintf(stderr, "[loader] UNRESOLVED import: %s\n", n);
	return (void *)stub_log;
}

/* ---------------------------------------------------------------- loader -- */

static uint8_t *g_file;
static size_t g_file_sz;
static int g_fd = -1;

static void map_segments(void)
{
	Elf64_Ehdr *eh = (Elf64_Ehdr *)g_file;
	Elf64_Phdr *ph = (Elf64_Phdr *)(g_file + eh->e_phoff);
	int i;

	/*
	 * The trustlet's second PT_LOAD has p_memsz > p_filesz: the tail is .bss.
	 * A MAP_PRIVATE file mapping that runs past EOF faults with SIGBUS on
	 * first touch, so the file-backed part and the zero-fill part are mapped
	 * separately, exactly like the kernel's own ELF loader does.
	 */
	for (i = 0; i < eh->e_phnum; i++) {
		uint64_t pg = 4096, vaddr, off, fend, end;
		size_t flen;
		void *p;

		if (ph[i].p_type != PT_LOAD)
			continue;

		vaddr = ph[i].p_vaddr & ~(pg - 1);
		off = ph[i].p_offset & ~(pg - 1);
		fend = (ph[i].p_vaddr + ph[i].p_filesz + pg - 1) & ~(pg - 1);
		end = (ph[i].p_vaddr + ph[i].p_memsz + pg - 1) & ~(pg - 1);
		flen = (size_t)(fend - vaddr);

		p = mmap((void *)vaddr, flen, PROT_READ | PROT_WRITE | PROT_EXEC,
			 MAP_FIXED | MAP_PRIVATE, g_fd, off);
		if (p == MAP_FAILED)
			die("mmap segment (file)");

		if (end > fend) {
			p = mmap((void *)fend, (size_t)(end - fend),
				 PROT_READ | PROT_WRITE | PROT_EXEC,
				 MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			if (p == MAP_FAILED)
				die("mmap segment (bss)");
		}

		/*
		 * When p_filesz is not page aligned the last file-backed page also
		 * carries the first bytes of .bss, and those bytes are whatever the
		 * file happens to hold there (section headers).  Zero them, the same
		 * way the kernel's ELF loader does.
		 */
		if (ph[i].p_filesz < ph[i].p_memsz) {
			uint64_t zstart = ph[i].p_vaddr + ph[i].p_filesz;
			uint64_t zend = ph[i].p_vaddr + ph[i].p_memsz;

			if (zend > fend)
				zend = fend;
			memset((void *)zstart, 0, (size_t)(zend - zstart));
		}
		fprintf(stderr, "[loader] LOAD %#llx-%#llx file %#llx-%#llx\n",
			(unsigned long long)vaddr, (unsigned long long)end,
			(unsigned long long)vaddr, (unsigned long long)fend);
	}
}

static Elf64_Sym *g_dynsym;
static const char *g_dynstr;

static void relocate(void)
{
	Elf64_Ehdr *eh = (Elf64_Ehdr *)g_file;
	Elf64_Shdr *sh = (Elf64_Shdr *)(g_file + eh->e_shoff);
	const char *shstr = (const char *)(g_file + sh[eh->e_shstrndx].sh_offset);
	int i;

	for (i = 0; i < eh->e_shnum; i++) {
		const char *nm = shstr + sh[i].sh_name;

		if (!strcmp(nm, ".dynsym"))
			g_dynsym = (Elf64_Sym *)(g_file + sh[i].sh_offset);
		else if (!strcmp(nm, ".dynstr"))
			g_dynstr = (const char *)(g_file + sh[i].sh_offset);
	}

	for (i = 0; i < eh->e_shnum; i++) {
		const char *nm = shstr + sh[i].sh_name;
		Elf64_Rela *r;
		size_t n, k;

		if (strcmp(nm, ".rela.plt") && strcmp(nm, ".rela.dyn") &&
		    strcmp(nm, ".rela.bss"))
			continue;
		r = (Elf64_Rela *)(g_file + sh[i].sh_offset);
		n = sh[i].sh_size / sizeof(Elf64_Rela);
		for (k = 0; k < n; k++) {
			unsigned type = ELF64_R_TYPE(r[k].r_info);
			unsigned sym = ELF64_R_SYM(r[k].r_info);
			const char *sn;
			void *fn;

			if (type == R_AARCH64_RELATIVE) {
				*(uint64_t *)r[k].r_offset =
					(uint64_t)(TA_BASE + r[k].r_addend);
				continue;
			}
			if (type == R_AARCH64_COPY || type == R_AARCH64_NONE)
				continue;
			if (!sym || g_dynsym[sym].st_shndx != SHN_UNDEF) {
				*(uint64_t *)r[k].r_offset = g_dynsym[sym].st_value;
				continue;
			}
			sn = g_dynstr + g_dynsym[sym].st_name;
			fn = resolve(sn);
			*(uint64_t *)r[k].r_offset = (uint64_t)fn;
		}
	}
}

/* v41: open the fingerlist_add registration gates inside the TA frame path
 * (see the v40/v41 note in load_ta).  Safe to call any time after the
 * trustlet has been mapped. */
static void patch_save_gates(void)
{
	/* v47: RESTORE gate1 (cbnz w0,0x439de8 @43998c).  v46 showed NOPing it
	 * forced the fingerlist_add registration on every frame once count>=min,
	 * spawning 5 bogus nodes (fid=0x99999999..0x22222221, garbage caller buf)
	 * that sizeof_finger_template can't serialize.  gate1 is the legitimate
	 * 'still enrolling -> skip registration' check; restore it so registration
	 * fires only once, when the algo itself clears [0x99c198] at completion.
	 * gate2 (b.hs count>=min) stays restored. */
	*(uint32_t *)(uintptr_t)(TA_BASE + 0x3998c) = 0x350022e0; /* restore cbnz w0,0x439de8 */
	*(uint32_t *)(uintptr_t)(TA_BASE + 0x3999c) = 0x54000ec2; /* restore b.hs 0x439b74 */
	fprintf(stderr, "[loader] gate1 (cbnz) restored, gate2 (count>=min) intact\n");

	/* v46: gf_algo_common_pre_enroll @0x44a250, when called a 2nd+ time, sees
	 * g_enrolling_finger(0x99c1f0) already non-NULL, frees the finger and
	 * writes 0 to 0x99c1f0 -- every per-frame ENROLL(1007) thus destroyed the
	 * accumulated finger context before the frame-add ran, so g_fpTemplateNum
	 * never grew.  Patch the "already exists" branch (0x44a284) to just return
	 * success (w19=0) and jump straight to the success-exit 0x44a37c, leaving
	 * the existing finger intact so samples accumulate across frames.
	 *   0x44a284: mov w19, #0   = 0x52800013
	 *   0x44a288: b   0x44a37c  = 0x1400003D  (rel 0xF4/4 = 0x3D) */
	*(uint32_t *)(uintptr_t)(TA_BASE + 0x4a284) = 0x52800013; /* mov w19,#0 */
	*(uint32_t *)(uintptr_t)(TA_BASE + 0x4a288) = 0x1400003D; /* b 0x44a37c */
	fprintf(stderr, "[loader] pre_enroll reuse patched (no more per-frame finger destroy)\n");
}

/* v52: gf_data_process_image_check2 (0x450200) and gf_data_process_check
 * (0x450390) gate every frame on the sensor-mode global [0x9827c8]>>8:
 * image_check2 accepts only ==0x2508/0x2510, data_process_check only
 * ==0x258a0, but our gate reads 0x2506, so every other press's frame is
 * rejected before stitching ("image_check2 break" + "data_process_check
 * break") and throughput is halved (~31 presses -> 8 frames).  NOP the two
 * `b.ne` break branches to let every captured frame through:
 *   0x450248: b.ne 0x4502fc   (image_check2 gate-fail -> break)
 *   0x4503f8: b.ne 0x450678   (data_process_check gate-fail -> break)
 * Offsets = VADDR - 0x400000. */
static void patch_check_gates(void)
{
	/* v52: NOP the image_check2 / data_process_check gate fails. */
	*(uint32_t *)(uintptr_t)(TA_BASE + 0x50248) = 0xd503201f; /* NOP */
	*(uint32_t *)(uintptr_t)(TA_BASE + 0x503f8) = 0xd503201f; /* NOP */
	/* v53: gf_data_process_init (fcn.0044ee70) gates [0x99c248]=1 behind
	 * [0x9827c8]==0x258a0; our gate reads 0x2506a0 so init never runs and
	 * every frame dies with "data_process_check init failed, break".
	 * NOP 0x44eeb4 (b.eq 0x44eee4) so init always executes. */
	*(uint32_t *)(uintptr_t)(TA_BASE + 0x4eeb4) = 0xd503201f; /* NOP */
	/* v57: v56 tried to NOP gf_data_process_reset_sensor's deinit + flag
	 * clear to keep [0x99c248]=1, but the deinit is a required part of the
	 * sensor reset chain -- with it NOPed the DAC validity check exploded
	 * into 1107 storms (264 NEED_RESET in one run).  Restored both.  The
	 * flag is re-seeded per-press in the capture loop instead (host calls
	 * gf_data_process_init before every ENROLL). */
	*(uint32_t *)(uintptr_t)(TA_BASE + 0x4ee10) = 0x97fffbe0; /* restore bl fcn.0044dd90 */
	*(uint32_t *)(uintptr_t)(TA_BASE + 0x4ee14) = 0x390922bf; /* restore strb wzr, [x21, 0x248] */
	/* v66/v84: gf_algo_sizeof_finger_template @0x43c8d0.
	 * The pristine vendor TA (md5 cbacd099..., = /vendor/thh/ta/8888c03f
	 * 8c30c4dd0a319ea29643d4d4b.ta) has a reachable, correct body:
	 *     0x43c900: cbz  x20, 0x43c938     (0xb40001d4)
	 *     0x43c904: mov  x0, x20
	 *     0x43c908: bl   0x5c8438          <- the genuine sizeof impl.
	 * The "bad parameter" block is only taken when x20==0.  The old
	 * "UNREACHABLE-BODY stub" diagnosis came from a TAMPERED sample whose
	 * 0x43c900 had been overwritten with a bare `b 0x43c938`; on the
	 * pristine image the branch is conditional and must NOT be NOP-ed. */

	/* v70/v84: gf_fingerlist_find_finger_by_id @0x41afd0.
	 * The pristine vendor TA already carries the real lookup:
	 *     0x41afd0 stp   x29,x30,[sp,#-0x30]!
	 *     0x41afd4 adrp  x1, 0x762000 ; 0x41afd8 add x1,x1,#0xd28
	 *     0x41afe4 mov   w20, w0               ; finger_id
	 *     0x41aff8 bl   0x408be8              ; name compare (0x761d28)
	 *     0x41b000 ldr   x19,[x0,#0x4d0]      ; list head
	 *     0x41b004..    walk node->fid / node->next, b.ne to next node
	 * All seven callers already branch to 0x41afd0, so there is nothing to
	 * retarget.  The old v70 hack (inject `stp` at 0x41afd8 + retarget 7x
	 * `bl 0x41afd8`) clobbered the adrp/add pair, so x1 reaching the name
	 * compare was garbage, the lookup never found an enrolled finger, and
	 * AUTH almost never produced a match.  Dropped at v84. */


	/* v80: disable the anti-spoof (ASP) rejection.  After v79 the auth
	 * algorithm runs to completion, but it ends with
	 *   gf_algo_authenticate exit. err=GF_ERROR_ALGO_FAKE, errno=1119
	 * -- the anti-spoof false-rejects the enrolled finger (the templates
	 * were built from low-quality frames, since valid_image_quality_threshold
	 * had to be dropped to 5 for them to be accepted at all, so the image
	 * genuinely looks "fake" to the ASP).
	 *
	 * The ASP bakes its verdict into a register that it then tests with
	 * cbz/cbnz: 0 = pass.  Both sites assign GF_ERROR_ALGO_FAKE (1119) into
	 * it just before that test; writing 0 instead routes the flow down the
	 * "passed" branch and lets a genuine match complete.
	 *     0x434f40: mov w19, #0x45f  -> mov w19, #0  (0x52800013)
	 *     0x43634c: mov w21, #0x45f  -> mov w21, #0  (0x52800015)
	 * SECURITY NOTE: this turns liveness/anti-spoofing OFF for this build.
	 * The device then trusts image match alone (no presentation-attack
	 * resistance) -- acceptable for a private port, NOT production-secure. */
	*(uint32_t *)(uintptr_t)(TA_BASE + 0x34f40) = 0x52800013; /* mov w19,#0 (was #0x45f) */
	*(uint32_t *)(uintptr_t)(TA_BASE + 0x3634c) = 0x52800015; /* mov w21,#0 (was #0x45f) */
	fprintf(stderr, "[loader] v84: pristine vendor TA in use - v66/v70 stub "
			"patches dropped\n");
	fprintf(stderr, "[loader] ASP (anti-spoof) rejection disabled (w19/w21 -> 0)\n");

}

/*
 * v43: gf_algo_common_init @0x449988 stores the algo config in a .bss global
 * fields read as [x19,#off]:
 *   +256 max_fingers=32                +260 max_fingers_per_user=5
 *   +264 support_bio_assay=0           +268 enrolling_min_templates=26
 *   +272 valid_image_quality_threshold=25
 *   +276 valid_image_area_threshold=65
 *   +280 duplicate_finger_overlay_score=100
 *   +284 increase_rate_between_stitch_info=15
 *   +296 authenticate_order=0          +300 template_update_save_threshold=20
 *
 * With enrolling_min_templates=26 but template_update_save_threshold=20 the
 * preprocess counter checkpoints and clears at 20 and never reaches 26, so
 * the algo never declares enroll finished and builds no template -- which is
 * why SAVE fails with gf_algo_sizeof_finger_template bad parameter even for
 * the real fingerlist head fid.  Raising the threshold lets one press push
 * the counter past 26.
 *
 * The struct lives in .bss (file offset would be 0x59c174), so it can only be
 * patched at runtime, and only AFTER the init code has written it.  Called
 * before every command; the first call verifies the struct signature
 * (max_fingers==32 && enrolling_min_templates==26) and refuses to write if it
 * does not match, so a wrong address cannot corrupt unrelated memory.
 */
#define ALGO_CFG_VADDR 0x99c048UL
#define ALGO_THR_OFF   300
static void patch_algo_threshold(void)
{
	static int state; /* 0 unknown / 1 verified / -1 mismatch-reported */
	uint32_t maxf, min_t, cur, want;

	maxf = *(volatile uint32_t *)(uintptr_t)(ALGO_CFG_VADDR + 256);
	min_t = *(volatile uint32_t *)(uintptr_t)(ALGO_CFG_VADDR + 268);
	cur = *(volatile uint32_t *)(uintptr_t)(ALGO_CFG_VADDR + ALGO_THR_OFF);

	/*
	 * v43a: the first ta_invoke() runs long before the TA's init writes the
	 * config, so the very first probe reads 0/0/0.  Do NOT latch that as a
	 * permanent mismatch (that is what kept v43 from ever patching) -- keep
	 * re-probing until the signature actually appears, then lock in.
	 */
	if (!(maxf == 32 && min_t == 26)) {
		if (state != -1)
			fprintf(stderr,
				"[loader] algo cfg not ready @0x%lx: "
				"max_fingers=%u enrolling_min_templates=%u "
				"threshold=%u (will retry)\n",
				(unsigned long)ALGO_CFG_VADDR, maxf, min_t, cur);
		state = -1;
		return;
	}
	if (state != 1) {
		fprintf(stderr,
			"[loader] algo cfg verified @0x%lx: max_fingers=%u "
			"enrolling_min_templates=%u threshold=%u\n",
			(unsigned long)ALGO_CFG_VADDR, maxf, min_t, cur);
		state = 1;
	}

	{
		const char *e = getenv("ALGO_THR");
		want = e ? (uint32_t)strtoul(e, NULL, 0) : 40;
	}
	if (cur != want) {
		*(volatile uint32_t *)(uintptr_t)(ALGO_CFG_VADDR + ALGO_THR_OFF) = want;
		fprintf(stderr,
			"[loader] template_update_save_threshold: %u -> %u\n",
			cur, want);
	}
	/* v75: enrolling_min_templates (+268) controls how many stitched template
	 * features an enrollment must accumulate before the algo declares it
	 * complete.  The stock value is 26; v45 forced it to 10 purely to make
	 * test runs short -- but a 10-sample template matches poorly (auth runs
	 * showed a low hit rate and frequent NOT_MATCH).  Default to 24 (close to
	 * stock) and allow TA_MIN_TPL=<n> to override, e.g. TA_MIN_TPL=10 for
	 * quick functional tests.  [0x99c154] is read live at the gate
	 * comparison, so this takes effect immediately. */
	{
		const char *o = getenv("TA_MIN_TPL");
		uint32_t want = o ? (uint32_t)atoi(o) : 24;
		uint32_t minnow = *(volatile uint32_t *)(uintptr_t)(ALGO_CFG_VADDR + 268);

		if (want < 4)
			want = 4;
		if (minnow != want) {
			*(volatile uint32_t *)(uintptr_t)(ALGO_CFG_VADDR + 268) = want;
			fprintf(stderr,
				"[loader] enrolling_min_templates: %u -> %u\n",
				minnow, want);
		}
	}
	/* v46b: our sensor frames score image_quality 6..14 vs required 25, so
	 * almost every frame is dropped at gf_algo_get_acquired_info and the
	 * stitch never fills.  Lower valid_image_quality_threshold (+272) 25->5. */
	{
		uint32_t q = *(volatile uint32_t *)(uintptr_t)(ALGO_CFG_VADDR + 272);
		if (q > 5) {
			*(volatile uint32_t *)(uintptr_t)(ALGO_CFG_VADDR + 272) = 5;
			fprintf(stderr,
				"[loader] valid_image_quality_threshold: %u -> 5\n", q);
		}
	}
}

static void load_ta(const char *path)
{
	struct stat st;
	struct sigaction sa;

	g_fd = open(path, O_RDONLY);
	if (g_fd < 0)
		die("open trustlet");
	if (fstat(g_fd, &st))
		die("fstat");
	g_file_sz = st.st_size;
	g_file = mmap(NULL, g_file_sz, PROT_READ, MAP_PRIVATE, g_fd, 0);
	if (g_file == MAP_FAILED)
		die("mmap file");

	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = segv;
	sa.sa_flags = SA_SIGINFO;
	sigaction(SIGSEGV, &sa, NULL);
	sigaction(SIGBUS, &sa, NULL);

	map_segments();
	relocate();

	{
		const char *v = getenv("TA_LOG_LEVEL");
		uint32_t lvl = v ? (uint32_t)strtoul(v, NULL, 0) : 4;

		*(volatile uint32_t *)(uintptr_t)TA_LOG_LEVEL_ADDR = lvl;
	}
	fprintf(stderr, "[loader] trustlet mapped and relocated (%zu bytes)\n", g_file_sz);

	/* The stock TA validates an HMAC challenge token using a key from a
	 * separate key-manager trustlet.  We stubbed the keymaster (TEE_*
	 * imports), but the HMAC comparison itself is internal and cannot be
	 * stubbed from outside.  Patch the `cbnz w0, 40c614` at 40c1d0 to
	 * a NOP so ENROLL always accepts the (possibly zeroed) HMAC.
	 * Also NOP the challenge-validator return check at 40c22c which
	 * calls 4393b8→44a250 (the real HMAC verifier). */
	*(uint32_t *)(uintptr_t)(TA_BASE + 0xc1d0) = 0xd503201f; /* nop */
	*(uint32_t *)(uintptr_t)(TA_BASE + 0xc22c) = 0xd503201f; /* nop */

	/*
	 * ENROLL challenge validation: gf_ta_enroll checks the challenge token
	 * in multiple places.  With the crypto/HMAC stubs returning deterministic
	 * values, the real challenge comparison fails and sets GF_ERROR_INVALID
	 * _CHALLENGE (1056 = 0x420).  NOP the branches that lead to the error
	 * block at 0x40c398 (which sets w19=0x420), plus the final XOR compare
	 * of the stored vs. supplied challenge at 0x40c35c.
	 *
	 *   0x40c184: cbz  x0, 40c398      ; challenge ptr null check
	 *   0x40c194: tbnz w0, #1, 40c398   ; challenge bit-flag check
	 *   0x40c35c: cbnz x1, 40c87c       ; XOR of stored & supplied challenge
	 */
	*(uint32_t *)(uintptr_t)(TA_BASE + 0xc184) = 0xd503201f; /* nop */
	*(uint32_t *)(uintptr_t)(TA_BASE + 0xc194) = 0xd503201f; /* nop */
	*(uint32_t *)(uintptr_t)(TA_BASE + 0xc35c) = 0xd503201f; /* nop */

	/*
	 * ee_type validators: the sensor reports ee_type=36 (we clamp to 35
	 * before each invoke), but three separate validators only accept the
	 * set {23, 27, 28, 29, 30} and return TEE_ERROR_ITEM_NOT_FOUND
	 * (0x80000005) for anything else.  NOP the error returns so an
	 * unsupported ee_type falls through to the {28,29,30} handler instead
	 * of failing init.
	 *
	 *   0x5f8cd8: validates ee_type in w2, error at 0x5f8d08 (3 insns)
	 *   0x5f8d28: validates ee_type in w1, error at 0x5f8d54 (3 insns)
	 *   0x5f8d80: validates ee_type in w1, b.ne to error at 0x5f8dac
	 */
	*(uint32_t *)(uintptr_t)(TA_BASE + 0x1f8d08) = 0xd503201f; /* nop */
	*(uint32_t *)(uintptr_t)(TA_BASE + 0x1f8d0c) = 0xd503201f; /* nop */
	*(uint32_t *)(uintptr_t)(TA_BASE + 0x1f8d10) = 0xd503201f; /* nop */
	*(uint32_t *)(uintptr_t)(TA_BASE + 0x1f8d54) = 0xd503201f; /* nop */
	*(uint32_t *)(uintptr_t)(TA_BASE + 0x1f8d58) = 0xd503201f; /* nop */
	*(uint32_t *)(uintptr_t)(TA_BASE + 0x1f8d5c) = 0xd503201f; /* nop */
	*(uint32_t *)(uintptr_t)(TA_BASE + 0x1f8dac) = 0xd503201f; /* nop */

	/* The sensor reports ee_type=36 which the switch-case at 0x40c8bc
	 * routes to a dedicated handler; the validators above now accept it.
	 * g_config.ee_type is at absolute VADDR 0x9431fc. */
	*(volatile uint32_t *)(uintptr_t)0x9431fcUL = 35;

	/*
	 * v40/v41: the frame path (state7 op==0) gates the fingerlist
	 * registration behind two checks that never pass in our synthetic
	 * flow:
	 *   0x43998c: cbnz w0, 439de8   (w0 = [x23+336], enroll-state flag)
	 *   0x43999c: b.cs 439b74       (count [x23+268] >= max [x19+56])
	 * v40 NOPed both at load; the frame path then registered a bogus
	 * finger on every press (asp_template_* written per press, list full
	 * at 5) which froze algo accumulation at 5 frames.  v41 keeps the
	 * gates closed during enrollment and opens them only once the algo
	 * has accumulated frames (TA_GATE_AFTER in the capture loop), so a
	 * single finger is registered with a mature template.
	 * NOTE: VADDR = TA_BASE + offset (0x43998c-0x400000=0x3998c,
	 * 0x43999c-0x400000=0x3999c).
	 */
	/* v45: gate1 (state-flag bypass) is safe to patch at load; gate2 now does
	 * the real gating on count>=min(10).  No more delayed gate. */
	patch_save_gates();
	/* v52: let every captured frame past the data-process gate checks */
	patch_check_gates();
}

/* ------------------------------------------------------------ TA entries -- */

typedef long (*fn0_t)(void);
typedef long (*fn3_t)(void *, void *, uint32_t);

#define TA_INIT   0x4023b8UL
#define TA_INVOKE 0x402400UL
#define TA_UPDATE_DAC 0x41d9c8UL /* milan_update_dac_value(dac_array) */
#define TA_REG_ACCESS 0x41c400UL /* unified sensor register read/write */

static long ta_init(void)
{
	fprintf(stderr, "[host] ut_pf_fp_init() ...\n");
	return ((fn0_t)TA_INIT)();
}

static long ta_invoke(void *req, void *cmd, uint32_t len){
	/*
	 * The sensor reports ee_type=36 which fp_image_ee_para_init doesn't
	 * accept (valid set is {2..7,23,27..30,32..35}).  Clamp it to 35
	 * BEFORE the command executes so gf_algo_init sees the corrected value.
	 * g_config.ee_type is at absolute VADDR 0x9431fc.
	 */
	*(volatile uint32_t *)(uintptr_t)0x9431fcUL = 35;
	patch_algo_threshold(); /* v43: raise template_update_save_threshold 20->40 */
	{
		long r = ((fn3_t)TA_INVOKE)(req, cmd, len);
		/* v43a: the config is (re)written during init commands, so also
		 * enforce right after each command returns. */
		patch_algo_threshold();
		return r;
	}
}

/*
 * milan_update_dac_value(dac_array) at TA 0x41d9c8 rewrites the four sensor
 * analog-DAC registers (0x220/0x236/0x238/0x23a) from the expected halfwords
 * kept in the TA context (context base 0x982788, DAC array at +0xf4 =
 * 0x98287c, halfwords for regs [+0]=0x220, [+2]=0x236, [+4]=0x238,
 * [+6]=0x23a).  This is the exact function the online drift-compensation
 * (0x4246b0/0x424890) calls.  Unlike DETECT/INIT it does NOT re-run
 * gf_algo_init, so the in-progress enrollment and every calibration /
 * preprocess counter is preserved -- the DAC value is restored while the
 * algorithm state is left untouched.
 */
static long reprogram_dac(void)
{
	typedef long (*update_dac_t)(void *);
	update_dac_t fn = (update_dac_t)(uintptr_t)TA_UPDATE_DAC;
	void *arr = (void *)(uintptr_t)0x98287cUL;
	long r = fn(arr);

	fprintf(stderr, "[dac] milan_update_dac_value(%p) -> %ld\n", arr, r);
	return r;
}

/*
 * Request structure for the TA's unified sensor-register accessor at 0x41c400.
 * Field layout recovered from its disassembly:
 *   [+0x00] u16 register id
 *   [+0x04] u32 direction: 0 = read, 1 = write
 *   [+0x08] u16 mode/byte-selector (2 = halfword, used by every DAC access)
 *   [+0x10] x   pointer to the halfword (output for read, input for write)
 */
typedef struct {
	uint16_t reg;
	uint16_t _pad0;
	uint32_t rw;
	uint16_t mode;
	uint16_t _pad1;
	uint32_t _pad2;
	void *data;
} reg_req_t;

/* Read (rw=0) or write (rw=1) a single sensor register as a halfword.
 * Returns the accessor's status (0 = ok). */
static long sensor_reg(uint16_t reg, uint32_t rw, uint16_t *half)
{
	typedef long (*regfn_t)(reg_req_t *);
	regfn_t fn = (regfn_t)(uintptr_t)TA_REG_ACCESS;
	reg_req_t req;
	long r;

	memset(&req, 0, sizeof(req));
	req.reg = reg;
	req.rw = rw;
	req.mode = 2;
	req.data = half;
	r = fn(&req);
	return r;
}

/* Dump, for one tag, every piece of state relevant to the DAC drift: the
 * sensor-mode gate at context+64, the compensation flag byte, the event global,
 * and -- side by side -- the TA expected DAC halfwords and the values actually
 * held in the sensor registers 0x220/0x236/0x238/0x23a. */
static void dump_dac_state(const char *tag)
{
	uint32_t gate = *(volatile uint32_t *)(uintptr_t)0x9827c8UL;
	uint8_t flag = *(volatile uint8_t *)(uintptr_t)0x9828a4UL;
	uint32_t evt = *(volatile uint32_t *)(uintptr_t)0x8b9084UL;
	static const uint16_t dac_regs[4] = { 0x220, 0x236, 0x238, 0x23a };
	/* v64: the v63 write-back is OFF by default.
	 *
	 * Measured 2026-10-01 (goodix_v63.txt): at press 2 the sensor sits in
	 * its key-detect hold state with three of the four registers already
	 * equal to the context halfwords (0x236=00be, 0x238=00bd, 0x23a=00bc)
	 * and only 0x220 reading 0x0bd8 -- which is exactly the healthy
	 * first-wake value recorded back in v25 for this board.  v63 rewrote
	 * 0x220 to the context value 0x00bd and the very next IRQ failed
	 * gf_milan_check_sensor_dac_validity -> 1107.  The identical press-2
	 * state with NO write (v62) passes that check (v62's first 1107 is at
	 * press 4).
	 *
	 * => the write-back is itself what breaks the sensor, so it is now
	 * opt-in via DAC_FIX=1.  The dump stays unconditional (it is the only
	 * view we have of the context DAC halfwords vs the sensor). */
	int do_fix = getenv("DAC_FIX") != NULL;
	int i;

	fprintf(stderr, "[dacdump %s] gate@9827c8=0x%08x flag@9828a4=%u event@8b9084=%u fix=%d\n",
		tag, gate, flag, evt, do_fix);
	for (i = 0; i < 4; i++) {
		uint16_t expected =
			*(volatile uint16_t *)(uintptr_t)(0x98287cUL + i * 2);
		uint16_t actual = 0;
		long rr = sensor_reg(dac_regs[i], 0, &actual);

		if (do_fix && rr == 0 && expected != actual) {
			uint16_t e2 = expected, back = 0;
			long wr = sensor_reg(dac_regs[i], 1, &e2);
			long rr2 = sensor_reg(dac_regs[i], 0, &back);

			fprintf(stderr,
				"[dacfix %s] reg 0x%03x %04x->%04x (wr=%ld readback=%04x rr=%ld)\n",
				tag, dac_regs[i], actual, expected,
				wr, back, rr2);
		}
		fprintf(stderr,
			"[dacdump %s] reg 0x%03x expected=0x%04x actual=0x%04x (read %s)\n",
			tag, dac_regs[i], expected, actual,
			rr == 0 ? "ok" : "FAIL");
	}
}

/* The trustlet's own command-id -> GF_CMD_* name lookup. */
#define TA_CMD_NAME 0x40e080UL

static const char *name_of_cmd(uint32_t id)
{
	const char *(*fn)(uint32_t) = (const char *(*)(uint32_t))TA_CMD_NAME;
	const char *n = fn(id);

	return n ? n : "(null)";
}

/* Most of the trustlet's state lives in its own .bss; dumping it is the
 * quickest way to see which global a failing code path depends on. */
static void dump_mem(uint64_t addr, unsigned len)
{
	unsigned i, j;

	for (i = 0; i < len; i += 16) {
		fprintf(stderr, "  %08llx:", (unsigned long long)(addr + i));
		for (j = 0; j < 16 && i + j < len; j++)
			fprintf(stderr, " %02x",
				*(volatile uint8_t *)(uintptr_t)(addr + i + j));
		fprintf(stderr, "\n");
	}
}

/* v35: dump everything the SAVE path touches -- group_id global (0x94c4c0),
 * finger list head pointer (0x94c4d0), the raw BSS around both, and the
 * slot table pointer (0x94b4F0).  The TA's SAVE handler (0x40afa8) and its
 * response serializer read exactly this region. */
static void dump_finger_state(const char *tag)
{
	uint64_t head = *(volatile uint64_t *)0x94c4d0UL;
	uint64_t stab = *(volatile uint64_t *)0x94b4F0UL;

	fprintf(stderr,
		"[fingerstate %s] gid=%u head=0x%llx slot=0x%llx\n",
		tag,
		*(volatile uint32_t *)0x94c4c0UL,
		(unsigned long long)head, (unsigned long long)stab);
	fprintf(stderr, "[fingerstate %s] BSS 0x94c4c0..0x94c540:\n", tag);
	dump_mem(0x94c4c0, 0x80);
	if (head) {
		fprintf(stderr, "[fingerstate %s] first node (64 bytes):\n", tag);
		dump_mem(head, 64);
	}
	if (stab) {
		fprintf(stderr, "[fingerstate %s] slot table (32 bytes):\n", tag);
		dump_mem(stab, 32);
	}
	/* v68: gf_fingerlist_get_finger_pdu (0x41b664) and
	 * get_finger_temp_info_size (0x41b430) both obtain their "algo finger
	 * template" argument from a helper at 0x41afd0 that just returns the
	 * CONSTANT 0x940d00, and then do `ldr x3,[x24,#16]` / `ldr x0,[x0,#16]`
	 * on it.  In the shipped image 0x940d00 is a plain int32 table
	 * (ef020000 3afdffff 4c040000 2f040000 af010000 26040000 ...), so that
	 * 8-byte load yields 0x426000001af -- exactly the garbage pointer seen
	 * in the v66 SEGV.  Watch the region across the run: if it never
	 * turns into a pointer, the SAVE/PDU path is structurally dead in this
	 * TA build. */
	fprintf(stderr, "[fingerstate %s] global 0x940d00 (pdu/sizeof src) 0x60:\n",
		tag);
	dump_mem(0x940d00, 0x60);
	fprintf(stderr, "[fingerstate %s]   [0x940d10]=0x%llx [0x940d20]=0x%llx\n",
		tag,
		(unsigned long long)*(volatile uint64_t *)(uintptr_t)(0x940d00UL + 0x10),
		(unsigned long long)*(volatile uint64_t *)(uintptr_t)(0x940d00UL + 0x20));
}

/* Scan anonymous readable memory regions for a 4-byte pattern.  Returns the
 * first match address that is not the known BSS global at 0x94c4c0, or 0. */
static uint64_t scan_mem_for_u32(uint32_t needle)
{
	FILE *f;
	char line[512];
	uint8_t pat[4];
	uint64_t found = 0;

	pat[0] = needle & 0xff;
	pat[1] = (needle >> 8) & 0xff;
	pat[2] = (needle >> 16) & 0xff;
	pat[3] = (needle >> 24) & 0xff;

	f = fopen("/proc/self/maps", "r");
	if (!f)
		return 0;

	while (fgets(line, sizeof(line), f)) {
		uint64_t start, end;
		char perms[8], path[256];
		uint8_t *p;
		size_t len, i;
		int n;

		path[0] = 0;
		n = sscanf(line, "%lx-%lx %7s %*x %*x:%*x %*d %255s",
			   &start, &end, perms, path);
		if (n < 3)
			continue;
		if (n >= 4 && path[0] && strcmp(path, "[heap]") != 0 &&
		    strcmp(path, "[stack]") != 0)
			continue;
		if (perms[0] != 'r')
			continue;
		/* skip stack to avoid local-variable copies of group_id */
		if (start >= 0xffff00000000UL)
			continue;
		len = end - start;
		if (len > 256 * 1024 * 1024)
			continue;
		fprintf(stderr, "[scan] region %#llx-%#llx (%s)\n",
			(unsigned long long)start, (unsigned long long)end,
			path[0] ? path : "anon");
		p = (uint8_t *)(uintptr_t)start;
		for (i = 0; i + 4 <= len; i++) {
			uint64_t addr = start + i;
			if (addr == 0x94c4c0UL)
				continue;  /* skip the known global */
			if (p[i] == pat[0] && p[i+1] == pat[1] &&
			    p[i+2] == pat[2] && p[i+3] == pat[3]) {
				found = addr;
				goto out;
			}
		}
	}
out:
	fclose(f);
	return found;
}

static uint64_t find_heap_pointer_in_bss(void)
{
	FILE *fp = fopen("/proc/self/maps", "r");
	if (!fp) return 0;
	uint64_t heap_start = 0, heap_end = 0;
	char line[512], perms[8], path[256];
	uint64_t start, end;
	int n;
	while (fgets(line, sizeof(line), fp)) {
		path[0] = 0;
		n = sscanf(line, "%lx-%lx %7s %*x %*x:%*x %*d %255s",
			   &start, &end, perms, path);
		if (n >= 4 && path[0] && strcmp(path, "[heap]") == 0) {
			heap_start = start;
			heap_end = end;
			break;
		}
	}
	fclose(fp);
	if (!heap_start) return 0;
	fprintf(stderr, "[scan] heap range %#llx-%#llx\n",
		(unsigned long long)heap_start, (unsigned long long)heap_end);
	uint64_t bss = (uint64_t)TA_BASE + 0x544000;
	uint64_t bss_end = (uint64_t)TA_BASE + 0x61f000;
	int count = 0;
	for (uint64_t a = bss; a + 8 <= bss_end; a += 8) {
		uint64_t v = *(volatile uint64_t *)(uintptr_t)a;
		if (v >= heap_start && v < heap_end) {
			fprintf(stderr, "[scan] heap ptr at BSS+0x%llx -> %#llx\n",
				(unsigned long long)(a - (uint64_t)TA_BASE),
				(unsigned long long)v);
			dump_mem(v, 128);
			count++;
			if (count > 10) break;
		}
	}
	return 0;
}

/* Print whatever the trustlet has written into its own log ring. */
/* v74: machine-readable authentication result.
 *
 * The trustlet's own log ring (0x943420, cursor at 0x943414) is a plain
 * rotating byte buffer that this process can read directly.  On a successful
 * match the trustlet logs
 *     [gf_ta][gf_ta_get_user_id] get user id **<n>**.
 * (gf_ta_get_user_id is only reached when a template matched), immediately
 * followed by gf_generate_hmac_authenticate.  Nothing in the IRQ response
 * distinguishes match from no-match -- status is 0 for every captured frame --
 * so this log marker is the reliable signal.
 *
 * ta_log_mark() snapshots the cursor; ta_log_since() scans only what was
 * written after that snapshot, so stale entries from earlier attempts cannot
 * produce a false positive. */
static uint32_t ta_log_mark(void)
{
	return *(volatile uint32_t *)(uintptr_t)TA_LOG_POS_ADDR;
}

static int ta_log_since(uint32_t from_pos, const char *needle)
{
	const unsigned char *ring = (const unsigned char *)(uintptr_t)TA_LOG_RING_ADDR;
	uint32_t to = *(volatile uint32_t *)(uintptr_t)TA_LOG_POS_ADDR;
	uint32_t n = to - from_pos, i;
	char buf[TA_LOG_RING_SIZE + 1];

	if (n == 0)
		return 0;
	if (n > TA_LOG_RING_SIZE)
		n = TA_LOG_RING_SIZE;
	for (i = 0; i < n; i++)
		buf[i] = (char)ring[(from_pos + i) % TA_LOG_RING_SIZE];
	buf[n] = '\0';
	return strstr(buf, needle) != NULL;
}

/* v77: per-attempt diagnostics.
 *
 * The IRQ response carries no match verdict, so the only place the trustlet
 * explains itself is its own log ring.  Copy the delta written since 'from'
 * and count the markers that matter, so every press prints WHY it failed:
 *   get user id                -> matched (success path)
 *   GF_ERROR_NOT_MATCH  (1006) -> compared, did not match
 *   GF_ERROR_ALGO_FAKE  (1119) -> ASP anti-spoof rejected the sample
 *   GF_ERROR_NEED_RESET (1107) -> DAC drift, frame never usable
 *   gf_algo_authenticate_enhance / gf_algo_asp_sample_asp -> stage reached
 */
static unsigned ta_log_since_text(uint32_t from, char *buf, unsigned cap)
{
	const unsigned char *ring = (const unsigned char *)(uintptr_t)TA_LOG_RING_ADDR;
	uint32_t to = *(volatile uint32_t *)(uintptr_t)TA_LOG_POS_ADDR;
	uint32_t n = to - from, i;

	if (n > TA_LOG_RING_SIZE)
		n = TA_LOG_RING_SIZE;
	if (n >= cap)
		n = cap - 1;
	for (i = 0; i < n; i++)
		buf[i] = (char)ring[(from + i) % TA_LOG_RING_SIZE];
	buf[n] = '\0';
	return n;
}

static int count_sub(const char *hay, const char *needle)
{
	int n = 0;
	size_t nl = strlen(needle);

	while (hay && (hay = strstr(hay, needle)) != NULL) {
		n++;
		hay += nl;
	}
	return n;
}

static void dump_attempt_verdict(uint32_t mark, int matched)
{
	static char dl[TA_LOG_RING_SIZE + 1];

	ta_log_since_text(mark, dl, sizeof(dl));
	fprintf(stderr,
		"[auth] verdict: %s  not_match=%d  algo_fake=%d  dac1107=%d"
		"  enhance=%d  asp=%d  (reject_num line: ",
		matched ? "MATCH" : "no-match",
		count_sub(dl, "GF_ERROR_NOT_MATCH"),
		count_sub(dl, "GF_ERROR_ALGO_FAKE"),
		count_sub(dl, "GF_ERROR_NEED_RESET"),
		count_sub(dl, "gf_algo_authenticate_enhance"),
		count_sub(dl, "gf_algo_asp_sample_asp"));
	{
		const char *p = strstr(dl, "g_reject_num before");

		if (p) {
			const char *e = strchr(p, '\n');
			int len = e ? (int)(e - p) : 40;

			if (len > 60)
				len = 60;
			fwrite(p, 1, len, stderr);
		} else {
			fputs("-", stderr);
		}
	}
	fprintf(stderr, ")\n");
}

static void dump_ta_log(void){
	uint32_t pos = *(volatile uint32_t *)(uintptr_t)TA_LOG_POS_ADDR;
	const unsigned char *ring = (const unsigned char *)(uintptr_t)TA_LOG_RING_ADDR;
	unsigned i, printed = 0;

	fprintf(stderr, "[ta-log] ring pos=%u\n", pos);
	for (i = 0; i < TA_LOG_RING_SIZE; i++) {
		unsigned char c = ring[i];

		if (c >= 0x20 && c < 0x7f) {
			fputc(c, stderr);
			printed = 1;
		} else if (printed) {
			fputc('\n', stderr);
			printed = 0;
		}
	}
	if (printed)
		fputc('\n', stderr);
}

/* ------------------------------------------------------------------ main -- */

static void sensor_power_cycle(void)
{
	uint32_t m;

	if (g_spifd < 0)
		return;
	m = GOODIX_FP_POWER_OFF;
	ioctl(g_spifd, GOODIX_FP_IOC_POWER, &m);
	usleep(200 * 1000);
	m = GOODIX_FP_POWER_ON;
	ioctl(g_spifd, GOODIX_FP_IOC_POWER, &m);
	usleep(200 * 1000);
}

/* Pulse the sensor hardware reset line (GPIO216) via the kernel RESET ioctl.
 * This is exactly gf_hal_reset_chip() in the production HAL: the TA's DAC
 * validity failure logs "need to reset chip", after which the host pulses
 * reset and re-enters the wake->capture sequence.  No power off/on, no
 * INIT / algo re-init, so enroll progress is preserved. */
static void sensor_reset_chip(void)
{
	if (g_spifd < 0)
		return;
	if (ioctl(g_spifd, GOODIX_FP_IOC_RESET, 0) < 0)
		fprintf(stderr, "[enroll] RESET ioctl failed\n");
	usleep(5 * 1000);
}

/*
 * Re-run the stock CA's hardware bring-up chain:
 *   GF_CMD_DETECT(1000) -> GF_CMD_INIT(1001) -> GF_CMD_INIT_FINISHED(1005)
 *
 * This is what gf_hal_reinit() does after a chip reset.  Crucially INIT calls
 * milan_common_update_dac_register_from_otp(), which re-reads the per-chip OTP
 * calibration and reprograms the sensor's analog DAC registers (0x236/0x238/
 * 0x23a).  A bare power cycle or reset pulse leaves those registers at their
 * power-on default, so gf_milan_check_sensor_dac_validity() keeps failing with
 * NEED_RESET(1107) no matter how long we settle -- the DAC is a value, not a
 * thermal state.  Re-running this chain restores it.
 *
 * req must point to >=256 bytes, cmdbuf to >=cbsize bytes (the same buffers the
 * caller already uses).  Returns the DETECT invoke result.
 */
/* v73: force the trustlet's operation queue to AUTHENTICATE_IMAGE.
 *
 * gf_state_get_operation_array (0x62df10) reads a 10-entry u32 array at
 * 0x8b9088, scanning index 9 down to 0 and treating 0x40 as an empty slot;
 * when every slot is 0x40 it falls back to gf_state_get_default_operation,
 * which resolves to OPERATION_HOME_KEY -- so every touch was handled as a
 * navigation gesture and gf_algo_authenticate never ran even though the
 * templates had loaded fine.  OPERATION_AUTHENTICATE_IMAGE == 1 (observed as
 * operation_code=1 in the v0 auth log).  The array is plain trustlet .data
 * mapped into this process, so writing it directly is enough. */
static void set_auth_operation_queue(void)
{
	volatile uint32_t *arr = (volatile uint32_t *)(uintptr_t)0x8b9088UL;
	int i;

	for (i = 0; i < 10; i++)
		arr[i] = 0x40;		/* OPERATION_NONE / empty */
	arr[0] = 1;			/* OPERATION_AUTHENTICATE_IMAGE */
}

/* v82: arm an AUTHENTICATE session (used by both `auth` and the daemon).
 * gf_hal_common_authenticate builds a 120-byte payload with
 *   [0x60] = arg2 (u32) / [0x68] = arg1 (u64 pointer) / [0x70] = 0xFFFFFFFF
 * and the dispatcher hands the handler a payload at (host buffer + 0x10), so
 * those land at cmdbuf +0x70 / +0x78 / +0x80.  Both offsets are written for
 * safety. */
static void arm_authenticate(uint8_t *req, uint8_t *cmdbuf, size_t cbsize)
{
	memset(cmdbuf, 0, cbsize);
	*(uint32_t *)cmdbuf = 1010;			/* GF_CMD_AUTHENTICATE */
	*(uint32_t *)(cmdbuf + 0x60) = 0;
	*(uint64_t *)(cmdbuf + 0x68) = 0;
	*(uint32_t *)(cmdbuf + 0x70) = 0;
	*(uint64_t *)(cmdbuf + 0x78) = 0;
	*(uint32_t *)(cmdbuf + 0x80) = 0xFFFFFFFFu;
	ta_invoke(req, cmdbuf, cbsize);
	set_auth_operation_queue();
}

static long bringup_chain(uint8_t *req, uint8_t *cmdbuf, size_t cbsize)
{
	memset(req, 0, 256);
	*(uint32_t *)(req + 8) = 1; /* route = main */

	memset(cmdbuf, 0, cbsize);
	*(uint32_t *)cmdbuf = 1000;
	ta_invoke(req, cmdbuf, cbsize);
	fprintf(stderr, "[reinit] DETECT status=%u\n", *(uint32_t *)req);

	memset(cmdbuf, 0, cbsize);
	*(uint32_t *)cmdbuf = 1001;
	ta_invoke(req, cmdbuf, cbsize);
	fprintf(stderr, "[reinit] INIT   status=%u\n", *(uint32_t *)req);

	memset(cmdbuf, 0, cbsize);
	*(uint32_t *)cmdbuf = 1005;
	ta_invoke(req, cmdbuf, cbsize);
	fprintf(stderr, "[reinit] INIT_FINISHED status=%u\n", *(uint32_t *)req);
	return 0;
}

/*
 * gf_hal_common_resume_enroll() invokes GF_CMD_RESUME_ENROLL(1091) with a
 * zeroed ~100-byte buffer after reinit, which calls gf_hw_data_sample_resume()
 * to re-arm the sensor's continuous data sampling for the in-progress
 * enrollment.  The algo/enroll context (accumulated templates) lives in a
 * separate user context that the DETECT/INIT chain does not tear down.
 */
static long resume_enroll(uint8_t *req, uint8_t *cmdbuf, size_t cbsize)
{
	memset(req, 0, 256);
	*(uint32_t *)(req + 8) = 1;
	memset(cmdbuf, 0, cbsize);
	*(uint32_t *)cmdbuf = 1091; /* GF_CMD_RESUME_ENROLL */
	ta_invoke(req, cmdbuf, cbsize);
	fprintf(stderr, "[reinit] RESUME_ENROLL status=%u\n", *(uint32_t *)req);
	return *(uint32_t *)req;
}

static void usage(const char *p)
{
	fprintf(stderr, "usage: %s <ta-file> <cmd> [args]\n", p);
	fprintf(stderr, "  init            run ut_pf_fp_init()\n");
	fprintf(stderr, "  invoke <a> <b>  call ut_pf_fp_invoke_command with a zeroed request\n");
	fprintf(stderr, "                  (a = u32 at req+0, b = u32 at req+8, cmd id = 1000)\n");
	fprintf(stderr, "  enroll [n]      interactive enroll loop (n iterations, def 30)\n");
	fprintf(stderr, "  spi             raw sensor read of register 0x0000\n");
	fprintf(stderr, "  power           power-cycle the sensor\n");
}

int main(int argc, char **argv)
{
	const char *ta;

	if (argc < 3) {
		usage(argv[0]);
		return 2;
	}
	ta = argv[1];
	ts_init();

	if (getenv("GOODIXTA_QUIET"))
		g_verbose = 0;

	if (!strcmp(argv[2], "spi") || !strcmp(argv[2], "power") ||
	    !strcmp(argv[2], "init") || !strcmp(argv[2], "invoke") ||
	    !strcmp(argv[2], "seq") || !strcmp(argv[2], "raw") ||
	    !strcmp(argv[2], "names") || !strcmp(argv[2], "enroll") ||
	    !strcmp(argv[2], "auth") ||
	    !strcmp(argv[2], "d")) {
		g_spifd = open(SENSOR_DEV, O_RDWR);
		if (g_spifd < 0) {
			fprintf(stderr, "[host] cannot open %s: %s\n", SENSOR_DEV, strerror(errno));
			/* v62: without the SPI bridge every TA call runs in a
			 * no-sensor state and the IRQ path SEGVs (pc=0x42a2a0 in
			 * the v61 run where the device node was root-only and the
			 * local user could not open it).  Fail loudly instead of
			 * crashing mid-enroll. */
			if (!strcmp(argv[2], "enroll")) {
				fprintf(stderr, "[host] sensor SPI not accessible (run as root, or fix /dev/goodix_fp permissions)\n");
				return 1;
			}
		}
	}

	if (!strcmp(argv[2], "power")) {
		sensor_power_cycle();
		fprintf(stderr, "[host] power cycled\n");
		return 0;
	}

	if (!strcmp(argv[2], "spi")) {
		uint8_t hdr[3] = { 0xf0, 0x00, 0x00 };
		uint8_t tx[17], rx[17];
		int i;

		memset(tx, 0xff, sizeof(tx));
		memset(rx, 0xcc, sizeof(rx));
		tx[0] = 0xf1;
		sensor_power_cycle();
		ut_pf_spi_send_and_receive(hdr, rx, 3, 3, NULL, 0);
		memset(rx, 0xcc, sizeof(rx));
		ut_pf_spi_send_and_receive(tx, rx, 17, 17, NULL, 0);
		fprintf(stderr, "[host] reg 0x0000:");
		for (i = 0; i < 17; i++)
			fprintf(stderr, " %02x", rx[i]);
		fprintf(stderr, "\n");
		return 0;
	}

	load_ta(ta);

	/*
	 * The CA power-cycles the sensor before it asks the trustlet to do
	 * anything, so the chip always starts from a known state.
	 */
	if (!strcmp(argv[2], "invoke") || !strcmp(argv[2], "seq") ||
	    !strcmp(argv[2], "raw") || !strcmp(argv[2], "enroll") ||
	    !strcmp(argv[2], "auth")) {
		sensor_power_cycle();
		g_spi_n = 0;
	}

	if (!strcmp(argv[2], "init")) {
		long r = ta_init();

		dump_ta_log();
		return (int)r & 0xff;
	}

	if (!strcmp(argv[2], "invoke")) {
		/*
		 * ut_pf_fp_invoke_command(req, cmd, len):
		 *   req[0]  operation, req[4] and req[8] select the sub-route
		 *   cmd[0]  u32 command id, payload from cmd+0x10
		 */
		uint8_t req[64];
		uint8_t cmdbuf[4096];
		uint32_t op0 = argc > 3 ? (uint32_t)strtoul(argv[3], NULL, 0) : 0;
		uint32_t op8 = argc > 4 ? (uint32_t)strtoul(argv[4], NULL, 0) : 1;
		uint32_t op4 = argc > 5 ? (uint32_t)strtoul(argv[5], NULL, 0) : 0;
		uint32_t id = argc > 6 ? (uint32_t)strtoul(argv[6], NULL, 0) : 0;
		long ret;

		ta_init();
		memset(req, 0, sizeof(req));
		memset(cmdbuf, 0, sizeof(cmdbuf));
		*(uint32_t *)(req + 0) = op0;
		*(uint32_t *)(req + 4) = op4;
		*(uint32_t *)(req + 8) = op8;
		*(uint32_t *)cmdbuf = id;
		fprintf(stderr, "[host] invoke req{0=%u,4=%u,8=%u} id=%u\n",
			op0, op4, op8, id);
		ret = ta_invoke(req, cmdbuf, sizeof(cmdbuf));
		fprintf(stderr, "[host] invoke returned %ld (%#lx)\n", ret, (unsigned long)ret);
		fprintf(stderr, "[host] req[0] (status) = %u\n", *(uint32_t *)req);
		dump_ta_log();
		return (int)ret & 0xff;
	}

	if (!strcmp(argv[2], "seq")) {
		/*
		 * Run a list of command ids in order, in one trustlet context, the
		 * way the CA drives the bring-up chain (DETECT_SENSOR, INIT,
		 * DOWNLOAD_FW, DOWNLOAD_CFG, INIT_FINISHED, ...).
		 */
		uint8_t req[64];
		uint8_t cmdbuf[16384];
		int i;

		ta_init();
		for (i = 3; i < argc; i++) {
			uint32_t id = (uint32_t)strtoul(argv[i], NULL, 0);
			uint32_t route = 1;
			char *at = strchr(argv[i], '@');
			int attempt;
			int need_challenge = (i + 1 < argc &&
					      !strcmp(argv[i + 1], "challenge"));

			/* skip non-command keywords */
			if (!id && !strcmp(argv[i], "challenge"))
				continue;

			/*
			 * A command may carry an explicit route: "<id>@<route>".
			 * The trustlet dispatches on req[8]: 1 = main, 2 = user,
			 * 3 = test, 4 = dump.  The GF_CMD_TEST_* family is only
			 * reachable through route 3 and GF_CMD_DUMP_* through route 4;
			 * sending them on route 1 gets
			 *   "invalid parameters cmd_id=GF_CMD_TEST_..., cmd_id_code=1064"
			 * with status 1070, which is what we saw for every TEST/DUMP id.
			 */
			if (at)
				route = (uint32_t)strtoul(at + 1, NULL, 0);

			for (attempt = 0; attempt < 2; attempt++) {
				if (id != 1007)
					memset(cmdbuf, 0, sizeof(cmdbuf));
				*(uint32_t *)(req + 8) = route;
				*(uint32_t *)cmdbuf = id;
				/*
				 * The Goodix CA generates an 8-byte random challenge
				 * and embeds it in the command buffer at offset 0x6b
				 * before calling PRE_ENROLL; ENROLL then reads it
				 * back and compares with the stored copy.
				 */
				if (need_challenge) {
					/* generate random challenge at cmdbuf+0x6b */
					int fd_r = open("/dev/urandom", O_RDONLY);
					if (fd_r >= 0) {
						read(fd_r, cmdbuf + 0x6b, 8);
						close(fd_r);
					}
				}
				if (id == 1007) {
					fprintf(stderr, "    [pre-enroll] cmdbuf[0..128]:\n");
					{ int j;
					for (j = 0; j < 128; j += 16) {
						fprintf(stderr, "      %03x:", j);
						{ int k; for (k = 0; k < 16; k++)
							fprintf(stderr, " %02x", cmdbuf[j + k]); }
						fprintf(stderr, "\n");
					} }
					fprintf(stderr, "    [pre-enroll] BSS+1248=%016lx\n",
						*(volatile unsigned long *)0x94b4E0UL);
				}
				ta_invoke(req, cmdbuf, sizeof(cmdbuf));
				fprintf(stderr, "    status=%u  cmdbuf[0x6b..0x73]:",
					*(uint32_t *)req);
				{
					int j;
					for (j = 0x6b; j < 0x73; j++)
						fprintf(stderr, " %02x", cmdbuf[j]);
				}
				fprintf(stderr, "\n");
				if (id == 1006 || id == 1007)
					fprintf(stderr, "    BSS+1248 after: %016lx\n",
						*(volatile unsigned long *)0x94b4E0UL);
				/*
				 * PRE_ENROLL writes the challenge at cmdbuf+0x60;
				 * ENROLL reads it from cmdbuf+0x6b.  The CA copies
				 * it between these offsets after PRE_ENROLL returns.
				 */
				if (id == 1006 && !*(uint32_t *)req) {
					/*
					 * PRE_ENROLL stores the challenge in BSS+1248.
					 * ENROLL reads it from two places:
					 *   cmdbuf+0x60 (u32, passed to 4393b8 validator)
					 *   cmdbuf+0x6b (u64, compared with BSS+1248)
					 * Copy from BSS to both slots.
					 */
					uint64_t ch = *(volatile uint64_t *)0x94b4E0UL;
					*(uint32_t *)(cmdbuf + 0x60) = 0; /* v50: real gid, TA gf_ta_enroll reads +0x60 as GID */
					memcpy(cmdbuf + 0x6b, &ch, 8);
					fprintf(stderr, "    [gid=0 -> cmdbuf+0x60; challenge -> cmdbuf+0x6b]\n");
				}
				if (*(uint32_t *)req != 1062)
					break;
				usleep(200 * 1000);
			}
		}
		dump_ta_log();
		if (getenv("TA_DUMP")) {
			char spec[64];
			char *colon;
			uint64_t a;
			unsigned n;

			snprintf(spec, sizeof(spec), "%s", getenv("TA_DUMP"));
			colon = strchr(spec, ':');
			a = strtoull(spec, NULL, 0);
			n = colon ? (unsigned)strtoul(colon + 1, NULL, 0) : 64;
			fprintf(stderr, "[peek] %#llx..%#llx\n",
				(unsigned long long)a, (unsigned long long)(a + n));
			dump_mem(a, n);
		}
		return 0;
	}

	if (!strcmp(argv[2], "d")) {
		/*
		 * v82: resident fingerprint daemon.
		 *
		 * Every other path (auth/verify) re-initialises the trustlet on each
		 * invocation, which costs 7-10 s AND rebuilds the sensor/analog state
		 * from scratch each time -- repeatedly wiping the authentication
		 * context, which is why the unattended loop could never reach
		 * gf_ta_get_user_id even after the ASP was bypassed.
		 *
		 * This mode brings the trustlet up ONCE and then keeps cycling the
		 * capture loop forever.  Whenever a frame matches, it stamps
		 * /tmp/goodix-fp.state so the PAM client (goodix-fp-pam) only has to
		 * read that file -- no IPC, no start-up cost, no per-call re-arming.
		 */
		uint8_t req[256];
		uint8_t cmdbuf[16384];
		uint8_t irqbuf[0x50000];
		const char *state = "/tmp/goodix-fp.state";
		time_t last_match = 0;
		time_t last_heavy = 0;
		unsigned long rounds = 0, matches = 0, frames = 0, heavy = 0;
		int fd_r;

		ta_init();
		memset(req, 0, sizeof(req));
		memset(cmdbuf, 0, sizeof(cmdbuf));
		memset(irqbuf, 0, sizeof(irqbuf));
		*(uint32_t *)(req + 8) = 1;

		bringup_chain(req, cmdbuf, sizeof(cmdbuf));

		/* PRE_ENROLL + challenge (trustlet stores it at BSS+1248) */
		fd_r = open("/dev/urandom", O_RDONLY);
		if (fd_r >= 0) { read(fd_r, cmdbuf + 0x6b, 8); close(fd_r); }
		*(uint32_t *)cmdbuf = 1006;
		ta_invoke(req, cmdbuf, sizeof(cmdbuf));
		fprintf(stderr, "[fp] PRE_ENROLL status=%u\n", *(uint32_t *)req);
		{
			uint64_t ch = *(volatile uint64_t *)0x94b4E0UL;

			*(uint32_t *)(cmdbuf + 0x60) = 0;
			memcpy(cmdbuf + 0x6b, &ch, 8);
		}

		memset(cmdbuf, 0, sizeof(cmdbuf));
		*(uint32_t *)cmdbuf = 1014;
		*(uint32_t *)(cmdbuf + 0x60) = 0;
		*(uint32_t *)(cmdbuf + 0x70) = 0;
		ta_invoke(req, cmdbuf, sizeof(cmdbuf));
		fprintf(stderr, "[fp] SET_ACTIVE_GROUP status=%u\n", *(uint32_t *)req);
		*(uint32_t *)cmdbuf = 1017;
		ta_invoke(req, cmdbuf, sizeof(cmdbuf));
		fprintf(stderr, "[fp] SCREEN_ON status=%u\n", *(uint32_t *)req);

		arm_authenticate(req, cmdbuf, sizeof(cmdbuf));
		fprintf(stderr, "[fp] daemon up: watching the sensor (state=%s)\n",
			state);

		for (;;) {
			int polln = 0, got = 0, n1107 = 0, matched = 0;
			uint32_t irq_st = 0, irq_type = 0, lm;

			lm = ta_log_mark();
			set_auth_operation_queue();
			do {
				*(volatile uint32_t *)(uintptr_t)0x982790UL = 2;
				*(uint32_t *)(irqbuf + 0x70) = 2;
				*(uint32_t *)irqbuf = 1016;
				ta_invoke(req, irqbuf, sizeof(irqbuf));
				irq_st = *(uint32_t *)req;
				irq_type = *(uint32_t *)(irqbuf + 0x70);
				if (irq_st == 1107) {
					n1107++;
					fprintf(stderr, "[fp] NEED_RESET(1107) #%d\n", n1107);
					/* Rate-limit the power cycle.  The sensor's DAC drifts
					 * by itself and comes back on its own; cycling the rail
					 * on every drift hammers the platform -- an unthrottled
					 * daemon doing this is the prime suspect for the
					 * 2026-10-01 20:55 system hang.  One heavy recovery per
					 * 30 s at most; between them just wait it out. */
					if (n1107 >= 3 && time(NULL) - last_heavy >= 30) {
						last_heavy = time(NULL);
						heavy++;
						fprintf(stderr,
							"[fp] heavy recovery #%lu\n", heavy);
						sensor_power_cycle();
						bringup_chain(req, cmdbuf, sizeof(cmdbuf));
						memset(cmdbuf, 0, sizeof(cmdbuf));
						*(uint32_t *)cmdbuf = 1014;
						*(uint32_t *)(cmdbuf + 0x60) = 0;
						ta_invoke(req, cmdbuf, sizeof(cmdbuf));
						*(uint32_t *)cmdbuf = 1017;
						ta_invoke(req, cmdbuf, sizeof(cmdbuf));
						arm_authenticate(req, cmdbuf, sizeof(cmdbuf));
					} else {
						sensor_reset_chip();
					}
					*(volatile uint32_t *)(uintptr_t)0x982790UL = 2;
					*(uint32_t *)(irqbuf + 0x70) = 2;
					usleep(300000);
				} else if (irq_type & 0x80) {
					got = 1;
				} else {
					usleep(150000);
				}
				polln++;
			} while (!got && polln < 20);

			rounds++;
			if (got) {
				frames++;
				matched = ta_log_since(lm, "get user id");
				if (matched) {
					FILE *sf = fopen(state, "w");

					if (sf) {
						fprintf(sf, "%ld %lu\n", (long)time(NULL),
							++matches);
						fclose(sf);
					}
					last_match = time(NULL);
					fprintf(stderr,
						"\n[fp] ===== MATCH #%lu (round %lu)! =====\n\n",
						matches, rounds);
				}
			}
			if ((rounds & 0x3f) == 0)
				fprintf(stderr,
					"[fp] rounds=%lu frames=%lu matches=%lu heavy=%lu"
					" last=%lds ago\n",
					rounds, frames, matches, heavy,
					last_match ? (long)(time(NULL) - last_match) : -1);

			/* operator-like rhythm so the trustlet does not reject every
			 * frame with TOO_FAST (1094). */
			usleep(1500000);
		}
	}

	if (!strcmp(argv[2], "auth")) {
		/*
		 * v72: authentication proof-of-life.  Bring the sensor up, let the
		 * trustlet load the persisted finger templates (finger_0_*.so) into
		 * its fingerlist, arm an authenticate session, then feed
		 * finger-down IRQs and report everything the trustlet says.
		 *
		 * Field mapping: the trustlet dispatcher hands every command handler
		 * a payload pointer at (host buffer + 0x10) -- the same convention
		 * that made SAVE need cmdbuf+0x70 for gid -- so a payload field at
		 * offset X lives at cmdbuf + X + 0x10.  libgf_hal's
		 * gf_hal_common_authenticate builds a 120-byte payload with
		 *   [0x60] = arg2 (u32) / [0x68] = arg1 (u64 ptr) / [0x70] = -1
		 * We write those at both the shifted and unshifted offsets so either
		 * convention resolves.
		 *
		 * Usage: auth [max_iterations]
		 */
		uint8_t req[256];
		uint8_t cmdbuf[16384];
		uint8_t irqbuf[0x50000];
		int max_iter = argc > 3 ? (int)strtol(argv[3], NULL, 0) : 10;
		int iter;
		int matched_total = 0;
		int verify_mode = getenv("FP_VERIFY") != NULL;
		/* FP_VERIFY: the sensor hands back spurious IRQ edges, so a
		 * fixed iteration count can burn through in 2 seconds and the
		 * caller never gets a chance to place a finger.  Run against a
		 * wall-clock budget instead (FP_VERIFY_SECS, default 12s). */
		time_t t0 = time(NULL);
		int budget = getenv("FP_VERIFY_SECS")
			? atoi(getenv("FP_VERIFY_SECS")) : 20;

		ta_init();
		memset(req, 0, sizeof(req));
		memset(cmdbuf, 0, sizeof(cmdbuf));
		memset(irqbuf, 0, sizeof(irqbuf));
		*(uint32_t *)(req + 8) = 1;

		bringup_chain(req, cmdbuf, sizeof(cmdbuf));

		/* PRE_ENROLL + challenge (the trustlet stores it at BSS+1248) */
		{
			int fd_r = open("/dev/urandom", O_RDONLY);

			if (fd_r >= 0) { read(fd_r, cmdbuf + 0x6b, 8); close(fd_r); }
		}
		*(uint32_t *)cmdbuf = 1006;
		ta_invoke(req, cmdbuf, sizeof(cmdbuf));
		fprintf(stderr, "[auth] PRE_ENROLL status=%u\n", *(uint32_t *)req);
		{
			uint64_t ch = *(volatile uint64_t *)0x94b4E0UL;

			*(uint32_t *)(cmdbuf + 0x60) = 0;
			memcpy(cmdbuf + 0x6b, &ch, 8);
		}

		memset(cmdbuf, 0, sizeof(cmdbuf));
		*(uint32_t *)cmdbuf = 1014;		/* SET_ACTIVE_GROUP */
		*(uint32_t *)(cmdbuf + 0x60) = 0;	/* gid, unshifted */
		*(uint32_t *)(cmdbuf + 0x70) = 0;	/* gid, shifted */
		ta_invoke(req, cmdbuf, sizeof(cmdbuf));
		fprintf(stderr, "[auth] SET_ACTIVE_GROUP status=%u\n", *(uint32_t *)req);
		dump_finger_state("auth-post-SET_ACTIVE_GROUP");

		*(uint32_t *)cmdbuf = 1017;		/* SCREEN_ON */
		ta_invoke(req, cmdbuf, sizeof(cmdbuf));
		fprintf(stderr, "[auth] SCREEN_ON status=%u\n", *(uint32_t *)req);

		memset(cmdbuf, 0, sizeof(cmdbuf));
		*(uint32_t *)cmdbuf = 1010;		/* AUTHENTICATE */
		*(uint32_t *)(cmdbuf + 0x60) = 0;
		*(uint64_t *)(cmdbuf + 0x68) = 0;
		*(uint32_t *)(cmdbuf + 0x70) = 0;
		*(uint64_t *)(cmdbuf + 0x78) = 0;
		*(uint32_t *)(cmdbuf + 0x80) = 0xFFFFFFFFu;
		ta_invoke(req, cmdbuf, sizeof(cmdbuf));
		fprintf(stderr, "[auth] AUTHENTICATE(arm) status=%u  cmdbuf[0x60..0x90]:",
			*(uint32_t *)req);
		{ int j; for (j = 0x60; j < 0x90; j++)
			fprintf(stderr, " %02x", cmdbuf[j]); }
		fprintf(stderr, "\n");
		dump_ta_log();
		/* v73: the arm call alone leaves the operation queue empty, so the
		 * state machine classifies every touch as HOME_KEY.  Queue
		 * AUTHENTICATE_IMAGE explicitly. */
		set_auth_operation_queue();
		fprintf(stderr, "[auth] operation queue set to AUTHENTICATE_IMAGE\n");

		for (iter = 0; iter < max_iter; iter++) {
			int polln = 0, got = 0, n1107 = 0, matched = 0;
			uint32_t irq_st = 0, irq_type = 0, lm = 0;

			fprintf(stderr, "\n[auth] ===== press %d/%d =====\n",
				iter + 1, max_iter);
			fprintf(stderr,
				"[auth] put the ENROLLED finger on the sensor, then press Enter\n");
			if (getenv("TA_PRESS")) {
				char line[16];

				if (!fgets(line, sizeof(line), stdin))
					fprintf(stderr, "[auth] stdin closed\n");
			} else {
				/* FP_VERIFY runs under a PAM prompt: keep each wait short
				 * so a miss falls through to the password quickly. */
				uint32_t t = verify_mode ? 3000 : 10000;

				ioctl(g_spifd, GOODIX_FP_IOC_WAIT_FINGER, &t);
			}
			/* Same re-seed the enroll loop needs: the per-press IRQ chain
			 * deinits the data-process object and clears [0x99c248], so the
			 * check body would be skipped and nothing gets matched. */
			{
				typedef long (*dp_init_t)(void);
				dp_init_t dp_init = (dp_init_t)(uintptr_t)(TA_BASE + 0x4ee70);

				fprintf(stderr,
					"[auth] re-seed gf_data_process_init() -> %ld\n",
					dp_init());
			}
			/* v73: re-arm the operation queue on every press -- the IRQ
			 * chain consumes it, and an empty queue means HOME_KEY. */
			set_auth_operation_queue();
			/* v74: snapshot the trustlet log cursor so a match can only be
			 * credited to THIS press. */
			lm = ta_log_mark();
			do {
				*(volatile uint32_t *)(uintptr_t)0x982790UL = 2;
				*(uint32_t *)(irqbuf + 0x70) = 2;
				*(uint32_t *)irqbuf = 1016;
				ta_invoke(req, irqbuf, sizeof(irqbuf));
				irq_st = *(uint32_t *)req;
				irq_type = *(uint32_t *)(irqbuf + 0x70);
				fprintf(stderr,
					"[auth] IRQ status=%u irq_type=0x%08x op=%u (poll %d)\n",
					irq_st, irq_type,
					*(uint32_t *)(irqbuf + 0x74), polln);
				if (irq_st == 1107) {
					n1107++;
					fprintf(stderr,
						"[auth] NEED_RESET (1107) #%d -- DAC drifted\n",
						n1107);
					/* FP_VERIFY runs inside a short PAM window, so
					 * recover one strike earlier there. */
					if (n1107 >= 3) {
						/* v73b: same heavy recovery the enroll loop
						 * needs.  A bare chip reset never restores
						 * the DAC once it drifts (v28/v37): only the
						 * full DETECT/INIT/INIT_FINISHED chain
						 * re-reads the OTP calibration.  Then
						 * re-establish the group and re-arm auth
						 * instead of RESUME_ENROLL. */
						fprintf(stderr,
							"[auth] heavy recovery: power cycle + DETECT/INIT/INIT_FINISHED + re-arm\n");
						sensor_power_cycle();
						bringup_chain(req, cmdbuf, sizeof(cmdbuf));
						memset(cmdbuf, 0, sizeof(cmdbuf));
						*(uint32_t *)cmdbuf = 1014;
						*(uint32_t *)(cmdbuf + 0x60) = 0;
						*(uint32_t *)(cmdbuf + 0x70) = 0;
						ta_invoke(req, cmdbuf, sizeof(cmdbuf));
						*(uint32_t *)cmdbuf = 1017;
						ta_invoke(req, cmdbuf, sizeof(cmdbuf));
						memset(cmdbuf, 0, sizeof(cmdbuf));
						*(uint32_t *)cmdbuf = 1010;
						*(uint32_t *)(cmdbuf + 0x80) = 0xFFFFFFFFu;
						ta_invoke(req, cmdbuf, sizeof(cmdbuf));
						set_auth_operation_queue();
						fprintf(stderr,
							"[auth] re-armed (SET_ACTIVE_GROUP/SCREEN_ON/AUTHENTICATE status=%u)\n",
							*(uint32_t *)req);
					} else {
						sensor_reset_chip();
					}
					*(volatile uint32_t *)(uintptr_t)0x982790UL = 2;
					*(uint32_t *)(irqbuf + 0x70) = 2;
					usleep(300 * 1000);
				} else if (irq_type & 0x80) {
					got = 1;
				} else {
					/* The trustlet log ring is only 1 KB, so the
					 * per-frame dump loses almost everything.
					 * In verify mode also dump while waiting. */
					if (verify_mode)
						dump_ta_log();
					usleep(150 * 1000);
				}
				polln++;
			} while (!got && polln < 40);

			fprintf(stderr, "[auth] frame=%s  final status=%u\n",
				got ? "CAPTURED" : "NONE", irq_st);
			/* v74: the match verdict comes from the trustlet's own log --
			 * gf_ta_get_user_id only runs when a template matched. */
			matched = got && ta_log_since(lm, "get user id");
			if (matched) {
				matched_total++;
				fprintf(stderr,
					"\n[auth] ===== MATCH! finger recognised (press %d) =====\n\n",
					iter + 1);
			} else if (got) {
				fprintf(stderr, "[auth] no match on this press\n");
			}
			if (got || verify_mode)
				dump_attempt_verdict(lm, matched);
			dump_ta_log();

			fprintf(stderr, "[auth] lift the finger FULLY, then press Enter\n");
			if (getenv("TA_PRESS")) {
				char line[16];

				if (!fgets(line, sizeof(line), stdin))
					fprintf(stderr, "[auth] stdin closed\n");
			} else {
				uint32_t t = verify_mode ? 1500 : 5000;

				ioctl(g_spifd, GOODIX_FP_IOC_WAIT_FINGER, &t);
			}
			*(volatile uint32_t *)(uintptr_t)0x982790UL = 2;
			*(uint32_t *)(irqbuf + 0x70) = 0x4;
			*(uint32_t *)(irqbuf + 0x74) = 0;
			*(uint32_t *)irqbuf = 1016;
			ta_invoke(req, irqbuf, sizeof(irqbuf));
			fprintf(stderr, "[auth] UP status=%u irq_type=0x%08x\n",
				*(uint32_t *)req, *(uint32_t *)(irqbuf + 0x70));
			if (matched && verify_mode)
				break;	/* FP_VERIFY: one verdict is all the caller needs */
			/* v78: pace the unattended loop like a human operator.  Cycling
			 * the seeded down/up IRQs every ~0.5s makes the trustlet's
			 * irq_pre_process bail with GF_ERROR_TOO_FAST (1094) before it
			 * ever runs the touch check or the algorithm -- 12 captures in
			 * a row, algorithm runs: 0.  The operator-driven v73b runs
			 * (2-5s per press) got real comparisons, so wait it out. */
			if (verify_mode) {
				usleep(3000000);
				set_auth_operation_queue();
			}
			if (verify_mode && (int)(time(NULL) - t0) >= budget) {
				fprintf(stderr,
					"[auth] verify budget %ds reached, no match\n",
					budget);
				break;
			}
		}
		fprintf(stderr, "\n[auth] done (matched=%d/%d)\n",
			matched_total, max_iter);
		return verify_mode ? (matched_total ? 0 : 1) : 0;
	}

	if (!strcmp(argv[2], "enroll")) {
		/*
		 * Interactive enrollment: DETECT -> INIT -> INIT_FINISHED ->
		 * PRE_ENROLL, then loop "press finger -> ENROLL -> lift finger"
		 * until the trustlet reports the template is complete, then
		 * POST_ENROLL + SAVE.  The trustlet's ENROLL does not block on
		 * a finger by itself; the CA is expected to wait for the finger
		 * IRQ between captures.
		 *
		 * Usage: enroll [max_iterations]  (default 30)
		 */
		uint8_t req[256];
		uint8_t cmdbuf[16384];
		/* GF_CMD_IRQ(1016) uses a ~320 KB in/out buffer: the TA reads the
		 * sensor IRQ status register over SPI and dumps the captured frame
		 * (decoded irq_type at +0x60 / operation at +0x64). */
		uint8_t irqbuf[0x50000];
		int max_iter = argc > 3 ? (int)strtol(argv[3], NULL, 0) : 80;
		/* v29: TA_UP_MODE selects the finger-up experiment after each
		 * captured frame: 0 = off (v27 behaviour), 1 = single 0x4,
		 * 2 = single 0x6 (down|up), 3 = 0x2 then 0x4. */
		int up_mode = getenv("TA_UP_MODE") ? atoi(getenv("TA_UP_MODE")) : 1;
		int iter;

		ta_init();
		memset(req, 0, sizeof(req));
		memset(cmdbuf, 0, sizeof(cmdbuf));
		memset(irqbuf, 0, sizeof(irqbuf));
		*(uint32_t *)(req + 8) = 1;

		/* --- bring-up chain --- */
		*(uint32_t *)cmdbuf = 1000; ta_invoke(req, cmdbuf, sizeof(cmdbuf));
		fprintf(stderr, "[enroll] DETECT status=%u\n", *(uint32_t *)req);
		*(uint32_t *)cmdbuf = 1001; ta_invoke(req, cmdbuf, sizeof(cmdbuf));
		fprintf(stderr, "[enroll] INIT   status=%u\n", *(uint32_t *)req);
		*(uint32_t *)cmdbuf = 1005; ta_invoke(req, cmdbuf, sizeof(cmdbuf));
		fprintf(stderr, "[enroll] INIT_FINISHED status=%u\n", *(uint32_t *)req);

		/* --- PRE_ENROLL with challenge --- */
		{
			int fd_r = open("/dev/urandom", O_RDONLY);
			if (fd_r >= 0) { read(fd_r, cmdbuf + 0x6b, 8); close(fd_r); }
		}
		*(uint32_t *)cmdbuf = 1006; ta_invoke(req, cmdbuf, sizeof(cmdbuf));
		fprintf(stderr, "[enroll] PRE_ENROLL status=%u\n", *(uint32_t *)req);
		fprintf(stderr, "    req[0..64]:");
		{ int jj; for (jj = 0; jj < 64; jj++)
			fprintf(stderr, " %02x", req[jj]);
		fprintf(stderr, "\n"); }
		fprintf(stderr, "    cmdbuf[0x50..0x90]:");
		{ int jj; for (jj = 0x50; jj < 0x90; jj++)
			fprintf(stderr, " %02x", cmdbuf[jj]);
		fprintf(stderr, "\n"); }
		{
			uint64_t ch = *(volatile uint64_t *)0x94b4E0UL;
			/* v51: cmdbuf+0x60 is the GID slot; challenge only in +0x6b */
			*(uint32_t *)(cmdbuf + 0x60) = 0; /* real gid */
			memcpy(cmdbuf + 0x6b, &ch, 8);
		}

		/* enumerate all known TA command names */
		for (int cc = 999; cc < 1100; cc++) {
			const char *nn = name_of_cmd(cc);
			if (nn && strncmp(nn, "(null)", 6) && strncmp(nn, "UNKNOWN", 7))
				fprintf(stderr, "[cmdenum] %d = %s\n", cc, nn);
		}

		/* enumerate all known TA command names */
		for (int cc = 999; cc < 1100; cc++) {
			const char *nn = name_of_cmd(cc);
			if (nn && strncmp(nn, "(null)", 6) && strncmp(nn, "UNKNOWN", 7))
				fprintf(stderr, "[cmdenum] %d = %s\n", cc, nn);
		}

		/* enable sensor for capture (HAL calls screen_on before enroll loop) */
		memset(cmdbuf, 0, sizeof(cmdbuf));
		/* v51: GF_CMD_SET_ACTIVE_GROUP(1014) gid=0 -- without it BSS
		 * [0x94c4c0] stays at 0x99 poison and every enroll fid /
		 * SAVE gid is garbage.  Handler fcn.0040b930 reads gid from
		 * cmdbuf+0x60 -> gf_ta_switch_fingerprint_user ->
		 * gf_fingerlist_set_active_group. */
		memset(cmdbuf, 0, sizeof(cmdbuf));
		*(uint32_t *)cmdbuf = 1014; /* GF_CMD_SET_ACTIVE_GROUP */
		*(uint32_t *)(cmdbuf + 0x60) = 0; /* gid = 0 */
		ta_invoke(req, cmdbuf, sizeof(cmdbuf));
		fprintf(stderr, "[enroll] SET_ACTIVE_GROUP(gid=0) status=%u\n",
					*(uint32_t *)req);
		dump_finger_state("post-SET_ACTIVE_GROUP");
		
		*(uint32_t *)cmdbuf = 1017; /* GF_CMD_SCREEN_ON */
		ta_invoke(req, cmdbuf, sizeof(cmdbuf));
		fprintf(stderr, "[enroll] SCREEN_ON status=%u\n", *(uint32_t *)req);

		/* v55: gf_data_process_check (fcn.00450390 @0x450404) aborts every
		 * frame with "init failed, break" while [0x99c248]==0; the only
		 * setter is gf_cali_reset_state->gf_data_process_init, a chain our
		 * synthetic host never triggers (v54 tried bare-flagging it and the
		 * check body crashed rc=139 on unbuilt structures).  Call the TA's
		 * own gf_data_process_init (fcn.0044ee70) directly: arg ignored
		 * (context recomputed via adrp), gate b.eq NOPed by v53, and on
		 * success it sets [0x99c248]=1 having built the structures. */
		{
			typedef long (*dp_init_t)(void);
			dp_init_t dp_init = (dp_init_t)(uintptr_t)(TA_BASE + 0x4ee70);
			long dp_r = dp_init();
			fprintf(stderr, "[enroll] direct gf_data_process_init() -> %ld\n", dp_r);
		}

		/* The 1016 handler is entered with x0=irqbuf+0x10 (dispatcher
		 * at 0x40cdb8 adds 0x10). Handler layout from irqbuf:
		 *   irq_type handler[x20+0x60] -> irqbuf+0x70
		 *   op       handler[x20+0x64] -> irqbuf+0x74
		 *   state    handler[x22+0x3f9c], x22=x20+0x4c000
		 *            -> irqbuf+0x4ffac
		 * Do NOT force state: state=0 must run the sensor wake sequence
		 * (4093e0) before state=2 can capture.  Instead make the state=0
		 * gate 427618 succeed: it requires global *(0x982790)==2.  Seed
		 * irq_type bit1=1 (finger-down) at the correct offset 0x70. */
		fprintf(stderr, "[enroll] global@0x982790 natural=%u\n",
			*(volatile uint32_t *)(uintptr_t)0x982790UL);
		*(volatile uint32_t *)(uintptr_t)0x982790UL = 2;
		*(uint32_t *)(irqbuf + 0x70) = 2;
		/* v65: prev_tpl MUST live OUTSIDE the press loop.  In v64 it was
		 * declared inside, so it was re-zeroed on every iteration and the
		 * "template saved (prev_tpl >= 8 && tpl == 0)" detector below could
		 * never fire -- v65's own log shows the TA completed the algorithm
		 * TWICE (tpl 9->0 at press 15 and press 26, fingerlist 0->1->2)
		 * while the host kept asking for more presses. */
		int prev_tpl = 0;
		/* --- capture loop --- */
		for (iter = 0; iter < max_iter; iter++) {
			uint32_t st;
			int press1107 = 0, pframe = 0;
			uint32_t est = 0;

			fprintf(stderr, "[enroll] === press finger (%d/%d) ===\n",
				iter + 1, max_iter);
			/* v41: open the registration gates only after the algo has
			 * accumulated enough frames (default 20 = the TA's
			 * template_update checkpoint), so the frame path registers
			 * ONE finger with a mature template instead of registering a
			 * bogus finger on the first presses (which froze algo
			 * accumulation at 5 in v40).  TA_GATE_EARLY keeps the old
			 * v40 behaviour (patch at load). */
			{
				static int gates_done;
				int gate_after = getenv("TA_GATE_AFTER")
					? atoi(getenv("TA_GATE_AFTER")) : 20;

				if (!gates_done && !getenv("TA_GATE_EARLY")
				    && iter >= gate_after) {
					patch_save_gates();
					gates_done = 1;
				}
			}
			/*
			 * The finger IRQ is only an "attention" line: the driver latches
			 * any edge into a flag with no clear-on-read path, and this board's
			 * GPIO136 floats (it picks up ~50 Hz hum), so WAIT_FINGER returns
			 * immediately on a spurious edge instead of blocking until a real
			 * press.  Report what it actually did rather than assuming it
			 * waited, and let TA_PRESS=1 gate the capture on the operator
			 * confirming the finger is down.
			 */
			if (getenv("TA_PRESS")) {
				char line[16];

				fprintf(stderr,
					"[enroll] TA_PRESS: put finger on sensor, then press Enter...\n");
				if (!fgets(line, sizeof(line), stdin))
					fprintf(stderr, "[enroll] TA_PRESS: stdin closed, continuing\n");
			} else {
				uint32_t timeout = 10000; /* 10s */
				long wr = ioctl(g_spifd, GOODIX_FP_IOC_WAIT_FINGER,
						&timeout);

				if (wr == 0)
					fprintf(stderr,
						"[enroll] WAIT_FINGER signalled (state=%u) — spurious edges make this unreliable\n",
						timeout);
				else
					fprintf(stderr,
						"[enroll] WAIT_FINGER failed: %s (proceeding anyway)\n",
						strerror(errno));
			}
			/* GF_CMD_IRQ(1016): tell the TA a finger event happened so it reads
			 * the sensor IRQ register over SPI and captures a frame into irqbuf.
			 * Response: irq_type (bitmask) at +0x60, operation at +0x64. */
			/* Each finger press is a fresh event: re-seed irq_type bit1=1 at
			 * the handler's true offset (irqbuf+0x70) and re-force the global
			 * 0x982790=2 gate, because the TA overwrites both while
			 * processing the previous frame.  Keep the internal state, do
			 * not memset.  Then set the command id. */
		{
			int polln = 0;
			uint32_t irq_st = 0, irq_type = 0, op = 0;
			int got_frame = 0;
			int n1107 = 0;

			/*
			 * One physical press is a wake->capture sequence.  The state
			 * machine returns from the first IRQ invoke after only the
			 * wake (irq_type bit1, no frame); the analog front end then
			 * needs a settle before the frame is ready.  Re-invoke IRQ
			 * with short delays until the sensor reports a frame
			 * (irq_type 0x80) or a hard error, instead of requiring a
			 * separate operator press for the capture.
			 */
			do {
				*(volatile uint32_t *)(uintptr_t)0x982790UL = 2;
				*(uint32_t *)(irqbuf + 0x70) = 2;
				if (polln == 0)
					dump_dac_state("pre");
				*(uint32_t *)irqbuf = 1016;
				ta_invoke(req, irqbuf, sizeof(irqbuf));
				irq_st = *(uint32_t *)req;
				irq_type = *(uint32_t *)(irqbuf + 0x70);
				op = *(uint32_t *)(irqbuf + 0x74);
				fprintf(stderr,
					"[enroll] IRQ status=%u irq_type=0x%08x op=%u (poll %d)\n",
					irq_st, irq_type, op, polln);
				if (irq_st == 1107) {
					n1107++;
					press1107 = 1;
					fprintf(stderr,
						"[enroll] NEED_RESET during poll: pulse chip RESET (GPIO216), rewind state to 0, settle\n");
					dump_dac_state("1107");
					/*
					 * v37: the reset pulse never restores
					 * the DAC once the sensor lost its
					 * key-detect hold state (v28/v36:
					 * identical garbage register pattern
					 * for 500+ consecutive polls).  The
					 * only recovery proven to reprogram
					 * the DAC is the full DETECT/INIT/
					 * INIT_FINISHED chain -- INIT re-reads
					 * the OTP calibration (v23).  Cost:
					 * the algo preprocess counter resets,
					 * but in this state we capture
					 * nothing anyway.
					 */
					if (n1107 == 3) {
						fprintf(stderr,
							"[enroll] heavy recovery: power cycle + DETECT/INIT/INIT_FINISHED + RESUME_ENROLL\n");
						sensor_power_cycle();
						bringup_chain(req, cmdbuf,
							      sizeof(cmdbuf));
						memset(cmdbuf, 0,
						       sizeof(cmdbuf));
						*(uint32_t *)cmdbuf = 1017;
						ta_invoke(req, cmdbuf,
							  sizeof(cmdbuf));
						fprintf(stderr,
							"[reinit] SCREEN_ON status=%u\n",
							*(uint32_t *)req);
						resume_enroll(req, cmdbuf,
							      sizeof(cmdbuf));
					} else {
						sensor_reset_chip();
					}
					*(uint32_t *)(irqbuf + 0x4ffac) = 0;
					*(volatile uint32_t *)(uintptr_t)0x982790UL = 2;
					*(uint32_t *)(irqbuf + 0x70) = 2;
					usleep(300 * 1000);
					/* v28 showed 80 straight reset pulses never restored
					 * the DAC once it drifted: stop burning ~20 s per
					 * press and let the operator see it clearly. */
					if (n1107 >= 12) {
						fprintf(stderr,
							"[enroll] %d consecutive 1107, DAC unrecoverable this press; aborting early\n",
							n1107);
						break;
					}
				} else if (irq_type & 0x80) {
					got_frame = 1;
					pframe = 1;
					n1107 = 0;
				} else {
					/* wake only / sensor not ready: settle then
					 * capture.  v42: do NOT clear n1107 here -- in
					 * the broken-DAC state the TA alternates
					 * 1107 / wake(irq_type=0x2), so clearing the
					 * counter on every wake poll kept it at 1 and the
					 * heavy recovery at n1107==3 never fired (v41:
					 * 40-poll spiral, no frame).  n1107 is reset on a
					 * real frame (got_frame) and at each press. */
					usleep(150 * 1000);
				}
				polln++;
			} while (!got_frame && polln < 40);

			if (!got_frame) {
				fprintf(stderr,
					"[enroll] no frame after %d polls; skipping ENROLL this press\n",
					polln);
				continue;
			}
		}
		*(uint32_t *)cmdbuf = 1007;
		/* v69: mirror gf_hal_common_enroll's 176-byte ENROLL buffer exactly
		 * (libgf_hal.so 0x204e0..0x20568).  The stock CA sends:
		 *   buf[ 96] = u32 arg2                     (host writes 0 at +0x60)
		 *   buf[104] = is_dump_enabled   (byte)
		 *   buf[105] = 0                 (byte -- the CA explicitly zeroes it)
		 *   buf[106..174] = 69-byte hw_auth_token_t:
		 *        [0]=version(=1) [1..8]=challenge u64 [9..16]=user_id
		 *        [17..24]=authenticator_id [25..28]=authenticator_type
		 *        [29..36]=timestamp [37..68]=hmac
		 * The TA's ENROLL handler reads the challenge u64 @0x6b and user_id
		 * u64 @0x73 and compares buf[105] against buf[106] (see the v34 RE
		 * note).  The host already drops its random challenge at +0x6b, but
		 * it never set the version byte, so stock sees buf[105]=0 !=
		 * buf[106]=1 while we saw 0 == 0 -- a different branch in the
		 * handler.  TA_HAT=0x<hex> overrides the whole 69-byte blob. */
		{
			const char *hat = getenv("TA_HAT");

			cmdbuf[104] = 0;	/* is_dump_enabled */
			cmdbuf[105] = 0;
			if (hat) {
				int k, n = (int)strlen(hat);

				for (k = 0; k < 69 && 2 * k + 1 < n; k++) {
					int hi = hat[2 * k], lo = hat[2 * k + 1];
					int hv = hi <= '9' ? hi - '0' : (hi | 32) - 'a' + 10;
					int lv = lo <= '9' ? lo - '0' : (lo | 32) - 'a' + 10;

					if (hv < 0 || hv > 15 || lv < 0 || lv > 15)
						break;
					cmdbuf[106 + k] = (uint8_t)((hv << 4) | lv);
				}
			} else {
				cmdbuf[106] = 1;	/* hw_auth_token version */
			}
		}
			/* v57: the per-press IRQ chain (gf_algo_common_reset_sensor_id)
			 * deinits the data-process object and clears [0x99c248], so the
			 * v55 init done before the loop is undone on every press and
			 * the check body is skipped (frames never stitch -> template
			 * count never reaches min_templates -> enroll never completes).
			 * Re-run gf_data_process_init right before ENROLL: it rebuilds
			 * the object and sets the flag; accumulated templates live in
			 * g_enrolling_finger (0x99c1f0), untouched by this. */
			{
				typedef long (*dp_init_t)(void);
				dp_init_t dp_init = (dp_init_t)(uintptr_t)(TA_BASE + 0x4ee70);
				long dp_r = dp_init();
				fprintf(stderr, "[enroll] re-seed gf_data_process_init() -> %ld\n", dp_r);
			}

			ta_invoke(req, cmdbuf, sizeof(cmdbuf));
			st = *(uint32_t *)req;
			est = st;
			fprintf(stderr, "[enroll] ENROLL status=%u\n", st);
			/* v58: watch the algo-side template count.  g_enrolling_finger
			 * (0x99c1f0) is the per-enroll finger object; the template
			 * count the gate2 comparison uses is [finger+0x38].  Also show
			 * the live min_templates (0x99c154) to confirm the 26->10
			 * patch still holds after every re-seed. */
			{
				void *efp = *(void **)(uintptr_t)0x99c1f0UL;
				uint32_t tpl = efp ? *(volatile uint32_t *)((uintptr_t)efp + 0x38) : 0xFFFFFFFFu;
				uint32_t min_t = *(volatile uint32_t *)(uintptr_t)0x99c154UL;
				fprintf(stderr, "[enroll] g_fpTemplateNum=%u min_templates=%u\n", tpl, min_t);
				fprintf(stderr, "[enroll] tplcheck prev=%u tpl=%u\n", prev_tpl, tpl);
				/* v69: watch whether the TA ever turns 0x940d00 into a real
				 * object.  The SAVE/pdu path reads *(0x940d00+0x10) as the
				 * algo finger template; in the shipped image that slot is
				 * constant table data (0x426000001af), which is the whole
				 * reason SAVE cannot encode.  If a proper 69-byte hw auth
				 * token flips the TA into the stock branch this should
				 * change. */
				fprintf(stderr,
					"[enroll] *(0x940d00+0x10)=0x%llx cmdbuf[104..112]:",
					(unsigned long long)*(volatile uint64_t *)(uintptr_t)(0x940d00UL + 0x10));
				{ int j; for (j = 104; j < 112; j++)
					fprintf(stderr, " %02x", cmdbuf[j]); }
				fprintf(stderr, "\n");
				/* v59: tpl hitting 9 then resetting to 0 means the algo just
				 * finished and saved the asp template (gf_algo_asp_save_templates_
				 * features wrote asp_template_features_* -- confirmed on device).
				 * That is the enrollment-complete signal; break so the after-loop
				 * SAVE(1012)/POST_ENROLL/ENUMERATE path can register the finger
				 * and hand us the so.  Guarded so the very first press (tpl 1->0
				 * or 0->1) never trips it. */
				if (prev_tpl >= 8 && tpl == 0) {
					fprintf(stderr,
						"[enroll] template saved (tpl %u -> 0), completing enroll\n",
						prev_tpl);
					/* v60: the finger is still physically down at this
					 * point; running SAVE/POST_ENROLL while it is pressed
					 * trips the DAC validity check and 1107-storms (v59).
					 * Do the same lift dance the normal loop does before
					 * breaking into the after-loop save path. */
					if (getenv("TA_PRESS")) {
						char uline2[16];
						fprintf(stderr,
							"[enroll] lift finger FULLY, then press Enter...\n");
						if (!fgets(uline2, sizeof(uline2), stdin))
							fprintf(stderr,
								"[enroll] stdin closed, continuing\n");
					} else {
						uint32_t timeout = 5000;
						ioctl(g_spifd, GOODIX_FP_IOC_WAIT_FINGER,
							&timeout);
					}
					if (up_mode) {
						*(volatile uint32_t *)(uintptr_t)0x982790UL = 2;
						*(uint32_t *)(irqbuf + 0x70) = 0x4;
						*(uint32_t *)(irqbuf + 0x74) = 0;
						*(uint32_t *)irqbuf = 1016;
						ta_invoke(req, irqbuf, sizeof(irqbuf));
						fprintf(stderr,
							"[enroll] UP status=%u irq_type=0x04\n",
							*(uint32_t *)req);
					}
					break;
				}
				prev_tpl = tpl;
			}
			fprintf(stderr, "    cmdbuf[0x00..0x40]:");
			{ int jj; for (jj = 0; jj < 0x40; jj++)
				fprintf(stderr, " %02x", cmdbuf[jj]);
			fprintf(stderr, "\n"); }
			/* status 0 = frame captured, 1003/1058 = need more frames,
			 * anything else = stop */
			if (st != 0 && st != 1003 && st != 1058 && st != 1062)
				break;
			fprintf(stderr, "[enroll] lift finger...\n");
			if (getenv("TA_PRESS")) {
				char uline[16];

				/* v48: feeding the UP irq while the finger is still
				 * physically down makes the TA's up path fail
				 * (polling_get_nav_base int failed -> FINGER_NOT_LEAVE
				 * 1065 -> check_sensor_dac_validity 1107), and once the
				 * DAC is invalid it stays invalid for every later press.
				 * Gate the UP feed on the operator confirming the finger
				 * is fully lifted. */
				fprintf(stderr,
					"[enroll] lift finger FULLY, then press Enter...\n");
				if (!fgets(uline, sizeof(uline), stdin))
					fprintf(stderr,
						"[enroll] stdin closed, continuing\n");
			} else {
				uint32_t timeout = 5000;

				ioctl(g_spifd, GOODIX_FP_IOC_WAIT_FINGER, &timeout);
			}
			/*
			 * v29: the real CA never seeds irq_type -- it is TA output.
			 * A press is down -> image -> *up*, and the CA's up handler
			 * (hal_milan_an_series_irq 0x457e8) reads the press-too-fast
			 * flags and closes the cycle.  This host has only ever fed
			 * down (0x2), so the TA never runs the up path (state stuck
			 * at 6/7), the sensor is never returned to its key-detect
			 * hold state, and after ~4 captures the DAC registers read
			 * garbage and every capture dies with 1107 (v28 log).
			 * Feed the up half here, at the physical lift.  CA buffer
			 * offsets +0x60/+0x6c..0x6e map to irqbuf+0x70/+0x7c..0x7e
			 * because the dispatcher enters the handler at irqbuf+0x10.
			 */
			if (up_mode) {
				static const struct { int n; uint32_t first; } upseq[] = {
					{ 1, 0x4 },	/* mode 1: single 0x4 */
					{ 1, 0x6 },	/* mode 2: 0x6 = down|up */
					{ 2, 0x2 },	/* mode 3: 0x2 then 0x4 */
				};
				int uc;

				if (iter == 0) {
					fprintf(stderr,
						"[enroll] irqbuf[0x60..0x90] before first up:\n");
					{ int j;
					for (j = 0x60; j < 0x90; j += 16) {
						fprintf(stderr, "  %03x:", j);
						{ int k; for (k = 0; k < 16; k++)
							fprintf(stderr, " %02x", irqbuf[j + k]); }
						fprintf(stderr, "\n");
					} }
				}
				fprintf(stderr,
					"[enroll] flags@0x7c/7d/7e before up: %02x %02x %02x\n",
					irqbuf[0x7c], irqbuf[0x7d], irqbuf[0x7e]);
				for (uc = 0; uc < upseq[up_mode - 1].n; uc++) {
					*(volatile uint32_t *)(uintptr_t)0x982790UL = 2;
					*(uint32_t *)(irqbuf + 0x70) =
						uc ? 0x4 : upseq[up_mode - 1].first;
					*(uint32_t *)(irqbuf + 0x74) = 0;
					*(uint32_t *)irqbuf = 1016;
					ta_invoke(req, irqbuf, sizeof(irqbuf));
					fprintf(stderr,
						"[enroll] UP[%d] status=%u irq_type=0x%08x op=%u state=%u flags=%02x %02x %02x\n",
						uc, *(uint32_t *)req,
						*(uint32_t *)(irqbuf + 0x70),
						*(uint32_t *)(irqbuf + 0x74),
						*(uint32_t *)(irqbuf + 0x4ffac),
						irqbuf[0x7c], irqbuf[0x7d], irqbuf[0x7e]);
					usleep(50 * 1000);
				}
			}
			usleep(300 * 1000);
			{
				/* live per-press card */
				uint32_t preproc = *(volatile uint32_t *)(uintptr_t)0x99c240UL;
				uint32_t flc = *(volatile uint32_t *)(uintptr_t)0x94c4c4UL;
				/* v51c: colour is unconditional (tee forwards ANSI to the
				 * terminal; the file keeps the codes for log_viewer).  Box
				 * is pure ASCII -- the CJK box chars (U+2550..) have
				 * ambiguous terminal width and broke line wrapping under
				 * tee. */
				const char *G="\033[32m",*R="\033[31m",*Y="\033[33m",
					  *C="\033[36m",*N="\033[0m";
				int good = pframe && !press1107 && (est==0||est==1003||est==1058||est==1062);
				fprintf(stderr,
			"\n%s+------------------------------------------------------------+%s\n",C,N);
				fprintf(stderr,
			"%s|%s  PRESS %3d / %-3d   %s%-3s%s%45s%s|%s\n",
					C,N, iter+1, max_iter,
					good?G:R, good?"OK":"!!", N, "", C,N);
				fprintf(stderr,
			"%s+------------------------------------------------------------+%s\n",C,N);
				fprintf(stderr,
			"%s|%s  Frame      : %s%-24s%s%28s%s|%s\n",
					C,N, pframe?G:R, pframe?"CAPTURED":"NO FRAME", N, "", C,N);
				fprintf(stderr,
			"%s|%s  ENROLL st  : %-24u%28s%s|%s\n",
					C,N, est, "", C,N);
				fprintf(stderr,
			"%s|%s  1107 reset : %s%-24d%s%28s%s|%s\n",
					C,N, press1107?R:G, press1107, N, "", C,N);
				fprintf(stderr,
			"%s|%s  preproc cnt: %-24u%28s%s|%s\n",
					C,N, preproc, "", C,N);
				fprintf(stderr,
			"%s|%s  fingerlist : %s%-24u%s%28s%s|%s\n",
					C,N, flc?Y:G, flc, N, "", C,N);
				fprintf(stderr,
			"%s+------------------------------------------------------------+%s\n\n",C,N);
				fflush(stderr);
			}
		}

		/* --- finalize --- */
		dump_finger_state("after-loop");
		/* v35: try SAVE before POST_ENROLL -- the node the response
		 * serializer trips over may only exist while enrollment is
		 * still open. */
		{
			uint32_t gid = *(volatile uint32_t *)0x94c4c0UL;

			memset(cmdbuf, 0, sizeof(cmdbuf));
			memset(req, 0, sizeof(req));
			*(uint32_t *)(req + 8) = 1;
			*(uint32_t *)cmdbuf = 1012;
			*(uint32_t *)(cmdbuf + 0x60) = gid;
			*(uint32_t *)(cmdbuf + 0x64) = 0;
			/* v71: the trustlet dispatcher enters every command handler
			 * with x0 = cmdbuf + 0x10 -- the same convention the IRQ path
			 * already relies on (host writes irq_type at irqbuf+0x70, the
			 * 1016 handler reads it at its own +0x60).  gf_ta_save does
			 * `ldp w25, w24, [x23, #96]` on ITS argument, so gid/fid have
			 * to land at cmdbuf+0x70 / +0x74.  v70's log proved the
			 * off-by-0x10: the trustlet reported "finger_id=0" for every
			 * candidate while cmdbuf+0x74 was zero.  Write both offsets so
			 * either convention resolves correctly. */
			*(uint32_t *)(cmdbuf + 0x70) = gid;
			*(uint32_t *)(cmdbuf + 0x74) = 0;
			fprintf(stderr, "[enroll] early SAVE (pre-POST_ENROLL) gid=%u fid=0...",
				gid);
			fflush(stderr);
			if (sigsetjmp(g_segv_jmp, 1) == 0) {
				g_segv_armed = 1;
				ta_invoke(req, cmdbuf, sizeof(cmdbuf));
				g_segv_armed = 0;
				fprintf(stderr, " status=%u\n", *(uint32_t *)req);
			} else {
				fprintf(stderr, " SEGV\n");
			}
			dump_finger_state("after-early-save");
		}
		*(uint32_t *)cmdbuf = 1008; ta_invoke(req, cmdbuf, sizeof(cmdbuf));
		fprintf(stderr, "[enroll] POST_ENROLL status=%u\n", *(uint32_t *)req);
		dump_finger_state("post-POST_ENROLL");
		/* dump BSS to find fingerlist (group_id + finger_id) */
		if (getenv("TA_DUMP")) {
			char spec[64];
			char *colon;
			uint64_t a;
			unsigned n;
			snprintf(spec, sizeof(spec), "%s", getenv("TA_DUMP"));
			colon = strchr(spec, ':');
			a = strtoull(spec, NULL, 0);
			n = colon ? (unsigned)strtoul(colon + 1, NULL, 0) : 64;
			fprintf(stderr, "[peek] %#llx..%#llx\n",
				(unsigned long long)a, (unsigned long long)(a + n));
			dump_mem(a, n);
		}
		/* enumerate fingers to find the enrolled finger_id */
		memset(cmdbuf, 0, sizeof(cmdbuf));
		*(uint32_t *)cmdbuf = 1015; ta_invoke(req, cmdbuf, sizeof(cmdbuf));
		fprintf(stderr, "[enroll] ENUMERATE status=%u\n", *(uint32_t *)req);
		fprintf(stderr, "    req[0..128]:");
		{ int jj; for (jj = 0; jj < 128; jj++)
			fprintf(stderr, " %02x", req[jj]);
		fprintf(stderr, "\n"); }
		fprintf(stderr, "    cmdbuf[0x00..0xc0]:");
		{ int jj; for (jj = 0; jj < 0xc0; jj++)
			fprintf(stderr, " %02x", cmdbuf[jj]);
		fprintf(stderr, "\n"); }
		/*
		 * v38: the CA's enumerate parser (libgf_hal 0x21068) reads the
		 * finger_id array from the response at cmdbuf+0x8c -- our earlier
		 * dumps stopped at 0x80 and never saw the fid.  Collect the u32s
		 * there as the primary SAVE candidates.
		 */
		uint32_t enum_fids[12];
		int enum_fn = 0;
		{
			int k;

			fprintf(stderr, "    enumerate fids@0x8c:");
			for (k = 0; k < 12; k++) {
				uint32_t f;

				memcpy(&f, cmdbuf + 0x8c + k * 4, 4);
				fprintf(stderr, " %u", f);
				if (f && f != 0xffffffff && enum_fn < 12)
					enum_fids[enum_fn++] = f;
			}
			fprintf(stderr, "\n");
		}
		/* where the CA reads the enroll-success fid from: the HAL's
		 * persistent rsp buffer tail (libgf_hal 0x231f4: +0x4fcc0/+8). */
		fprintf(stderr, "    irqbuf[0x4fc80..0x4ffd0]:");
		{ int jj; for (jj = 0x4fc80; jj < 0x4ffd0; jj++)
			fprintf(stderr, " %02x", irqbuf[jj]);
		fprintf(stderr, "\n"); }
		/* SAVE with gid/fid per the TA's own SAVE handler (0x40afa8):
		 * ldp w25,w24,[x23,#96] reads gid from cmdbuf+0x60 and fid from
		 * cmdbuf+0x64; the lookup 0x41b228 requires gid == *(0x94c4c0)
		 * and walks the finger list rooted at *(0x94c4d0) (node: u32 fid
		 * at +0, next at +40) to match fid.  v31 and earlier wrote fid
		 * into the gid slot, so every candidate mismatched. */
		{
			uint32_t gid = *(volatile uint32_t *)0x94c4c0UL;
			uint32_t save_status = 1047;
			uint32_t real_fid = 0;
			int have_real_fid = 0;

			fprintf(stderr,
				"[enroll] BSS group_id=0x%08x (%u)\n", gid, gid);
			/* Walk the TA's finger list and dump the first node. */
			{
				uint64_t node = *(uint64_t *)0x94c4d0UL;
				int guard = 0;

				fprintf(stderr, "[enroll] finger list@0x94c4d0:");
				while (node && guard++ < 16) {
					uint32_t f = *(uint32_t *)node;

					fprintf(stderr, " fid=%u", f);
					if (!have_real_fid) {
						/* v61: the enroll path never assigned a real
						 * fid -- the node carries BSS poison
						 * (0x99999999) or RNG bytes.  Force fid=1 so
						 * SAVE writes finger_0_1.so. */
						if (f == 0 || f == 0xffffffff ||
						    f == 0x99999999) {
							*(volatile uint32_t *)node = 1;
							f = 1;
							fprintf(stderr, "(fixed->1)");
						}
						real_fid = f;
						have_real_fid = 1;
						fprintf(stderr,
							"\n[enroll] finger node dump (64 bytes @0x%llx):\n",
							(unsigned long long)node);
						dump_mem(node, 64);
					}
					node = *(uint64_t *)(node + 40);
				}
				if (!guard || !have_real_fid)
					fprintf(stderr, " (empty)");
				fprintf(stderr, "\n");
			}
			dump_finger_state("pre-SAVE-loop");
			/*
			 * v38: fid candidates from the ENUMERATE response
			 * (cmdbuf+0x8c, parsed above) first -- that is where the
			 * CA's own enumerate parser reads them.  Then the finger
			 * list walk, 0, small ids, challenge bytes, constants.
			 */
			{
				uint32_t trylist[24];
				int tn = 0;
				static const int ch_offs[] = {
					0x6e, 0x6a, 0x6b, 0x6f, 0x6c, 0x60
				};
				static const uint32_t consts[] = {
					0x11111111, 0x22222222, 0x33333333,
					0x44444444, 0x55555555, 0x66666666,
					0x77777777, 0x88888888, 0x99999999
				};
				size_t ci2;
				int ci;

				for (ci = 0; ci < enum_fn && tn < 24; ci++) {
					int dup = 0, q;

					for (q = 0; q < tn; q++)
						if (trylist[q] == enum_fids[ci])
							dup = 1;
					if (!dup)
						trylist[tn++] = enum_fids[ci];
				}
				if (have_real_fid && tn < 24)
					trylist[tn++] = real_fid;
				if (tn < 24)
					trylist[tn++] = 0;
				for (ci = 1; ci <= 5 && tn < 24; ci++)
					trylist[tn++] = ci;
				for (ci = 0; ci < (int)(sizeof(ch_offs) / sizeof(ch_offs[0]));
				     ci++) {
					uint32_t v;

					memcpy(&v, cmdbuf + ch_offs[ci], 4);
					if (v && v != 0xffffffff) {
						int dup = 0, q;

						for (q = 0; q < tn; q++)
							if (trylist[q] == v)
								dup = 1;
						if (!dup && tn < 24)
							trylist[tn++] = v;
					}
				}
				for (ci2 = 0; ci2 < sizeof(consts) / sizeof(consts[0]);
				     ci2++)
					if (tn < 24)
						trylist[tn++] = consts[ci2];

				for (ci = 0; ci < tn && save_status != 0; ci++) {
					uint32_t fid = trylist[ci];

					memset(cmdbuf, 0, sizeof(cmdbuf));
					memset(req, 0, sizeof(req));
					*(uint32_t *)(req + 8) = 1;  /* route */
					*(uint32_t *)cmdbuf = 1012;
					*(uint32_t *)(cmdbuf + 0x60) = gid;
					*(uint32_t *)(cmdbuf + 0x64) = fid;
					/* v71: handler base is cmdbuf+0x10 -- see the
					 * early-SAVE note.  Without this the trustlet
					 * always saw finger_id=0. */
					*(uint32_t *)(cmdbuf + 0x70) = gid;
					*(uint32_t *)(cmdbuf + 0x74) = fid;
					fprintf(stderr,
						"[enroll] SAVE try gid=%u fid=%u...",
						gid, fid);
					fflush(stderr);
					if (sigsetjmp(g_segv_jmp, 1) == 0) {
						g_segv_armed = 1;
						ta_invoke(req, cmdbuf,
							  sizeof(cmdbuf));
						g_segv_armed = 0;
						save_status = *(uint32_t *)req;
						fprintf(stderr, " status=%u\n",
							save_status);
					} else {
						fprintf(stderr,
							" SEGV (serialize failed), next candidate\n");
						save_status = 139;
					}
				}
			}
			fprintf(stderr, "[enroll] SAVE final status=%u\n",
				save_status);
		}

		dump_ta_log();
		return 0;
	}

	if (!strcmp(argv[2], "raw")) {
		/*
		 * Fill the command buffer from a hex string so the message header
		 * fields can be experimented with: "raw <route> <hex bytes>".
		 */
		uint8_t req[64];
		uint8_t cmdbuf[8192];
		uint32_t route = argc > 3 ? (uint32_t)strtoul(argv[3], NULL, 0) : 1;
		const char *hex = argc > 4 ? argv[4] : "";
		size_t n = strlen(hex) / 2, k;

		if (n > sizeof(cmdbuf))
			n = sizeof(cmdbuf);
		ta_init();
		memset(req, 0, sizeof(req));
		memset(cmdbuf, 0, sizeof(cmdbuf));
		*(uint32_t *)(req + 8) = route;
		for (k = 0; k < n; k++) {
			unsigned v;

			if (sscanf(hex + k * 2, "%2x", &v) != 1)
				break;
			cmdbuf[k] = (uint8_t)v;
		}
		if (n >= 4)
			fprintf(stderr, "[host] raw route=%u id=%u hdr=%u,%u,%u len=%zu\n",
				route, *(uint32_t *)cmdbuf,
				*(uint32_t *)(cmdbuf + 4), *(uint32_t *)(cmdbuf + 8),
				*(uint32_t *)(cmdbuf + 12), n);
		ta_invoke(req, cmdbuf, sizeof(cmdbuf));
		fprintf(stderr, "[host] status=%u\n", *(uint32_t *)req);
		dump_ta_log();
		return 0;
	}

	if (!strcmp(argv[2], "names")) {
		/* Enumerate the whole GF_CMD_* table through the trustlet. */
		uint32_t from = argc > 3 ? (uint32_t)strtoul(argv[3], NULL, 0) : 1000;
		uint32_t to = argc > 4 ? (uint32_t)strtoul(argv[4], NULL, 0) : 1120;
		uint32_t id;

		ta_init();
		for (id = from; id <= to; id++)
			printf("%u %s\n", id, name_of_cmd(id));
		return 0;
	}

	if (!strcmp(argv[2], "scan")) {
		/* Walk a range of command ids on one route and report the ones the
		 * trustlet does not reject as UNKNOWN_CMD (1070). */
		uint8_t req[64];
		uint8_t cmdbuf[4096];
		uint32_t route = argc > 3 ? (uint32_t)strtoul(argv[3], NULL, 0) : 1;
		uint32_t from = argc > 4 ? (uint32_t)strtoul(argv[4], NULL, 0) : 0;
		uint32_t to = argc > 5 ? (uint32_t)strtoul(argv[5], NULL, 0) : 200;
		uint32_t id;

		ta_init();
		for (id = from; id <= to; id++) {
			uint32_t st;

			memset(req, 0, sizeof(req));
			memset(cmdbuf, 0, sizeof(cmdbuf));
			*(uint32_t *)(req + 8) = route;
			*(uint32_t *)cmdbuf = id;
			ta_invoke(req, cmdbuf, sizeof(cmdbuf));
			st = *(uint32_t *)req;
			if (st != 1070)
				fprintf(stderr, "[scan] route=%u id=%u status=%u\n",
					route, id, st);
		}
		fprintf(stderr, "[scan] done route=%u ids %u..%u\n", route, from, to);
		dump_ta_log();
		return 0;
	}

	usage(argv[0]);
	return 2;
}
