/*
 * Copyright (c) 2012 Rob Clark <robdclark@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <errno.h>

#include "redump.h"
#include "disasm.h"
#include "script.h"
#include "io.h"
#include "rnnutil.h"

/* ************************************************************************* */
/* originally based on kernel recovery dump code: */

typedef enum {
	true = 1, false = 0,
} bool;

static bool needs_wfi = false;
static bool dump_shaders = false;
static bool no_color = false;
static bool summary = false;
static bool allregs = false;
static bool dump_textures = false;
static bool is_blob = false;
static int vertices;
static unsigned gpu_id = 220;

static inline unsigned regcnt(void)
{
	if (gpu_id >= 500)
		return 0xffff;
	else
		return 0x7fff;
}

static int is_64b(void)
{
	return gpu_id >= 500;
}

#define CP_TYPE0_PKT 0x00000000
#define CP_TYPE2_PKT 0x80000000
#define CP_TYPE3_PKT 0xc0000000
#define CP_TYPE4_PKT 0x40000000
#define CP_TYPE7_PKT 0x70000000

#define pkt_is_type0(pkt) (((pkt) & 0XC0000000) == CP_TYPE0_PKT)
#define type0_pkt_size(pkt) ((((pkt) >> 16) & 0x3FFF) + 1)
#define type0_pkt_offset(pkt) ((pkt) & 0x7FFF)

#define pkt_is_type2(pkt) ((pkt) == CP_TYPE2_PKT)

/*
 * Check both for the type3 opcode and make sure that the reserved bits [1:7]
 * and 15 are 0
 */

static inline uint pm4_calc_odd_parity_bit(uint val)
{
	return (0x9669 >> (0xf & ((val) ^
			((val) >> 4) ^ ((val) >> 8) ^ ((val) >> 12) ^
			((val) >> 16) ^ ((val) >> 20) ^ ((val) >> 24) ^
			((val) >> 28)))) & 1;
}

#define pkt_is_type3(pkt) \
        ((((pkt) & 0xC0000000) == CP_TYPE3_PKT) && \
         (((pkt) & 0x80FE) == 0))

#define cp_type3_opcode(pkt) (((pkt) >> 8) & 0xFF)
#define type3_pkt_size(pkt) ((((pkt) >> 16) & 0x3FFF) + 1)

#define pkt_is_type4(pkt) \
        ((((pkt) & 0xF0000000) == CP_TYPE4_PKT) && \
         ((((pkt) >> 27) & 0x1) == \
         pm4_calc_odd_parity_bit(type4_pkt_offset(pkt))) \
         && ((((pkt) >> 7) & 0x1) == \
         pm4_calc_odd_parity_bit(type4_pkt_size(pkt))))

#define type4_pkt_offset(pkt) (((pkt) >> 8) & 0x7FFFF)
#define type4_pkt_size(pkt) ((pkt) & 0x7F)

#define pkt_is_type7(pkt) \
        ((((pkt) & 0xF0000000) == CP_TYPE7_PKT) && \
         (((pkt) & 0x0F000000) == 0) && \
         ((((pkt) >> 23) & 0x1) == \
         pm4_calc_odd_parity_bit(cp_type7_opcode(pkt))) \
         && ((((pkt) >> 15) & 0x1) == \
         pm4_calc_odd_parity_bit(type7_pkt_size(pkt))))

#define cp_type7_opcode(pkt) (((pkt) >> 16) & 0x7F)
#define type7_pkt_size(pkt) ((pkt) & 0x3FFF)


/* note: not sure if CP_SET_DRAW_STATE counts as a complete extra level
 * of IB or if it is restricted to just have register writes:
 */
static int draws[3];
static int ib;

static int draw_filter;
static int draw_count;
static int current_draw_count;

/* query mode.. to handle symbolic register name queries, we need to
 * defer parsing query string until after gpu_id is know and rnn db
 * loaded:
 */
static char **querystrs;
static int *queryvals;
static int nquery;
static bool disasm;

static char *script;

static bool quiet(int lvl)
{
	if ((draw_filter != -1) && (draw_filter != current_draw_count))
		return true;
	if ((lvl >= 3) && (summary || querystrs || script))
		return true;
	if ((lvl >= 2) && (querystrs || script))
		return true;
	return false;
}

static void printl(int lvl, const char *fmt, ...)
{
	va_list args;
	if (quiet(lvl))
		return;
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
}

static const char *levels[] = {
		"\t",
		"\t\t",
		"\t\t\t",
		"\t\t\t\t",
		"\t\t\t\t\t",
		"\t\t\t\t\t\t",
		"\t\t\t\t\t\t\t",
		"\t\t\t\t\t\t\t\t",
		"\t\t\t\t\t\t\t\t\t",
		"x",
		"x",
		"x",
		"x",
		"x",
		"x",
};

static void dump_commands(uint32_t *dwords, uint32_t sizedwords, int level);
static void dump_register_val(uint32_t regbase, uint32_t dword, int level);
static const char *regname(uint32_t regbase, int color);
static uint32_t regbase(const char *name);

struct buffer {
	void *hostptr;
	unsigned int len;
	uint64_t gpuaddr;
};

static struct buffer buffers[512];
static int nbuffers;

static int buffer_contains_gpuaddr(struct buffer *buf, uint64_t gpuaddr, uint32_t len)
{
	return (buf->gpuaddr <= gpuaddr) && (gpuaddr < (buf->gpuaddr + buf->len));
}

static int buffer_contains_hostptr(struct buffer *buf, void *hostptr)
{
	return (buf->hostptr <= hostptr) && (hostptr < (buf->hostptr + buf->len));
}


static uint64_t gpuaddr(void *hostptr)
{
	int i;
	for (i = 0; i < nbuffers; i++)
		if (buffer_contains_hostptr(&buffers[i], hostptr))
			return buffers[i].gpuaddr + (hostptr - buffers[i].hostptr);
	return 0;
}

uint64_t gpubaseaddr(uint64_t gpuaddr)
{
	int i;
	if (!gpuaddr)
		return 0;
	for (i = 0; i < nbuffers; i++)
		if (buffer_contains_gpuaddr(&buffers[i], gpuaddr, 0))
			return buffers[i].gpuaddr;
	return 0;
}

static void *hostptr(uint64_t gpuaddr)
{
	int i;
	if (!gpuaddr)
		return 0;
	for (i = 0; i < nbuffers; i++)
		if (buffer_contains_gpuaddr(&buffers[i], gpuaddr, 0))
			return buffers[i].hostptr + (gpuaddr - buffers[i].gpuaddr);
	return 0;
}

unsigned hostlen(uint64_t gpuaddr)
{
	int i;
	if (!gpuaddr)
		return 0;
	for (i = 0; i < nbuffers; i++)
		if (buffer_contains_gpuaddr(&buffers[i], gpuaddr, 0))
			return buffers[i].len + buffers[i].gpuaddr - gpuaddr;
	return 0;
}

static void dump_hex(uint32_t *dwords, uint32_t sizedwords, int level)
{
	int i, j;
	int lastzero = 1;

	if (quiet(2))
		return;

	for (i = 0; i < sizedwords; i += 8) {
		int zero = 1;

		/* always show first row: */
		if (i == 0)
			zero = 0;

		for (j = 0; (j < 8) && (i+j < sizedwords) && zero; j++)
			if (dwords[i+j])
				zero = 0;

		if (zero && !lastzero)
			printf("*\n");

		lastzero = zero;

		if (zero)
			continue;

		if (is_64b()) {
			printf("%016lx:%s", gpuaddr(&dwords[i]), levels[level]);
		} else {
			printf("%08x:%s", (uint32_t)gpuaddr(&dwords[i]), levels[level]);
		}

		printf("%04x:", i * 4);

		for (j = 0; (j < 8) && (i+j < sizedwords); j++) {
			printf(" %08x", dwords[i+j]);
		}

		printf("\n");
	}
}

static void dump_float(float *dwords, uint32_t sizedwords, int level)
{
	int i;
	for (i = 0; i < sizedwords; i++) {
		if ((i % 8) == 0) {
			if (is_64b()) {
				printf("%016lx:%s", gpuaddr(dwords), levels[level]);
			} else {
				printf("%08x:%s", (uint32_t)gpuaddr(dwords), levels[level]);
			}
		} else {
			printf(" ");
		}
		printf("%8f", *(dwords++));
		if ((i % 8) == 7)
			printf("\n");
	}
	if (i % 8)
		printf("\n");
}

/* I believe the surface format is low bits:
#define RB_COLOR_INFO__COLOR_FORMAT_MASK                   0x0000000fL
comments in sys2gmem_tex_const indicate that address is [31:12], but
looks like at least some of the bits above the format have different meaning..
*/
static void parse_dword_addr(uint32_t dword, uint32_t *gpuaddr,
		uint32_t *flags, uint32_t mask)
{
	assert(!is_64b());  /* this is only used on a2xx */
	*gpuaddr = dword & ~mask;
	*flags   = dword & mask;
}

static uint32_t type0_reg_vals[0xffff + 1];
static uint8_t type0_reg_rewritten[sizeof(type0_reg_vals)/8];  /* written since last draw */
static uint8_t type0_reg_written[sizeof(type0_reg_vals)/8];
static uint32_t lastvals[ARRAY_SIZE(type0_reg_vals)];

static bool reg_rewritten(uint32_t regbase)
{
	return !!(type0_reg_rewritten[regbase/8] & (1 << (regbase % 8)));
}

bool reg_written(uint32_t regbase)
{
	return !!(type0_reg_written[regbase/8] & (1 << (regbase % 8)));
}

static void clear_rewritten(void)
{
	memset(type0_reg_rewritten, 0, sizeof(type0_reg_rewritten));
}

static void clear_written(void)
{
	memset(type0_reg_written, 0, sizeof(type0_reg_written));
	clear_rewritten();
}

uint32_t reg_lastval(uint32_t regbase)
{
	return lastvals[regbase];
}

static void clear_lastvals(void)
{
	memset(lastvals, 0, sizeof(lastvals));
}

uint32_t reg_val(uint32_t regbase)
{
	return type0_reg_vals[regbase];
}

static void reg_set(uint32_t regbase, uint32_t val)
{
	type0_reg_vals[regbase] = val;
	type0_reg_written[regbase/8] |= (1 << (regbase % 8));
	type0_reg_rewritten[regbase/8] |= (1 << (regbase % 8));
}

static void reg_dump_scratch(const char *name, uint32_t dword, int level)
{
	unsigned r;

	if (quiet(3))
		return;

	r = regbase("CP_SCRATCH[0].REG");

	// if not, try old a2xx/a3xx version:
	if (!r)
		r = regbase("CP_SCRATCH_REG0");

	if (!r)
		return;

	printf("%s:%u,%u,%u,%u\n", levels[level],
			reg_val(r + 4), reg_val(r + 5),
			reg_val(r + 6), reg_val(r + 7));
}

static void dump_gpuaddr_size(uint64_t gpuaddr, int level, int sizedwords, int quietlvl)
{
	void *buf;

	if (quiet(quietlvl))
		return;

	buf = hostptr(gpuaddr);
	if (buf) {
		dump_hex(buf, sizedwords, level+1);
	}
}

static void dump_gpuaddr(uint64_t gpuaddr, int level)
{
	dump_gpuaddr_size(gpuaddr, level, 64, 3);
}

static void reg_dump_gpuaddr(const char *name, uint32_t dword, int level)
{
	dump_gpuaddr(dword, level);
}

uint32_t gpuaddr_lo;
static void reg_gpuaddr_lo(const char *name, uint32_t dword, int level)
{
	gpuaddr_lo = dword;
}

static void reg_dump_gpuaddr_hi(const char *name, uint32_t dword, int level)
{
	dump_gpuaddr(gpuaddr_lo | (((uint64_t)dword) << 32), level);
}


static void dump_shader(const char *ext, void *buf, int bufsz)
{
	if (dump_shaders) {
		static int n = 0;
		char filename[8];
		int fd;
		sprintf(filename, "%04d.%s", n++, ext);
		fd = open(filename, O_WRONLY| O_TRUNC | O_CREAT, 0644);
		write(fd, buf, bufsz);
		close(fd);
	}
}

static void disasm_gpuaddr(const char *name, uint64_t gpuaddr, int level)
{
	void *buf;

	gpuaddr &= 0xfffffffffffffff0;

	if (quiet(3))
		return;

	buf = hostptr(gpuaddr);
	if (buf) {
		uint32_t sizedwords = hostlen(gpuaddr) / 4;
		const char *ext;

		dump_hex(buf, 64, level+1);
		disasm_a3xx(buf, sizedwords, level+2, stdout, gpu_id);

		/* this is a bit ugly way, but oh well.. */
		if (strstr(name, "SP_VS_OBJ")) {
			ext = "vo3";
		} else if (strstr(name, "SP_FS_OBJ")) {
			ext = "fo3";
		} else if (strstr(name, "SP_GS_OBJ")) {
			ext = "go3";
		} else if (strstr(name, "SP_CS_OBJ")) {
			ext = "co3";
		} else {
			ext = NULL;
		}

		if (ext)
			dump_shader(ext, buf, sizedwords * 4);
	}
}

static void reg_disasm_gpuaddr(const char *name, uint32_t dword, int level)
{
	disasm_gpuaddr(name, dword, level);
}

static void reg_disasm_gpuaddr_hi(const char *name, uint32_t dword, int level)
{
	disasm_gpuaddr(name, gpuaddr_lo | (((uint64_t)dword) << 32), level);
}

static void reg_dump_tex_samp_hi(const char *name, uint32_t dword, int level)
{
	reg_dump_gpuaddr_hi(name, dword, level); // XXX TODO
}

static void reg_dump_tex_const_hi(const char *name, uint32_t dword, int level)
{
	reg_dump_gpuaddr_hi(name, dword, level); // XXX TODO
}

/*
 * Registers with special handling (rnndec_decode() handles rest):
 */
#define REG(x, fxn) { #x, fxn }
static struct {
	const char *regname;
	void (*fxn)(const char *name, uint32_t dword, int level);
	uint32_t regbase;
} reg_a2xx[] = {
		REG(CP_SCRATCH_REG0, reg_dump_scratch),
		REG(CP_SCRATCH_REG1, reg_dump_scratch),
		REG(CP_SCRATCH_REG2, reg_dump_scratch),
		REG(CP_SCRATCH_REG3, reg_dump_scratch),
		REG(CP_SCRATCH_REG4, reg_dump_scratch),
		REG(CP_SCRATCH_REG5, reg_dump_scratch),
		REG(CP_SCRATCH_REG6, reg_dump_scratch),
		REG(CP_SCRATCH_REG7, reg_dump_scratch),
		{NULL},
}, reg_a3xx[] = {
		REG(CP_SCRATCH_REG0, reg_dump_scratch),
		REG(CP_SCRATCH_REG1, reg_dump_scratch),
		REG(CP_SCRATCH_REG2, reg_dump_scratch),
		REG(CP_SCRATCH_REG3, reg_dump_scratch),
		REG(CP_SCRATCH_REG4, reg_dump_scratch),
		REG(CP_SCRATCH_REG5, reg_dump_scratch),
		REG(CP_SCRATCH_REG6, reg_dump_scratch),
		REG(CP_SCRATCH_REG7, reg_dump_scratch),
		REG(VSC_SIZE_ADDRESS, reg_dump_gpuaddr),
		REG(SP_VS_PVT_MEM_ADDR_REG, reg_dump_gpuaddr),
		REG(SP_FS_PVT_MEM_ADDR_REG, reg_dump_gpuaddr),
		REG(SP_VS_OBJ_START_REG, reg_disasm_gpuaddr),
		REG(SP_FS_OBJ_START_REG, reg_disasm_gpuaddr),
		REG(TPL1_TP_FS_BORDER_COLOR_BASE_ADDR, reg_dump_gpuaddr),
		{NULL},
}, reg_a4xx[] = {
		REG(CP_SCRATCH[0].REG, reg_dump_scratch),
		REG(CP_SCRATCH[0x1].REG, reg_dump_scratch),
		REG(CP_SCRATCH[0x2].REG, reg_dump_scratch),
		REG(CP_SCRATCH[0x3].REG, reg_dump_scratch),
		REG(CP_SCRATCH[0x4].REG, reg_dump_scratch),
		REG(CP_SCRATCH[0x5].REG, reg_dump_scratch),
		REG(CP_SCRATCH[0x6].REG, reg_dump_scratch),
		REG(CP_SCRATCH[0x7].REG, reg_dump_scratch),
		REG(SP_VS_PVT_MEM_ADDR, reg_dump_gpuaddr),
		REG(SP_FS_PVT_MEM_ADDR, reg_dump_gpuaddr),
		REG(SP_GS_PVT_MEM_ADDR, reg_dump_gpuaddr),
		REG(SP_HS_PVT_MEM_ADDR, reg_dump_gpuaddr),
		REG(SP_DS_PVT_MEM_ADDR, reg_dump_gpuaddr),
		REG(SP_CS_PVT_MEM_ADDR, reg_dump_gpuaddr),
		REG(SP_VS_OBJ_START, reg_disasm_gpuaddr),
		REG(SP_FS_OBJ_START, reg_disasm_gpuaddr),
		REG(SP_GS_OBJ_START, reg_disasm_gpuaddr),
		REG(SP_HS_OBJ_START, reg_disasm_gpuaddr),
		REG(SP_DS_OBJ_START, reg_disasm_gpuaddr),
		REG(SP_CS_OBJ_START, reg_disasm_gpuaddr),
		REG(TPL1_TP_VS_BORDER_COLOR_BASE_ADDR, reg_dump_gpuaddr),
		REG(TPL1_TP_HS_BORDER_COLOR_BASE_ADDR, reg_dump_gpuaddr),
		REG(TPL1_TP_DS_BORDER_COLOR_BASE_ADDR, reg_dump_gpuaddr),
		REG(TPL1_TP_GS_BORDER_COLOR_BASE_ADDR, reg_dump_gpuaddr),
		REG(TPL1_TP_FS_BORDER_COLOR_BASE_ADDR, reg_dump_gpuaddr),
		{NULL},
}, reg_a5xx[] = {
		REG(CP_SCRATCH[0x4].REG, reg_dump_scratch),
		REG(CP_SCRATCH[0x5].REG, reg_dump_scratch),
		REG(CP_SCRATCH[0x6].REG, reg_dump_scratch),
		REG(CP_SCRATCH[0x7].REG, reg_dump_scratch),
		REG(SP_VS_OBJ_START_LO, reg_gpuaddr_lo),
		REG(SP_VS_OBJ_START_HI, reg_disasm_gpuaddr_hi),
		REG(SP_HS_OBJ_START_LO, reg_gpuaddr_lo),
		REG(SP_HS_OBJ_START_HI, reg_disasm_gpuaddr_hi),
		REG(SP_DS_OBJ_START_LO, reg_gpuaddr_lo),
		REG(SP_DS_OBJ_START_HI, reg_disasm_gpuaddr_hi),
		REG(SP_GS_OBJ_START_LO, reg_gpuaddr_lo),
		REG(SP_GS_OBJ_START_HI, reg_disasm_gpuaddr_hi),
		REG(SP_FS_OBJ_START_LO, reg_gpuaddr_lo),
		REG(SP_FS_OBJ_START_HI, reg_disasm_gpuaddr_hi),
		REG(SP_CS_OBJ_START_LO, reg_gpuaddr_lo),
		REG(SP_CS_OBJ_START_HI, reg_disasm_gpuaddr_hi),
		REG(TPL1_VS_TEX_CONST_LO, reg_gpuaddr_lo),
		REG(TPL1_VS_TEX_CONST_HI, reg_dump_tex_const_hi),
		REG(TPL1_VS_TEX_SAMP_LO,  reg_gpuaddr_lo),
		REG(TPL1_VS_TEX_SAMP_HI,  reg_dump_tex_samp_hi),
		REG(TPL1_HS_TEX_CONST_LO, reg_gpuaddr_lo),
		REG(TPL1_HS_TEX_CONST_HI, reg_dump_tex_const_hi),
		REG(TPL1_HS_TEX_SAMP_LO,  reg_gpuaddr_lo),
		REG(TPL1_HS_TEX_SAMP_HI,  reg_dump_tex_samp_hi),
		REG(TPL1_DS_TEX_CONST_LO, reg_gpuaddr_lo),
		REG(TPL1_DS_TEX_CONST_HI, reg_dump_tex_const_hi),
		REG(TPL1_DS_TEX_SAMP_LO,  reg_gpuaddr_lo),
		REG(TPL1_DS_TEX_SAMP_HI,  reg_dump_tex_samp_hi),
		REG(TPL1_GS_TEX_CONST_LO, reg_gpuaddr_lo),
		REG(TPL1_GS_TEX_CONST_HI, reg_dump_tex_const_hi),
		REG(TPL1_GS_TEX_SAMP_LO,  reg_gpuaddr_lo),
		REG(TPL1_GS_TEX_SAMP_HI,  reg_dump_tex_samp_hi),
		REG(TPL1_FS_TEX_CONST_LO, reg_gpuaddr_lo),
		REG(TPL1_FS_TEX_CONST_HI, reg_dump_tex_const_hi),
		REG(TPL1_FS_TEX_SAMP_LO,  reg_gpuaddr_lo),
		REG(TPL1_FS_TEX_SAMP_HI,  reg_dump_tex_samp_hi),
		REG(TPL1_CS_TEX_CONST_LO, reg_gpuaddr_lo),
		REG(TPL1_CS_TEX_CONST_HI, reg_dump_tex_const_hi),
		REG(TPL1_CS_TEX_SAMP_LO,  reg_gpuaddr_lo),
		REG(TPL1_CS_TEX_SAMP_HI,  reg_dump_tex_samp_hi),
		REG(TPL1_TP_BORDER_COLOR_BASE_ADDR_LO,  reg_gpuaddr_lo),
		REG(TPL1_TP_BORDER_COLOR_BASE_ADDR_HI,  reg_dump_gpuaddr_hi),
//		REG(RB_MRT_FLAG_BUFFER[0].ADDR_LO, reg_gpuaddr_lo),
//		REG(RB_MRT_FLAG_BUFFER[0].ADDR_HI, reg_dump_gpuaddr_hi),
//		REG(RB_MRT_FLAG_BUFFER[1].ADDR_LO, reg_gpuaddr_lo),
//		REG(RB_MRT_FLAG_BUFFER[1].ADDR_HI, reg_dump_gpuaddr_hi),
//		REG(RB_MRT_FLAG_BUFFER[2].ADDR_LO, reg_gpuaddr_lo),
//		REG(RB_MRT_FLAG_BUFFER[2].ADDR_HI, reg_dump_gpuaddr_hi),
//		REG(RB_MRT_FLAG_BUFFER[3].ADDR_LO, reg_gpuaddr_lo),
//		REG(RB_MRT_FLAG_BUFFER[3].ADDR_HI, reg_dump_gpuaddr_hi),
//		REG(RB_MRT_FLAG_BUFFER[4].ADDR_LO, reg_gpuaddr_lo),
//		REG(RB_MRT_FLAG_BUFFER[4].ADDR_HI, reg_dump_gpuaddr_hi),
//		REG(RB_MRT_FLAG_BUFFER[5].ADDR_LO, reg_gpuaddr_lo),
//		REG(RB_MRT_FLAG_BUFFER[5].ADDR_HI, reg_dump_gpuaddr_hi),
//		REG(RB_MRT_FLAG_BUFFER[6].ADDR_LO, reg_gpuaddr_lo),
//		REG(RB_MRT_FLAG_BUFFER[6].ADDR_HI, reg_dump_gpuaddr_hi),
//		REG(RB_MRT_FLAG_BUFFER[7].ADDR_LO, reg_gpuaddr_lo),
//		REG(RB_MRT_FLAG_BUFFER[7].ADDR_HI, reg_dump_gpuaddr_hi),
//		REG(RB_BLIT_FLAG_DST_LO, reg_gpuaddr_lo),
//		REG(RB_BLIT_FLAG_DST_HI, reg_dump_gpuaddr_hi),
//		REG(RB_MRT[0].BASE_LO, reg_gpuaddr_lo),
//		REG(RB_MRT[0].BASE_HI, reg_dump_gpuaddr_hi),
//		REG(RB_DEPTH_BUFFER_BASE_LO, reg_gpuaddr_lo),
//		REG(RB_DEPTH_BUFFER_BASE_HI, reg_dump_gpuaddr_hi),
//		REG(RB_DEPTH_FLAG_BUFFER_BASE_LO, reg_gpuaddr_lo),
//		REG(RB_DEPTH_FLAG_BUFFER_BASE_HI, reg_dump_gpuaddr_hi),
//		REG(RB_BLIT_DST_LO, reg_gpuaddr_lo),
//		REG(RB_BLIT_DST_HI, reg_dump_gpuaddr_hi),

//		REG(RB_2D_SRC_LO, reg_gpuaddr_lo),
//		REG(RB_2D_SRC_HI, reg_dump_gpuaddr_hi),
//		REG(RB_2D_SRC_FLAGS_LO, reg_gpuaddr_lo),
//		REG(RB_2D_SRC_FLAGS_HI, reg_dump_gpuaddr_hi),
//		REG(RB_2D_DST_LO, reg_gpuaddr_lo),
//		REG(RB_2D_DST_HI, reg_dump_gpuaddr_hi),
//		REG(RB_2D_DST_FLAGS_LO, reg_gpuaddr_lo),
//		REG(RB_2D_DST_FLAGS_HI, reg_dump_gpuaddr_hi),

		{NULL},
}, reg_a6xx[] = {
		REG(CP_SCRATCH[0x4].REG, reg_dump_scratch),
		REG(CP_SCRATCH[0x5].REG, reg_dump_scratch),
		REG(CP_SCRATCH[0x6].REG, reg_dump_scratch),
		REG(CP_SCRATCH[0x7].REG, reg_dump_scratch),

		REG(SP_VS_OBJ_START_LO, reg_gpuaddr_lo),
		REG(SP_VS_OBJ_START_HI, reg_disasm_gpuaddr_hi),
		REG(SP_HS_OBJ_START_LO, reg_gpuaddr_lo),
		REG(SP_HS_OBJ_START_HI, reg_disasm_gpuaddr_hi),
		REG(SP_DS_OBJ_START_LO, reg_gpuaddr_lo),
		REG(SP_DS_OBJ_START_HI, reg_disasm_gpuaddr_hi),
		REG(SP_GS_OBJ_START_LO, reg_gpuaddr_lo),
		REG(SP_GS_OBJ_START_HI, reg_disasm_gpuaddr_hi),
		REG(SP_FS_OBJ_START_LO, reg_gpuaddr_lo),
		REG(SP_FS_OBJ_START_HI, reg_disasm_gpuaddr_hi),
		REG(SP_CS_OBJ_START_LO, reg_gpuaddr_lo),
		REG(SP_CS_OBJ_START_HI, reg_disasm_gpuaddr_hi),

		REG(SP_VS_TEX_CONST_LO, reg_gpuaddr_lo),
		REG(SP_VS_TEX_CONST_HI, reg_dump_tex_const_hi),
		REG(SP_VS_TEX_SAMP_LO,  reg_gpuaddr_lo),
		REG(SP_VS_TEX_SAMP_HI,  reg_dump_tex_samp_hi),
		REG(SP_HS_TEX_CONST_LO, reg_gpuaddr_lo),
		REG(SP_HS_TEX_CONST_HI, reg_dump_tex_const_hi),
		REG(SP_HS_TEX_SAMP_LO,  reg_gpuaddr_lo),
		REG(SP_HS_TEX_SAMP_HI,  reg_dump_tex_samp_hi),
		REG(SP_DS_TEX_CONST_LO, reg_gpuaddr_lo),
		REG(SP_DS_TEX_CONST_HI, reg_dump_tex_const_hi),
		REG(SP_DS_TEX_SAMP_LO,  reg_gpuaddr_lo),
		REG(SP_DS_TEX_SAMP_HI,  reg_dump_tex_samp_hi),
		REG(SP_GS_TEX_CONST_LO, reg_gpuaddr_lo),
		REG(SP_GS_TEX_CONST_HI, reg_dump_tex_const_hi),
		REG(SP_GS_TEX_SAMP_LO,  reg_gpuaddr_lo),
		REG(SP_GS_TEX_SAMP_HI,  reg_dump_tex_samp_hi),
		REG(SP_FS_TEX_CONST_LO, reg_gpuaddr_lo),
		REG(SP_FS_TEX_CONST_HI, reg_dump_tex_const_hi),
		REG(SP_FS_TEX_SAMP_LO,  reg_gpuaddr_lo),
		REG(SP_FS_TEX_SAMP_HI,  reg_dump_tex_samp_hi),
		REG(SP_CS_TEX_CONST_LO, reg_gpuaddr_lo),
		REG(SP_CS_TEX_CONST_HI, reg_dump_tex_const_hi),
		REG(SP_CS_TEX_SAMP_LO,  reg_gpuaddr_lo),
		REG(SP_CS_TEX_SAMP_HI,  reg_dump_tex_samp_hi),

		{NULL},
}, *type0_reg;

static bool initialized = false;
static struct rnn *rnn;

static void init_rnn(const char *gpuname)
{
	rnn = rnn_new(no_color);

	rnn_load(rnn, gpuname);

	initialized = true;

	if (querystrs) {
		int i;
		queryvals = calloc(nquery, sizeof(queryvals[0]));

		for (i = 0; i < nquery; i++) {
			int val = strtol(querystrs[i], NULL, 0);

			if (val == 0)
				val = regbase(querystrs[i]);

			queryvals[i] = val;
			printf("querystr: %s -> 0x%x\n", querystrs[i], queryvals[i]);
		}
	}

	for (unsigned idx = 0; type0_reg[idx].regname; idx++) {
		type0_reg[idx].regbase = regbase(type0_reg[idx].regname);
		if (!type0_reg[idx].regbase) {
			printf("invalid register name: %s\n", type0_reg[idx].regname);
			exit(1);
		}
	}
}

static void init_a2xx(void)
{
	if (type0_reg == reg_a2xx)
		return;
	type0_reg = reg_a2xx;
	init_rnn("a2xx");
}

static void init_a3xx(void)
{
	if (type0_reg == reg_a3xx)
		return;
	type0_reg = reg_a3xx;
	init_rnn("a3xx");
}

static void init_a4xx(void)
{
	if (type0_reg == reg_a4xx)
		return;
	type0_reg = reg_a4xx;
	init_rnn("a4xx");
}

static void init_a5xx(void)
{
	if (type0_reg == reg_a5xx)
		return;
	type0_reg = reg_a5xx;
	init_rnn("a5xx");
}

static void init_a6xx(void)
{
	if (type0_reg == reg_a6xx)
		return;
	type0_reg = reg_a6xx;
	init_rnn("a6xx");
}

static void init(void)
{
	if (!initialized) {
		/* default to a2xx so we can still parse older rd files prior to RD_GPU_ID */
		init_a2xx();
	}
}

static const char *regname(uint32_t regbase, int color)
{
	init();
	return rnn_regname(rnn, regbase, color);
}

static uint32_t regbase(const char *name)
{
	init();
	return rnn_regbase(rnn, name);
}

static int endswith(uint32_t regbase, const char *suffix)
{
	const char *name = regname(regbase, 0);
	const char *s = strstr(name, suffix);
	if (!s)
		return 0;
	return (s - strlen(name) + strlen(suffix)) == name;
}

static void dump_register_val(uint32_t regbase, uint32_t dword, int level)
{
	struct rnndecaddrinfo *info = rnn_reginfo(rnn, regbase);

	if (info && info->typeinfo) {
		uint64_t gpuaddr = 0;
		char *decoded = rnndec_decodeval(rnn->vc, info->typeinfo, dword, info->width);
		printf("%s%s: %s", levels[level], info->name, decoded);

		/* Try and figure out if we are looking at a gpuaddr.. this
		 * might be useful for other gen's too, but at least a5xx has
		 * the _HI/_LO suffix we can look for.  Maybe a better approach
		 * would be some special annotation in the xml..
		 */
		if (gpu_id >= 500) {
			if (endswith(regbase, "_HI") && endswith(regbase-1, "_LO")) {
				gpuaddr = (((uint64_t)dword) << 32) | reg_val(regbase-1);
			} else if (endswith(regbase, "_LO") && endswith(regbase+1, "_HI")) {
				gpuaddr = (((uint64_t)reg_val(regbase+1)) << 32) | dword;
			}
		}

		if (gpuaddr && hostptr(gpuaddr)) {
			printf("\t\tbase=%lx, offset=%lu, size=%u",
					gpubaseaddr(gpuaddr),
					gpuaddr - gpubaseaddr(gpuaddr),
					hostlen(gpubaseaddr(gpuaddr)));

			if (disasm && (gpu_id >= 300)) {
				/* low bits of gpuaddr are actually some other bitfield: */
				gpuaddr &= ~0xf;
				printf("\n");
				disasm_a3xx(hostptr(gpuaddr), hostlen(gpuaddr) / 4,
						level + 1, stdout, gpu_id);
			}
		}

		printf("\n");

		free(decoded);
	} else if (info) {
		printf("%s%s: %08x\n", levels[level], info->name, dword);

	} else {
		printf("%s<%04x>: %08x\n", levels[level], regbase, dword);
	}

	if (info) {
		free(info->name);
		free(info);
	}
}

static void dump_register(uint32_t regbase, uint32_t dword, int level)
{
	init();

	if (!quiet(3)) {
		dump_register_val(regbase, dword, level);
	}

	for (unsigned idx = 0; type0_reg[idx].regname; idx++) {
		if (type0_reg[idx].regbase == regbase) {
			type0_reg[idx].fxn(type0_reg[idx].regname, dword, level);
			break;
		}
	}
}

static bool is_banked_reg(uint32_t regbase)
{
	return (0x2000 <= regbase) && (regbase < 0x2400);
}

static void dump_registers(uint32_t regbase,
		uint32_t *dwords, uint32_t sizedwords, int level)
{
	while (sizedwords--) {
		int last_summary = summary;

		/* access to non-banked registers needs a WFI:
		 * TODO banked register range for a2xx??
		 */
		if (needs_wfi && !is_banked_reg(regbase))
			printl(2, "NEEDS WFI: %s (%x)\n", regname(regbase, 1), regbase);

		reg_set(regbase, *dwords);
		dump_register(regbase, *dwords, level);
		regbase++;
		dwords++;
		summary = last_summary;
	}
}

static void dump_domain(uint32_t *dwords, uint32_t sizedwords, int level,
		const char *name)
{
	struct rnndomain *dom;
	int i;

	init();

	dom = rnn_finddomain(rnn->db, name);

	if (!dom)
		return;

	script_packet(dwords, sizedwords, rnn, dom);

	if (quiet(2))
		return;

	for (i = 0; i < sizedwords; i++) {
		struct rnndecaddrinfo *info = rnndec_decodeaddr(rnn->vc, dom, i, 0);
		char *decoded;
		if (!(info && info->typeinfo))
			break;
		decoded = rnndec_decodeval(rnn->vc, info->typeinfo, dwords[i], info->width);
		printf("%s%s\n", levels[level], decoded);
		free(decoded);
		free(info->name);
		free(info);
	}
}


static uint32_t bin_x1, bin_x2, bin_y1, bin_y2;
static unsigned mode;
static const char *render_mode;

/* well, actually query and script..
 * NOTE: call this before dump_register_summary()
 */
static void do_query(const char *primtype, uint32_t num_indices)
{
	int i;
	int n = 0;

	if ((500 <= gpu_id) && (gpu_id < 700)) {
		uint32_t scissor_tl = reg_val(regbase("GRAS_SC_WINDOW_SCISSOR_TL"));
		uint32_t scissor_br = reg_val(regbase("GRAS_SC_WINDOW_SCISSOR_BR"));

		bin_x1 = scissor_tl & 0xffff;
		bin_y1 = scissor_tl >> 16;
		bin_x2 = scissor_br & 0xffff;
		bin_y2 = scissor_br >> 16;
	}

	for (i = 0; i < nquery; i++) {
		uint32_t regbase = queryvals[i];
		if (reg_written(regbase)) {
			uint32_t lastval = reg_val(regbase);
			printf("%4d: %s(%u,%u-%u,%u):%u:", draw_count, primtype,
					bin_x1, bin_y1, bin_x2, bin_y2, num_indices);
			if (gpu_id >= 500)
				printf("%s:", render_mode);
			printf("\t%08x", lastval);
			if (lastval != lastvals[regbase]) {
				printf("!");
			} else {
				printf(" ");
			}
			if (reg_rewritten(regbase)) {
				printf("+");
			} else {
				printf(" ");
			}
			dump_register_val(regbase, lastval, 0);
			n++;
		}
	}

	if (n > 1)
		printf("\n");

	script_draw(primtype, num_indices);
}

static void cp_im_loadi(uint32_t *dwords, uint32_t sizedwords, int level)
{
	uint32_t start = dwords[1] >> 16;
	uint32_t size  = dwords[1] & 0xffff;
	const char *type = NULL, *ext = NULL;
	enum shader_t disasm_type;

	switch (dwords[0]) {
	case 0:
		type = "vertex";
		ext = "vo";
		disasm_type = SHADER_VERTEX;
		break;
	case 1:
		type = "fragment";
		ext = "fo";
		disasm_type = SHADER_FRAGMENT;
		break;
	default:
		type = "<unknown>";
		disasm_type = 0;
		break;
	}

	printf("%s%s shader, start=%04x, size=%04x\n", levels[level], type, start, size);
	disasm_a2xx(dwords + 2, sizedwords - 2, level+2, disasm_type);

	/* dump raw shader: */
	if (ext)
		dump_shader(ext, dwords + 2, (sizedwords - 2) * 4);
}

static void cp_wide_reg_write(uint32_t *dwords, uint32_t sizedwords, int level)
{
	uint32_t reg = dwords[0] & 0xffff;
	int i;
	for (i = 1; i < sizedwords; i++) {
		dump_register(reg, dwords[i], level+1);
		reg_set(reg, dwords[i]);
		reg++;
	}
}

enum state_t {
	TEX_SAMP = 1,
	TEX_CONST,
	TEX_MIPADDR,  /* a3xx only */
	SHADER_PROG,
	SHADER_CONST,

	// image/ssbo state:
	SSBO_0,
	SSBO_1,
	SSBO_2,

	UBO,

	// unknown things, just to hexdumps:
	UNKNOWN_DWORDS,
	UNKNOWN_2DWORDS,
	UNKNOWN_4DWORDS,
};

enum adreno_state_block {
	SB_VERT_TEX = 0,
	SB_VERT_MIPADDR = 1,
	SB_FRAG_TEX = 2,
	SB_FRAG_MIPADDR = 3,
	SB_VERT_SHADER = 4,
	SB_GEOM_SHADER = 5,
	SB_FRAG_SHADER = 6,
	SB_COMPUTE_SHADER = 7,
};

/* TODO there is probably a clever way to let rnndec parse things so
 * we don't have to care about packet format differences across gens
 */

static void
a3xx_get_state_type(uint32_t *dwords, enum shader_t *stage, enum state_t *state)
{
	unsigned state_block_id = (dwords[0] >> 19) & 0x7;
	unsigned state_type = dwords[1] & 0x3;
	static const struct {
		enum shader_t stage;
		enum state_t state;
	} lookup[0xf][0x3] = {
		[SB_VERT_TEX][0]    = { SHADER_VERTEX,    TEX_SAMP },
		[SB_VERT_TEX][1]    = { SHADER_VERTEX,    TEX_CONST },
		[SB_FRAG_TEX][0]    = { SHADER_FRAGMENT,  TEX_SAMP },
		[SB_FRAG_TEX][1]    = { SHADER_FRAGMENT,  TEX_CONST },
		[SB_VERT_SHADER][0] = { SHADER_VERTEX,    SHADER_PROG },
		[SB_VERT_SHADER][1] = { SHADER_VERTEX,    SHADER_CONST },
		[SB_FRAG_SHADER][0] = { SHADER_FRAGMENT,  SHADER_PROG },
		[SB_FRAG_SHADER][1] = { SHADER_FRAGMENT,  SHADER_CONST },
	};

	*stage = lookup[state_block_id][state_type].stage;
	*state = lookup[state_block_id][state_type].state;
}

static void
_get_state_type(unsigned state_block_id, unsigned state_type,
		enum shader_t *stage, enum state_t *state)
{
	static const struct {
		enum shader_t stage;
		enum state_t  state;
	} lookup[0x10][0x4] = {
		// SB4_VS_TEX:
		[0x0][0] = { SHADER_VERTEX,    TEX_SAMP },
		[0x0][1] = { SHADER_VERTEX,    TEX_CONST },
		[0x0][2] = { SHADER_VERTEX,    UBO },
		// SB4_HS_TEX:
		[0x1][0] = { SHADER_TCS,       TEX_SAMP },
		[0x1][1] = { SHADER_TCS,       TEX_CONST },
		[0x1][2] = { SHADER_TCS,       UBO },
		// SB4_DS_TEX:
		[0x2][0] = { SHADER_TES,       TEX_SAMP },
		[0x2][1] = { SHADER_TES,       TEX_CONST },
		[0x2][2] = { SHADER_TES,       UBO },
		// SB4_GS_TEX:
		[0x3][0] = { SHADER_GEOM,      TEX_SAMP },
		[0x3][1] = { SHADER_GEOM,      TEX_CONST },
		[0x3][2] = { SHADER_GEOM,      UBO },
		// SB4_FS_TEX:
		[0x4][0] = { SHADER_FRAGMENT,  TEX_SAMP },
		[0x4][1] = { SHADER_FRAGMENT,  TEX_CONST },
		[0x4][2] = { SHADER_FRAGMENT,  UBO },
		// SB4_CS_TEX:
		[0x5][0] = { SHADER_COMPUTE,   TEX_SAMP },
		[0x5][1] = { SHADER_COMPUTE,   TEX_CONST },
		[0x5][2] = { SHADER_COMPUTE,   UBO },
		// SB4_VS_SHADER:
		[0x8][0] = { SHADER_VERTEX,    SHADER_PROG },
		[0x8][1] = { SHADER_VERTEX,    SHADER_CONST },
		[0x8][2] = { SHADER_VERTEX,    UBO },
		// SB4_HS_SHADER
		[0x9][0] = { SHADER_TCS,       SHADER_PROG },
		[0x9][1] = { SHADER_TCS,       SHADER_CONST },
		[0x9][2] = { SHADER_TCS,       UBO },
		// SB4_DS_SHADER
		[0xa][0] = { SHADER_TES,       SHADER_PROG },
		[0xa][1] = { SHADER_TES,       SHADER_CONST },
		[0xa][2] = { SHADER_TES,       UBO },
		// SB4_GS_SHADER
		[0xb][0] = { SHADER_GEOM,      SHADER_PROG },
		[0xb][1] = { SHADER_GEOM,      SHADER_CONST },
		[0xb][2] = { SHADER_GEOM,      UBO },
		// SB4_FS_SHADER:
		[0xc][0] = { SHADER_FRAGMENT,  SHADER_PROG },
		[0xc][1] = { SHADER_FRAGMENT,  SHADER_CONST },
		[0xc][2] = { SHADER_FRAGMENT,  UBO },
		// SB4_CS_SHADER:
		[0xd][0] = { SHADER_COMPUTE,   SHADER_PROG },
		[0xd][1] = { SHADER_COMPUTE,   SHADER_CONST },
		[0xd][2] = { SHADER_COMPUTE,   UBO },
		[0xd][3] = { SHADER_COMPUTE,   SSBO_0 },      /* a6xx location */
		// SB4_SSBO (shared across all stages)
		[0xe][0] = { 0, SSBO_0 },                     /* a5xx (and a4xx?) location */
		[0xe][1] = { 0, SSBO_1 },
		[0xe][2] = { 0, SSBO_2 },
		// SB4_CS_SSBO
		[0xf][0] = { SHADER_COMPUTE, SSBO_0 },
		[0xf][1] = { SHADER_COMPUTE, SSBO_1 },
		[0xf][2] = { SHADER_COMPUTE, SSBO_2 },
		// unknown things
		/* This looks like combined UBO state for 3d stages (a5xx and
		 * before??  I think a6xx has UBO state per shader stage:
		 */
		[0x6][2] = { 0, UBO },
		[0x7][1] = { 0, UNKNOWN_2DWORDS },
	};

	*stage = lookup[state_block_id][state_type].stage;
	*state = lookup[state_block_id][state_type].state;
}

static void
a4xx_get_state_type(uint32_t *dwords, enum shader_t *stage, enum state_t *state)
{
	unsigned state_block_id = (dwords[0] >> 18) & 0xf;
	unsigned state_type = dwords[1] & 0x3;
	_get_state_type(state_block_id, state_type, stage, state);
}

static void
a6xx_get_state_type(uint32_t *dwords, enum shader_t *stage, enum state_t *state)
{
	unsigned state_block_id = (dwords[0] >> 18) & 0xf;
	unsigned state_type = (dwords[0] >> 14) & 0x3;
	_get_state_type(state_block_id, state_type, stage, state);
}

static void cp_load_state(uint32_t *dwords, uint32_t sizedwords, int level)
{
	enum shader_t stage;
	enum state_t state;
	uint32_t num_unit = (dwords[0] >> 22) & 0x1ff;
	uint64_t ext_src_addr;
	void *contents = NULL;
	int i;

	if (quiet(2) && !script)
		return;

	if (gpu_id >= 600)
		a6xx_get_state_type(dwords, &stage, &state);
	else if (gpu_id >= 400)
		a4xx_get_state_type(dwords, &stage, &state);
	else
		a3xx_get_state_type(dwords, &stage, &state);

	if (is_64b()) {
		ext_src_addr = dwords[1] & 0xfffffffc;
		ext_src_addr |= ((uint64_t)dwords[2]) << 32;
		contents = dwords + 3;
	} else {
		ext_src_addr = dwords[1] & 0xfffffffc;
		contents = dwords + 2;
	}

	/* we could either have a ptr to other gpu buffer, or directly have
	 * contents inline:
	 */
	if (ext_src_addr)
		contents = hostptr(ext_src_addr);

	if (!contents)
		return;

	switch (state) {
	case SHADER_PROG: {
		const char *ext = NULL;

		if (quiet(2))
			return;

		if (gpu_id >= 400)
			num_unit *= 16;
		else if (gpu_id >= 300)
			num_unit *= 4;

		/* shaders:
		 *
		 * note: num_unit seems to be # of instruction groups, where
		 * an instruction group has 4 64bit instructions.
		 */
		if (stage == SHADER_VERTEX) {
			ext = "vo3";
		} else if (stage == SHADER_GEOM) {
			ext = "go3";
		} else if (stage == SHADER_COMPUTE) {
			ext = "co3";
		} else if (stage == SHADER_FRAGMENT){
			ext = "fo3";
		}

		if (contents)
			disasm_a3xx(contents, num_unit * 2, level+2, stdout, gpu_id);

		/* dump raw shader: */
		if (ext)
			dump_shader(ext, contents, num_unit * 2 * 4);

		break;
	}
	case SHADER_CONST: {
		if (quiet(2))
			return;

		/* uniforms/consts:
		 *
		 * note: num_unit seems to be # of pairs of dwords??
		 */

		if (gpu_id >= 400)
			num_unit *= 2;

		dump_float(contents, num_unit*2, level+1);
		dump_hex(contents, num_unit*2, level+1);

		break;
	}
	case TEX_MIPADDR: {
		uint32_t *addrs = contents;

		if (quiet(2))
			return;

		/* mipmap consts block just appears to be array of num_unit gpu addr's: */
		for (i = 0; i < num_unit; i++) {
			void *ptr = hostptr(addrs[i]);
			printf("%s%2d: %08x\n", levels[level+1], i, addrs[i]);
			if (dump_textures) {
				printf("base=%08x\n", (uint32_t)gpubaseaddr(addrs[i]));
				dump_hex(ptr, hostlen(addrs[i])/4, level+1);
			}
		}
		break;
	}
	case TEX_SAMP: {
		uint32_t *texsamp = (uint32_t *)contents;
		for (i = 0; i < num_unit; i++) {
			/* work-around to reduce noise for opencl blob which always
			 * writes the max # regardless of # of textures used
			 */
			if ((num_unit == 16) && (texsamp[0] == 0) && (texsamp[1] == 0))
				break;

			if ((300 <= gpu_id) && (gpu_id < 400)) {
				dump_domain(texsamp, 2, level+2, "A3XX_TEX_SAMP");
				dump_hex(texsamp, 2, level+1);
				texsamp += 2;
			} else if ((400 <= gpu_id) && (gpu_id < 500)) {
				dump_domain(texsamp, 2, level+2, "A4XX_TEX_SAMP");
				dump_hex(texsamp, 2, level+1);
				texsamp += 2;
			} else if ((500 <= gpu_id) && (gpu_id < 600)) {
				dump_domain(texsamp, 4, level+2, "A5XX_TEX_SAMP");
				dump_hex(texsamp, 4, level+1);
				texsamp += 4;
			} else if ((600 <= gpu_id) && (gpu_id < 700)) {
				dump_domain(texsamp, 4, level+2, "A6XX_TEX_SAMP");
				dump_hex(texsamp, 4, level+1);
				texsamp += 4;
			}
		}
		break;
	}
	case TEX_CONST: {
		uint32_t *texconst = (uint32_t *)contents;

		for (i = 0; i < num_unit; i++) {
			/* work-around to reduce noise for opencl blob which always
			 * writes the max # regardless of # of textures used
			 */
			if ((num_unit == 16) &&
				(texconst[0] == 0) && (texconst[1] == 0) &&
				(texconst[2] == 0) && (texconst[3] == 0))
				break;

			if ((300 <= gpu_id) && (gpu_id < 400)) {
				dump_domain(texconst, 4, level+2, "A3XX_TEX_CONST");
				dump_hex(texconst, 4, level+1);
				texconst += 4;
			} else if ((400 <= gpu_id) && (gpu_id < 500)) {
				dump_domain(texconst, 8, level+2, "A4XX_TEX_CONST");
				if (dump_textures) {
					uint32_t addr = texconst[4] & ~0x1f;
					dump_gpuaddr(addr, level-2);
				}
				dump_hex(texconst, 8, level+1);
				texconst += 8;
			} else if ((500 <= gpu_id) && (gpu_id < 600)) {
				dump_domain(texconst, 12, level+2, "A5XX_TEX_CONST");
				if (dump_textures) {
					uint64_t addr = (((uint64_t)texconst[5] & 0x1ffff) << 32) | texconst[4];
					dump_gpuaddr_size(addr, level-2, hostlen(addr) / 4, 3);
				}
				dump_hex(texconst, 12, level+1);
				texconst += 12;
			} else if ((600 <= gpu_id) && (gpu_id < 700)) {
				dump_domain(texconst, 16, level+2, "A6XX_TEX_CONST");
				if (dump_textures) {
					uint64_t addr = (((uint64_t)texconst[5] & 0x1ffff) << 32) | texconst[4];
					dump_gpuaddr_size(addr, level-2, hostlen(addr) / 4, 3);
				}
				dump_hex(texconst, 16, level+1);
				texconst += 16;
			}
		}
		break;
	}
	case SSBO_0: {
		uint32_t *ssboconst = (uint32_t *)contents;

		for (i = 0; i < num_unit; i++) {
			int sz = 4;
			if (400 <= gpu_id && gpu_id < 500) {
				dump_domain(ssboconst, 4, level+2, "A4XX_SSBO_0");
			} else if (500 <= gpu_id && gpu_id < 600) {
				dump_domain(ssboconst, 4, level+2, "A5XX_SSBO_0");
			} else if (600 <= gpu_id && gpu_id < 700) {
				sz = 16;
				dump_domain(ssboconst, 16, level+2, "A6XX_IBO");
			}
			dump_hex(ssboconst, sz, level+1);
			ssboconst += sz;
		}
		break;
	}
	case SSBO_1: {
		uint32_t *ssboconst = (uint32_t *)contents;

		for (i = 0; i < num_unit; i++) {
			if (400 <= gpu_id && gpu_id < 500)
				dump_domain(ssboconst, 2, level+2, "A4XX_SSBO_1");
			else if (500 <= gpu_id && gpu_id < 600)
				dump_domain(ssboconst, 2, level+2, "A5XX_SSBO_1");
			dump_hex(ssboconst, 2, level+1);
			ssboconst += 2;
		}
		break;
	}
	case SSBO_2: {
		uint32_t *ssboconst = (uint32_t *)contents;

		for (i = 0; i < num_unit; i++) {
			/* TODO a4xx and a5xx might be same: */
			if ((500 <= gpu_id) && (gpu_id < 600)) {
				dump_domain(ssboconst, 2, level+2, "A5XX_SSBO_2");
				dump_hex(ssboconst, 2, level+1);
			}
			if (dump_textures) {
				uint64_t addr = (((uint64_t)ssboconst[1] & 0x1ffff) << 32) | ssboconst[0];
				dump_gpuaddr_size(addr, level-2, hostlen(addr) / 4, 3);
			}
			ssboconst += 2;
		}
		break;
	}
	case UBO: {
		uint32_t *uboconst = (uint32_t *)contents;

		for (i = 0; i < num_unit; i++) {
			// TODO probably similar on a4xx..
			if (500 <= gpu_id && gpu_id < 600)
				dump_domain(uboconst, 2, level+2, "A5XX_UBO");
			else if (600 <= gpu_id && gpu_id < 700)
				dump_domain(uboconst, 2, level+2, "A6XX_UBO");
			dump_hex(uboconst, 2, level+1);
			uboconst += 2;
		}
		break;
	}
	case UNKNOWN_DWORDS: {
		if (quiet(2))
			return;
		dump_hex(contents, num_unit, level+1);
		break;
	}
	case UNKNOWN_2DWORDS: {
		if (quiet(2))
			return;
		dump_hex(contents, num_unit * 2, level+1);
		break;
	}
	case UNKNOWN_4DWORDS: {
		if (quiet(2))
			return;
		dump_hex(contents, num_unit * 4, level+1);
		break;
	}
	default:
		if (quiet(2))
			return;
		/* hmm.. */
		dump_hex(contents, num_unit, level+1);
		break;
	}
}

static void cp_set_bin(uint32_t *dwords, uint32_t sizedwords, int level)
{
	bin_x1 = dwords[1] & 0xffff;
	bin_y1 = dwords[1] >> 16;
	bin_x2 = dwords[2] & 0xffff;
	bin_y2 = dwords[2] >> 16;
}

static void dump_tex_const(uint32_t *dwords, uint32_t sizedwords, uint32_t val, int level)
{
	uint32_t w, h, p;
	uint32_t gpuaddr, flags, mip_gpuaddr, mip_flags;
	uint32_t min, mag, swiz, clamp_x, clamp_y, clamp_z;
	static const char *filter[] = {
			"point", "bilinear", "bicubic",
	};
	static const char *clamp[] = {
			"wrap", "mirror", "clamp-last-texel",
	};
	static const char swiznames[] = "xyzw01??";

	/* see sys2gmem_tex_const[] in adreno_a2xxx.c */

	/* Texture, FormatXYZW=Unsigned, ClampXYZ=Wrap/Repeat,
	 * RFMode=ZeroClamp-1, Dim=1:2d, pitch
	 */
	p = (dwords[0] >> 22) << 5;
	clamp_x = (dwords[0] >> 10) & 0x3;
	clamp_y = (dwords[0] >> 13) & 0x3;
	clamp_z = (dwords[0] >> 16) & 0x3;

	/* Format=6:8888_WZYX, EndianSwap=0:None, ReqSize=0:256bit, DimHi=0,
	 * NearestClamp=1:OGL Mode
	 */
	parse_dword_addr(dwords[1], &gpuaddr, &flags, 0xfff);

	/* Width, Height, EndianSwap=0:None */
	w = (dwords[2] & 0x1fff) + 1;
	h = ((dwords[2] >> 13) & 0x1fff) + 1;

	/* NumFormat=0:RF, DstSelXYZW=XYZW, ExpAdj=0, MagFilt=MinFilt=0:Point,
	 * Mip=2:BaseMap
	 */
	mag = (dwords[3] >> 19) & 0x3;
	min = (dwords[3] >> 21) & 0x3;
	swiz = (dwords[3] >> 1) & 0xfff;

	/* VolMag=VolMin=0:Point, MinMipLvl=0, MaxMipLvl=1, LodBiasH=V=0,
	 * Dim3d=0
	 */
	// XXX

	/* BorderColor=0:ABGRBlack, ForceBC=0:diable, TriJuice=0, Aniso=0,
	 * Dim=1:2d, MipPacking=0
	 */
	parse_dword_addr(dwords[5], &mip_gpuaddr, &mip_flags, 0xfff);

	printf("%sset texture const %04x\n", levels[level], val);
	printf("%sclamp x/y/z: %s/%s/%s\n", levels[level+1],
			clamp[clamp_x], clamp[clamp_y], clamp[clamp_z]);
	printf("%sfilter min/mag: %s/%s\n", levels[level+1], filter[min], filter[mag]);
	printf("%sswizzle: %c%c%c%c\n", levels[level+1],
			swiznames[(swiz >> 0) & 0x7], swiznames[(swiz >> 3) & 0x7],
			swiznames[(swiz >> 6) & 0x7], swiznames[(swiz >> 9) & 0x7]);
	printf("%saddr=%08x (flags=%03x), size=%dx%d, pitch=%d, format=%s\n",
			levels[level+1], gpuaddr, flags, w, h, p,
			rnn_enumname(rnn, "a2xx_sq_surfaceformat", flags & 0xf));
	printf("%smipaddr=%08x (flags=%03x)\n", levels[level+1],
			mip_gpuaddr, mip_flags);
}

static void dump_shader_const(uint32_t *dwords, uint32_t sizedwords, uint32_t val, int level)
{
	int i;
	printf("%sset shader const %04x\n", levels[level], val);
	for (i = 0; i < sizedwords; ) {
		uint32_t gpuaddr, flags;
		parse_dword_addr(dwords[i++], &gpuaddr, &flags, 0xf);
		void *addr = hostptr(gpuaddr);
		if (addr) {
			const char * fmt =
				rnn_enumname(rnn, "a2xx_sq_surfaceformat", flags & 0xf);
			uint32_t size = dwords[i++];
			printf("%saddr=%08x, size=%d, format=%s\n", levels[level+1],
					gpuaddr, size, fmt);
			// TODO maybe dump these as bytes instead of dwords?
			size = (size + 3) / 4; // for now convert to dwords
			dump_hex(addr, min(size, 64), level + 1);
			if (size > min(size, 64))
				printf("%s\t\t...\n", levels[level+1]);
			dump_float(addr, min(size, 64), level + 1);
			if (size > min(size, 64))
				printf("%s\t\t...\n", levels[level+1]);
		}
	}
}

static void cp_set_const(uint32_t *dwords, uint32_t sizedwords, int level)
{
	uint32_t val = dwords[0] & 0xffff;
	switch((dwords[0] >> 16) & 0xf) {
	case 0x0:
		dump_float((float *)(dwords+1), sizedwords-1, level+1);
		break;
	case 0x1:
		/* need to figure out how const space is partitioned between
		 * attributes, textures, etc..
		 */
		if (val < 0x78) {
			dump_tex_const(dwords+1, sizedwords-1, val, level);
		} else {
			dump_shader_const(dwords+1, sizedwords-1, val, level);
		}
		break;
	case 0x2:
		printf("%sset bool const %04x\n", levels[level], val);
		break;
	case 0x3:
		printf("%sset loop const %04x\n", levels[level], val);
		break;
	case 0x4:
		val += 0x2000;
		if (dwords[0] & 0x80000000) {
			uint32_t srcreg = dwords[1];
			uint32_t dstval = dwords[2];

			/* TODO: not sure what happens w/ payload != 2.. */
			assert(sizedwords == 3);
			assert(srcreg < ARRAY_SIZE(type0_reg_vals));

			/* note: rnn_regname uses a static buf so we can't do
			 * two regname() calls for one printf..
			 */
			printf("%s%s = %08x + ", levels[level], regname(val, 1), dstval);
			printf("%s (%08x)\n", regname(srcreg, 1), type0_reg_vals[srcreg]);

			dstval += type0_reg_vals[srcreg];

			dump_registers(val, &dstval, 1, level+1);
		} else {
			dump_registers(val, dwords+1, sizedwords-1, level+1);
		}
		break;
	}
}

static void dump_register_summary(int level);

static void cp_event_write(uint32_t *dwords, uint32_t sizedwords, int level)
{
	const char *name = rnn_enumname(rnn, "vgt_event_type", dwords[0]);
	printl(2, "%sevent %s\n", levels[level], name);

	if (name && (gpu_id > 500)) {
		char eventname[64];
		snprintf(eventname, sizeof(eventname), "EVENT:%s", name);
		if (!strcmp(name, "BLIT")) {
			do_query(eventname, 0);
			dump_register_summary(level);
		}
	}
}

static void dump_register_summary(int level)
{
	uint32_t i;
	bool saved_summary = summary;
	summary = false;

	/* dump current state of registers: */
	printl(2, "%sdraw[%i] register values\n", levels[level], draw_count);
	for (i = 0; i < regcnt(); i++) {
		uint32_t regbase = i;
		uint32_t lastval = reg_val(regbase);
		/* skip registers that haven't been updated since last draw/blit: */
		if (!(allregs || reg_rewritten(regbase)))
			continue;
		if (!reg_written(regbase))
			continue;
		if (lastval != lastvals[regbase]) {
			printl(2, "!");
			lastvals[regbase] = lastval;
		} else {
			printl(2, " ");
		}
		if (reg_rewritten(regbase)) {
			printl(2, "+");
		} else {
			printl(2, " ");
		}
		printl(2, "\t%08x", lastval);
		if (!quiet(2)) {
			dump_register(regbase, lastval, level);
		}
	}

	clear_rewritten();

	draw_count++;
	summary = saved_summary;
}

static uint32_t draw_indx_common(uint32_t *dwords, int level)
{
	uint32_t prim_type     = dwords[1] & 0x1f;
	uint32_t source_select = (dwords[1] >> 6) & 0x3;
	uint32_t num_indices   = dwords[2];
	const char *primtype;

	primtype = rnn_enumname(rnn, "pc_di_primtype", prim_type);

	do_query(primtype, num_indices);

	printl(2, "%sdraw:          %d\n", levels[level], draws[ib]);
	printl(2, "%sprim_type:     %s (%d)\n", levels[level], primtype,
			prim_type);
	printl(2, "%ssource_select: %s (%d)\n", levels[level],
			rnn_enumname(rnn, "pc_di_src_sel", source_select),
			source_select);
	printl(2, "%snum_indices:   %d\n", levels[level], num_indices);

	vertices += num_indices;

	draws[ib]++;

	return num_indices;
}

enum pc_di_index_size {
	INDEX_SIZE_IGN = 0,
	INDEX_SIZE_16_BIT = 0,
	INDEX_SIZE_32_BIT = 1,
	INDEX_SIZE_8_BIT = 2,
	INDEX_SIZE_INVALID = 0,
};

static void cp_draw_indx(uint32_t *dwords, uint32_t sizedwords, int level)
{
	uint32_t num_indices = draw_indx_common(dwords, level);

	assert(!is_64b());

	/* if we have an index buffer, dump that: */
	if (sizedwords == 5) {
		void *ptr = hostptr(dwords[3]);
		printl(2, "%sgpuaddr:       %08x\n", levels[level], dwords[3]);
		printl(2, "%sidx_size:      %d\n", levels[level], dwords[4]);
		if (ptr) {
			enum pc_di_index_size size =
					((dwords[1] >> 11) & 1) | ((dwords[1] >> 12) & 2);
			if (!quiet(2)) {
				int i;
				printf("%sidxs:         ", levels[level]);
				if (size == INDEX_SIZE_8_BIT) {
					uint8_t *idx = ptr;
					for (i = 0; i < dwords[4]; i++)
						printf(" %u", idx[i]);
				} else if (size == INDEX_SIZE_16_BIT) {
					uint16_t *idx = ptr;
					for (i = 0; i < dwords[4]/2; i++)
						printf(" %u", idx[i]);
				} else if (size == INDEX_SIZE_32_BIT) {
					uint32_t *idx = ptr;
					for (i = 0; i < dwords[4]/4; i++)
						printf(" %u", idx[i]);
				}
				printf("\n");
				dump_hex(ptr, dwords[4]/4, level+1);
			}
		}
	}

	/* don't bother dumping registers for the dummy draw_indx's.. */
	if (num_indices > 0)
		dump_register_summary(level);

	needs_wfi = true;
}

static void cp_draw_indx_2(uint32_t *dwords, uint32_t sizedwords, int level)
{
	uint32_t num_indices = draw_indx_common(dwords, level);
	enum pc_di_index_size size =
			((dwords[1] >> 11) & 1) | ((dwords[1] >> 12) & 2);
	void *ptr = &dwords[3];
	int sz = 0;

	assert(!is_64b());

	/* CP_DRAW_INDX_2 has embedded/inline idx buffer: */
	if (!quiet(2)) {
		int i;
		printf("%sidxs:         ", levels[level]);
		if (size == INDEX_SIZE_8_BIT) {
			uint8_t *idx = ptr;
			for (i = 0; i < num_indices; i++)
				printf(" %u", idx[i]);
			sz = num_indices;
		} else if (size == INDEX_SIZE_16_BIT) {
			uint16_t *idx = ptr;
			for (i = 0; i < num_indices; i++)
				printf(" %u", idx[i]);
			sz = num_indices * 2;
		} else if (size == INDEX_SIZE_32_BIT) {
			uint32_t *idx = ptr;
			for (i = 0; i < num_indices; i++)
				printf(" %u", idx[i]);
			sz = num_indices * 4;
		}
		printf("\n");
		dump_hex(ptr, sz / 4, level+1);
	}

	/* don't bother dumping registers for the dummy draw_indx's.. */
	if (num_indices > 0)
		dump_register_summary(level);
}

static void cp_draw_indx_offset(uint32_t *dwords, uint32_t sizedwords, int level)
{
	uint32_t num_indices = dwords[2];
	uint32_t prim_type = dwords[0] & 0x1f;

	do_query(rnn_enumname(rnn, "pc_di_primtype", prim_type), num_indices);

	if ((gpu_id >= 500) && !quiet(2)) {
		printf("%smode: %s\n", levels[level], render_mode);
	}

	/* don't bother dumping registers for the dummy draw_indx's.. */
	if (num_indices > 0)
		dump_register_summary(level);
}

static void cp_draw_indx_indirect(uint32_t *dwords, uint32_t sizedwords, int level)
{
	uint32_t prim_type = dwords[0] & 0x1f;
	uint64_t addr;

	do_query(rnn_enumname(rnn, "pc_di_primtype", prim_type), 0);

	if ((gpu_id >= 500) && !quiet(2)) {
		printf("%smode: %s\n", levels[level], render_mode);
	}

	if (is_64b())
		addr = (((uint64_t)dwords[2] & 0x1ffff) << 32) | dwords[1];
	else
		addr = dwords[1];
	dump_gpuaddr_size(addr, level, 0x10, 2);

	if (is_64b())
		addr = (((uint64_t)dwords[5] & 0x1ffff) << 32) | dwords[4];
	else
		addr = dwords[3];
	dump_gpuaddr_size(addr, level, 0x10, 2);

	dump_register_summary(level);
}

static void cp_draw_indirect(uint32_t *dwords, uint32_t sizedwords, int level)
{
	uint32_t prim_type = dwords[0] & 0x1f;
	uint64_t addr;

	do_query(rnn_enumname(rnn, "pc_di_primtype", prim_type), 0);

	if ((gpu_id >= 500) && !quiet(2)) {
		printf("%smode: %s\n", levels[level], render_mode);
	}

	addr = (((uint64_t)dwords[2] & 0x1ffff) << 32) | dwords[1];
	dump_gpuaddr_size(addr, level, 0x10, 2);

	dump_register_summary(level);
}

static void cp_run_cl(uint32_t *dwords, uint32_t sizedwords, int level)
{
	do_query("COMPUTE", 1);
	dump_register_summary(level);
}

static void cp_nop(uint32_t *dwords, uint32_t sizedwords, int level)
{
	const char *buf = (void *)dwords;
	int i;

	if (quiet(3))
		return;

	// blob doesn't use CP_NOP for string_marker but it does
	// use it for things that end up looking like, but aren't
	// ascii chars:
	if (is_blob)
		return;

	for (i = 0; i < 4 * sizedwords; i++) {
		if (buf[i] == '\0')
			break;
		if (isascii(buf[i]))
			printf("%c", buf[i]);
	}
	printf("\n");
}

static void cp_indirect(uint32_t *dwords, uint32_t sizedwords, int level)
{
	/* traverse indirect buffers */
	uint64_t ibaddr;
	uint32_t ibsize;
	uint32_t *ptr = NULL;

	if (is_64b()) {
		/* a5xx+.. high 32b of gpu addr, then size: */
		ibaddr = dwords[0];
		ibaddr |= ((uint64_t)dwords[1]) << 32;
		ibsize = dwords[2];
	} else {
		ibaddr = dwords[0];
		ibsize = dwords[1];
	}

	if (!quiet(3)) {
		if (is_64b()) {
			printf("%sibaddr:%016lx\n", levels[level], ibaddr);
		} else {
			printf("%sibaddr:%08x\n", levels[level], (uint32_t)ibaddr);
		}
		printf("%sibsize:%08x\n", levels[level], ibsize);
	} else {
		level--;
	}

	/* map gpuaddr back to hostptr: */
	ptr = hostptr(ibaddr);

	if (ptr) {
		ib++;
		dump_commands(ptr, ibsize, level);
		ib--;
	} else {
		fprintf(stderr, "could not find: %016lx (%d)\n", ibaddr, ibsize);
	}
}

static void cp_wfi(uint32_t *dwords, uint32_t sizedwords, int level)
{
	needs_wfi = false;
}

static void cp_mem_write(uint32_t *dwords, uint32_t sizedwords, int level)
{

	if (quiet(2))
		return;

	if (is_64b()) {
		uint64_t gpuaddr = dwords[0] | (((uint64_t)dwords[1]) << 32);
		printf("%sgpuaddr:%016lx\n", levels[level], gpuaddr);
		dump_hex(&dwords[2], sizedwords-2, level+1);

		if (pkt_is_type4(dwords[2]) || pkt_is_type7(dwords[2]))
			dump_commands(&dwords[2], sizedwords-2, level+1);
	} else {
		uint32_t gpuaddr = dwords[0];
		printf("%sgpuaddr:%08x\n", levels[level], gpuaddr);
		dump_float((float *)&dwords[1], sizedwords-1, level+1);
	}
}

static void cp_rmw(uint32_t *dwords, uint32_t sizedwords, int level)
{
	uint32_t val = dwords[0] & 0xffff;
	uint32_t and = dwords[1];
	uint32_t or  = dwords[2];
	printl(3, "%srmw (%s & 0x%08x) | 0x%08x)\n", levels[level], regname(val, 1), and, or);
	if (needs_wfi)
		printl(2, "NEEDS WFI: rmw (%s & 0x%08x) | 0x%08x)\n", regname(val, 1), and, or);
	reg_set(val, (reg_val(val) & and) | or);
}

static void cp_reg_mem(uint32_t *dwords, uint32_t sizedwords, int level)
{
	uint32_t val = dwords[0] & 0xffff;
	printl(3, "%sbase register: %s\n", levels[level], regname(val, 1));

	if (quiet(2))
		return;

	uint64_t gpuaddr = dwords[1] | (((uint64_t)dwords[2]) << 32);
	printf("%sgpuaddr:%016lx\n", levels[level], gpuaddr);
	void *ptr = hostptr(gpuaddr);
	if (ptr) {
		uint32_t cnt = (dwords[0] >> 19) & 0x3ff;
		dump_hex(ptr, cnt, level + 1);
	}
}

struct draw_state {
	uint16_t enable_mask;
	uint16_t flags;
	uint32_t count;
	uint64_t addr;
};

struct draw_state state[32];

#define FLAG_DIRTY              0x1
#define FLAG_DISABLE            0x2
#define FLAG_DISABLE_ALL_GROUPS 0x4
#define FLAG_LOAD_IMMED         0x8

static int draw_mode;

static void disable_group(unsigned group_id)
{
	struct draw_state *ds = &state[group_id];
	memset(ds, 0, sizeof(*ds));
}

static void disable_all_groups(void)
{
	for (unsigned i = 0; i < ARRAY_SIZE(state); i++)
		disable_group(i);
}

static void load_group(unsigned group_id, int level)
{
	struct draw_state *ds = &state[group_id];

	if (!ds->count)
		return;

	printl(2, "%sgroup_id: %u\n", levels[level], group_id);
	printl(2, "%scount: %d\n", levels[level], ds->count);
	printl(2, "%saddr: %016llx\n", levels[level], ds->addr);
	printl(2, "%sflags: %x\n", levels[level], ds->flags);

	if (gpu_id >= 600) {
		printl(2, "%senable_mask: 0x%x\n", levels[level], ds->enable_mask);

		/* a6xx seems to be a bit more sophisticated, it can emit
		 * different, potentially conflicting, state-groups for
		 * binning pass vs draw.  So we need to figure out the
		 * current mode and only dump_commands() for the enabled
		 * state-groups:
		 *
		 * This is probably not quite right, but is a reasonable
		 * first-pass approximation for now..
		 */
		unsigned mode;

		if (draw_mode == 1) {
			mode = 0x1;
		} else {
			mode = 0x6;
		}

		if (!(ds->enable_mask & mode)) {
			printl(2, "%s\tskipped!\n\n", levels[level]);
			return;
		}
	}

	void *ptr = hostptr(ds->addr);
	if (ptr) {
		if (!quiet(2))
			dump_hex(ptr, ds->count, level+1);

		ib++;
		dump_commands(ptr, ds->count, level+1);
		ib--;
	}

	disable_group(group_id);
}

static void load_all_groups(int level)
{
	/* sanity check, we should never recursively hit recursion here, and if
	 * we do bad things happen:
	 */
	static bool loading_groups = false;
	if (loading_groups) {
		printf("ERROR: nothing in draw state should trigger recursively loading groups!\n");
		return;
	}
	loading_groups = true;
	for (unsigned i = 0; i < ARRAY_SIZE(state); i++)
		load_group(i, level);
	loading_groups = false;
}

static void cp_set_draw_state(uint32_t *dwords, uint32_t sizedwords, int level)
{
	uint32_t i;

	for (i = 0; i < sizedwords; ) {
		struct draw_state *ds;
		uint32_t count = dwords[i] & 0xffff;
		uint32_t group_id = (dwords[i] >> 24) & 0x1f;
		uint32_t enable_mask = (dwords[i] >> 20) & 0xf;
		uint32_t flags = (dwords[i] >> 16) & 0xf;
		uint64_t addr;

		if (is_64b()) {
			addr = dwords[i + 1];
			addr |= ((uint64_t)dwords[i + 2]) << 32;
			i += 3;
		} else {
			addr = dwords[i + 1];
			i += 2;
		}

		if (flags & FLAG_DISABLE_ALL_GROUPS) {
			disable_all_groups();
			continue;
		}

		if (flags & FLAG_DISABLE) {
			disable_group(group_id);
			continue;
		}

		assert(group_id < ARRAY_SIZE(state));
		disable_group(group_id);

		ds = &state[group_id];

		ds->enable_mask = enable_mask;
		ds->flags = flags;
		ds->count = count;
		ds->addr  = addr;

		if (flags & FLAG_LOAD_IMMED) {
			load_group(group_id, level);
			disable_group(group_id);
		}
	}
}

static void cp_set_mode(uint32_t *dwords, uint32_t sizedwords, int level)
{
	draw_mode = dwords[0];
}

/* execute compute shader */
static void cp_exec_cs(uint32_t *dwords, uint32_t sizedwords, int level)
{
	do_query("compute", 0);
	dump_register_summary(level);
}

static void cp_exec_cs_indirect(uint32_t *dwords, uint32_t sizedwords, int level)
{
	uint64_t addr;

	if (is_64b()) {
		addr = (((uint64_t)dwords[2] & 0x1ffff) << 32) | dwords[1];
	} else {
		addr = dwords[1];
	}

	printl(3, "%saddr: %016llx\n", levels[level], addr);
	dump_gpuaddr_size(addr, level, 0x10, 2);

	do_query("compute", 0);
	dump_register_summary(level);
}

static void cp_set_marker(uint32_t *dwords, uint32_t sizedwords, int level)
{
	static const char *modes[] = {
		[0x0] = "MODE_0",
		[0x1] = "BYPASS",
		[0x2] = "BINNING",
		[0x4] = "GMEM",
		[0x5] = "BLIT2D",
		[0x6] = "RESOLVE",
		[0x7] = "MODE_7",
		[0x8] = "MODE_8",
		[0x9] = "MODE_9",
		[0xa] = "MODE_a",
		[0xb] = "MODE_b",
		[0xc] = "MODE_c",
		[0xd] = "MODE_d",
		[0xe] = "MODE_e",
		[0xf] = "MODE_f",
	};
	render_mode = modes[dwords[0] & 0xf];
}

static void cp_set_render_mode(uint32_t *dwords, uint32_t sizedwords, int level)
{
	uint64_t addr;
	uint32_t *ptr, len;

	assert(is_64b());

	/* TODO seems to have two ptrs, 9 dwords total (incl pkt7 hdr)..
	 * not sure if this can come in different sizes.
	 *
	 * First ptr doesn't seem to be cmdstream, second one does.
	 *
	 * Comment from downstream kernel:
	 *
	 * SRM -- set render mode (ex binning, direct render etc)
	 * SRM is set by UMD usually at start of IB to tell CP the type of
	 * preemption.
	 * KMD needs to set SRM to NULL to indicate CP that rendering is
	 * done by IB.
	 * ------------------------------------------------------------------
	 *
	 * Seems to always be one of these two:
	 * 70ec0008 00000001 001c0000 00000000 00000010 00000003 0000000d 001c2000 00000000
	 * 70ec0008 00000001 001c0000 00000000 00000000 00000003 0000000d 001c2000 00000000
	 *
	 */

	assert(gpu_id >= 500);

	render_mode = rnn_enumname(rnn, "render_mode_cmd", dwords[0]);

	if (sizedwords == 1)
		return;

	addr = dwords[1];
	addr |= ((uint64_t)dwords[2]) << 32;

	mode = dwords[3];

	dump_gpuaddr(addr, level+1);

	if (sizedwords == 5)
		return;

	assert(sizedwords == 8);

	len = dwords[5];
	addr = dwords[6];
	addr |= ((uint64_t)dwords[7]) << 32;

	printl(3, "%saddr: 0x%016lx\n", levels[level], addr);
	printl(3, "%slen:  0x%x\n", levels[level], len);

	ptr = hostptr(addr);

	if (ptr) {
		if (!quiet(2)) {
			ib++;
			dump_commands(ptr, len, level+1);
			ib--;
			dump_hex(ptr, len, level+1);
		}
	}
}

static void cp_compute_checkpoint(uint32_t *dwords, uint32_t sizedwords, int level)
{
	uint64_t addr;
	uint32_t *ptr, len;

	assert(is_64b());
	assert(gpu_id >= 500);

	assert(sizedwords == 8);

	addr = dwords[5];
	addr |= ((uint64_t)dwords[6]) << 32;
	len = dwords[7];

	printl(3, "%saddr: 0x%016lx\n", levels[level], addr);
	printl(3, "%slen:  0x%x\n", levels[level], len);

	ptr = hostptr(addr);

	if (ptr) {
		if (!quiet(2)) {
			ib++;
			dump_commands(ptr, len, level+1);
			ib--;
			dump_hex(ptr, len, level+1);
		}
	}
}

static void cp_blit(uint32_t *dwords, uint32_t sizedwords, int level)
{
	if ((gpu_id >= 500) && !quiet(2)) {
		printf("%smode: %s\n", levels[level], render_mode);
	}
	do_query(rnn_enumname(rnn, "cp_blit_cmd", dwords[0]), 0);
	dump_register_summary(level);
}

static void cp_context_reg_bunch(uint32_t *dwords, uint32_t sizedwords, int level)
{
	int i;

	/* NOTE: seems to write same reg multiple times.. not sure if different parts of
	 * these are triggered by the FLUSH_SO_n events?? (if that is what they actually
	 * are?)
	 */
	bool saved_summary = summary;
	summary = false;

	for (i = 0; i < sizedwords; i += 2) {
		dump_register(dwords[i+0], dwords[i+1], level+1);
		reg_set(dwords[i+0], dwords[i+1]);
	}

	summary = saved_summary;
}

static void cp_reg_write(uint32_t *dwords, uint32_t sizedwords, int level)
{
	uint32_t reg = dwords[1] & 0xffff;

	assert(dwords[0] == 0x2);  /* not sure what a value other than 2 does */

	dump_register(reg, dwords[2], level+1);
	reg_set(reg, dwords[2]);
}

static void cp_unk_a6xx_55(uint32_t *dwords, uint32_t sizedwords, int level)
{
	uint64_t addr;
	uint32_t size = dwords[2] & 0xffff;
	void *ptr;

	addr = dwords[0] | ((uint64_t)dwords[1] << 32);

	printf("addr=%lx\n", addr);
	ptr = hostptr(addr);
	if (ptr) {
		dump_commands(ptr, size, level+1);
	}
}

#define CP(x, fxn, ...)   { "CP_" #x, fxn, ##__VA_ARGS__ }
static const struct type3_op {
	const char *name;
	void (*fxn)(uint32_t *dwords, uint32_t sizedwords, int level);
	struct {
		bool load_all_groups;
	} options;
} type3_op[] = {
		CP(NOP, cp_nop),
		CP(INDIRECT_BUFFER, cp_indirect),
		CP(INDIRECT_BUFFER_PFD, cp_indirect),
		CP(WAIT_FOR_IDLE, cp_wfi),
		CP(REG_RMW, cp_rmw),
		CP(REG_TO_MEM, cp_reg_mem),
		CP(MEM_TO_REG, cp_reg_mem),  /* same layout as CP_REG_TO_MEM */
		CP(MEM_WRITE, cp_mem_write),
		CP(EVENT_WRITE, cp_event_write),
		CP(RUN_OPENCL, cp_run_cl),
		CP(DRAW_INDX, cp_draw_indx, {.load_all_groups=true}),
		CP(DRAW_INDX_2, cp_draw_indx_2, {.load_all_groups=true}),
		CP(SET_CONSTANT, cp_set_const),
		CP(IM_LOAD_IMMEDIATE, cp_im_loadi),
		CP(WIDE_REG_WRITE, cp_wide_reg_write),

		/* for a3xx */
		CP(LOAD_STATE, cp_load_state),
		CP(SET_BIN, cp_set_bin),

		/* for a4xx */
		CP(LOAD_STATE4, cp_load_state),
		CP(SET_DRAW_STATE, cp_set_draw_state),
		CP(DRAW_INDX_OFFSET, cp_draw_indx_offset, {.load_all_groups=true}),
		CP(EXEC_CS, cp_exec_cs),
		CP(EXEC_CS_INDIRECT, cp_exec_cs_indirect),

		/* for a5xx */
		CP(SET_RENDER_MODE, cp_set_render_mode),
		CP(COMPUTE_CHECKPOINT, cp_compute_checkpoint),
		CP(BLIT, cp_blit),
		CP(CONTEXT_REG_BUNCH, cp_context_reg_bunch),
		CP(DRAW_INDIRECT, cp_draw_indirect, {.load_all_groups=true}),
		CP(DRAW_INDX_INDIRECT, cp_draw_indx_indirect, {.load_all_groups=true}),

		/* for a6xx */
		CP(LOAD_STATE6_GEOM, cp_load_state),
		CP(LOAD_STATE6_FRAG, cp_load_state),
		CP(LOAD_STATE6, cp_load_state),
		CP(SET_MODE, cp_set_mode),
		CP(SET_MARKER, cp_set_marker),
		CP(REG_WRITE, cp_reg_write),

		CP(UNK_A6XX_55, cp_unk_a6xx_55),
};

static void noop_fxn(uint32_t *dwords, uint32_t sizedwords, int level)
{
}

static const struct type3_op *get_type3_op(unsigned opc)
{
	static const struct type3_op dummy_op = {
		.fxn = noop_fxn,
	};
	const char *name = rnn_enumname(rnn, "adreno_pm4_type3_packets", opc);

	if (!name)
		return &dummy_op;

	for (unsigned i = 0; i < ARRAY_SIZE(type3_op); i++)
		if (!strcmp(name, type3_op[i].name))
			return &type3_op[i];

	return &dummy_op;
}

static void dump_commands(uint32_t *dwords, uint32_t sizedwords, int level)
{
	int dwords_left = sizedwords;
	uint32_t count = 0; /* dword count including packet header */
	uint32_t val;

	if (!dwords) {
		printf("NULL cmd buffer!\n");
		return;
	}

	draws[ib] = 0;

	while (dwords_left > 0) {

		current_draw_count = draw_count;

		/* hack, this looks like a -1 underflow, in some versions
		 * when it tries to write zero registers via pkt0
		 */
//		if ((dwords[0] >> 16) == 0xffff)
//			goto skip;

		if (pkt_is_type0(dwords[0])) {
			printl(3, "t0");
			count = type0_pkt_size(dwords[0]) + 1;
			val = type0_pkt_offset(dwords[0]);
			printl(3, "%swrite %s%s (%04x)\n", levels[level+1], regname(val, 1),
					(dwords[0] & 0x8000) ? " (same register)" : "", val);
			dump_registers(val, dwords+1, count-1, level+2);
			if (!quiet(3))
				dump_hex(dwords, count, level+1);
		} else if (pkt_is_type4(dwords[0])) {
			/* basically the same(ish) as type0 prior to a5xx */
			printl(3, "t4");
			count = type4_pkt_size(dwords[0]) + 1;
			val = type4_pkt_offset(dwords[0]);
			printl(3, "%swrite %s (%04x)\n", levels[level+1], regname(val, 1), val);
			dump_registers(val, dwords+1, count-1, level+2);
			if (!quiet(3))
				dump_hex(dwords, count, level+1);
#if 0
		} else if (pkt_is_type1(dwords[0])) {
			printl(3, "t1");
			count = 3;
			val = dwords[0] & 0xfff;
			printl(3, "%swrite %s\n", levels[level+1], regname(val, 1));
			dump_registers(val, dwords+1, 1, level+2);
			val = (dwords[0] >> 12) & 0xfff;
			printl(3, "%swrite %s\n", levels[level+1], regname(val, 1));
			dump_registers(val, dwords+2, 1, level+2);
			if (!quiet(3))
				dump_hex(dwords, count, level+1);
		} else if (pkt_is_type2(dwords[0])) {
			printl(3, "t2");
			printf("%sNOP\n", levels[level+1]);
			count = 1;
			if (!quiet(3))
				dump_hex(dwords, count, level+1);
#endif
		} else if (pkt_is_type3(dwords[0])) {
			count = type3_pkt_size(dwords[0]) + 1;
			val = cp_type3_opcode(dwords[0]);
			const struct type3_op *op = get_type3_op(val);
			if (op->options.load_all_groups)
				load_all_groups(level+1);
			printl(3, "t3");
			init();
			const char *name = rnn_enumname(rnn, "adreno_pm4_type3_packets", val);
			if (!quiet(2)) {
				printf("\t%sopcode: %s%s%s (%02x) (%d dwords)%s\n", levels[level],
						rnn->vc->colors->bctarg, name, rnn->vc->colors->reset,
						val, count, (dwords[0] & 0x1) ? " (predicated)" : "");
			}
			if (name)
				dump_domain(dwords+1, count-1, level+2, name);
			op->fxn(dwords+1, count-1, level+1);
			if (!quiet(2))
				dump_hex(dwords, count, level+1);
		} else if (pkt_is_type7(dwords[0])) {
			count = type7_pkt_size(dwords[0]) + 1;
			val = cp_type7_opcode(dwords[0]);
			const struct type3_op *op = get_type3_op(val);
			if (op->options.load_all_groups)
				load_all_groups(level+1);
			printl(3, "t7");
			init();
			const char *name = rnn_enumname(rnn, "adreno_pm4_type3_packets", val);
			if (!quiet(2)) {
				printf("\t%sopcode: %s%s%s (%02x) (%d dwords)\n", levels[level],
						rnn->vc->colors->bctarg, name, rnn->vc->colors->reset,
						val, count);
			}
			if (name) {
				/* special hack for two packets that decode the same way
				 * on a6xx:
				 */
				if (!strcmp(name, "CP_LOAD_STATE6_FRAG") ||
						!strcmp(name, "CP_LOAD_STATE6_GEOM"))
					name = "CP_LOAD_STATE6";
				dump_domain(dwords+1, count-1, level+2, name);
			}
			op->fxn(dwords+1, count-1, level+1);
			if (!quiet(2))
				dump_hex(dwords, count, level+1);
		} else if (pkt_is_type2(dwords[0])) {
			printl(3, "t2");
			printl(3, "%snop\n", levels[level+1]);
		} else {
			printf("bad type! %08x\n", dwords[0]);
			return;
		}

		dwords += count;
		dwords_left -= count;

	}

	if (dwords_left < 0)
		printf("**** this ain't right!! dwords_left=%d\n", dwords_left);
}

static int handle_file(const char *filename, int start, int end, int draw);

static void print_usage(const char *name)
{
	printf("Usage: %s [OPTIONS]... FILE...\n", name);
	printf("    --verbose         - more verbose disassembly\n");
	printf("    --dump-shaders    - dump each shader to raw file\n");
	printf("    --no-color        - disable colorized output (default for non-console\n");
	printf("                        output)\n");
	printf("    --color           - enable colorized output (default for tty output)\n");
	printf("    --summary         - don't show individual register writes, but just show\n");
	printf("                        register values on draws\n");
	printf("    --allregs         - show all registers (including ones not written since\n");
	printf("                        previous draw) at each draw\n");
	printf("    --start N         - decode start frame number\n");
	printf("    --end N           - decode end frame number\n");
	printf("    --frame N         - decode specified frame number\n");
	printf("    --draw N          - decode specified draw number\n");
	printf("    --textures        - dump texture contents (if possible)\n");
	printf("    --script FILE     - run specified lua script to analyze state at draws\n");
	printf("    --query/-q REG    - query mode, dump only specified query registers on\n");
	printf("                        each draw; multiple --query/-q args can be given to\n");
	printf("                        dump multiple registers; register can be specified\n");
	printf("                        either by name or numeric offset\n");
	printf("    --disasm/-d       - combine with query mode, disassembles shader referenced\n");
	printf("                        by queried register\n");
	printf("    --help            - show this message\n");
}


static pid_t pager_pid;

static void pager_death(int n)
{
	exit(0);
}

static void pager_open(void)
{
	int fd[2];

	if (pipe(fd) < 0) {
		fprintf(stderr, "Failed to create pager pipe: %m\n");
		exit(-1);
	}

	pager_pid = fork();
	if (pager_pid < 0) {
		fprintf(stderr, "Failed to fork pager: %m\n");
		exit(-1);
	}

	if (pager_pid == 0) {
		const char* less_opts;

		dup2(fd[0], STDIN_FILENO);
		close(fd[0]);
		close(fd[1]);

		less_opts = "FRSMKX";
		setenv("LESS", less_opts, 1);

		execlp("less", "less", NULL);

	} else {
		/* we want to kill the parent process when pager exits: */
		signal(SIGCHLD, pager_death);
		dup2(fd[1], STDOUT_FILENO);
		close(fd[0]);
		close(fd[1]);
	}
}

static int pager_close(void)
{
	siginfo_t status;

	close(STDOUT_FILENO);

	while (true) {
		memset(&status, 0, sizeof(status));
		if (waitid(P_PID, pager_pid, &status, WEXITED) < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}

		return 0;
	}
}

int main(int argc, char **argv)
{
	int ret = -1, n = 1;
	int start = 0, end = 0x7ffffff, draw = -1;
	int interactive = isatty(STDOUT_FILENO);

	no_color = !interactive;

	while (n < argc) {
		if (!strcmp(argv[n], "--verbose")) {
			disasm_set_debug(PRINT_RAW | EXPAND_REPEAT | PRINT_VERBOSE);
			n++;
			continue;
		}

		if (!strcmp(argv[n], "--dump-shaders")) {
			dump_shaders = true;
			n++;
			continue;
		}

		if (!strcmp(argv[n], "--no-color")) {
			no_color = true;
			n++;
			continue;
		}

		if (!strcmp(argv[n], "--color")) {
			no_color = false;
			n++;
			continue;
		}

		if (!strcmp(argv[n], "--summary")) {
			summary = true;
			n++;
			continue;
		}

		if (!strcmp(argv[n], "--allregs")) {
			allregs = true;
			n++;
			continue;
		}

		if (!strcmp(argv[n], "--start")) {
			n++;
			start = atoi(argv[n]);
			n++;
			continue;
		}

		if (!strcmp(argv[n], "--end")) {
			n++;
			end = atoi(argv[n]);
			n++;
			continue;
		}

		if (!strcmp(argv[n], "--frame")) {
			n++;
			end = start = atoi(argv[n]);
			n++;
			continue;
		}

		if (!strcmp(argv[n], "--draw")) {
			n++;
			draw = atoi(argv[n]);
			n++;
			continue;
		}

		if (!strcmp(argv[n], "--textures")) {
			n++;
			dump_textures = true;
			continue;
		}

		if (!strcmp(argv[n], "--script")) {
			n++;
			script = argv[n];
			if (script_load(script)) {
				fprintf(stderr, "error loading %s\n", argv[n]);
				return 1;
			}
			n++;
			continue;
		}

		if (!strcmp(argv[n], "--query") ||
				!strcmp(argv[n], "-q")) {
			n++;
			querystrs = realloc(querystrs, (nquery + 1) * sizeof(*querystrs));
			querystrs[nquery] = argv[n];
			nquery++;
			n++;
			interactive = 0;
			continue;
		}

		if (!strcmp(argv[n], "--disasm") ||
				!strcmp(argv[n], "-d")) {
			n++;
			disasm = true;
			continue;
		}

		if (!strcmp(argv[n], "--help")) {
			n++;
			print_usage(argv[0]);
			return 0;
		}

		break;
	}

	if (disasm && (nquery == 0)) {
		printf("disasm mode only valid with query!\n");
		print_usage(argv[0]);
		return 0;
	}

	if (interactive) {
		pager_open();
	}

	rnn = rnn_new(no_color);

	while (n < argc) {
		ret = handle_file(argv[n], start, end, draw);
		if (ret) {
			fprintf(stderr, "error reading: %s\n", argv[n]);
			fprintf(stderr, "continuing..\n");
		}
		n++;
	}

	if (ret) {
		print_usage(argv[0]);
		return ret;
	}

	script_finish();

	if (interactive) {
		pager_close();
	}

	return 0;
}

static void parse_addr(uint32_t *buf, int sz, unsigned int *len, uint64_t *gpuaddr)
{
	*gpuaddr = buf[0];
	*len = buf[1];
	if (sz > 8)
		*gpuaddr |= ((uint64_t)(buf[2])) << 32;
}

static int handle_file(const char *filename, int start, int end, int draw)
{
	enum rd_sect_type type = RD_NONE;
	void *buf = NULL;
	struct io *io;
	int submit = 0, got_gpu_id = 0;
	int sz, i, ret = 0;
	bool needs_reset = false;
	bool skip = false;

	draw_filter = draw;
	draw_count = 0;

	printf("Reading %s...\n", filename);

	script_start_cmdstream(filename);

	if (!strcmp(filename, "-"))
		io = io_openfd(0);
	else
		io = io_open(filename);

	if (!io) {
		fprintf(stderr, "could not open: %s\n", filename);
		return -1;
	}

	clear_written();
	clear_lastvals();

	if (check_extension(filename, ".txt")) {
		/* read in from hexdump.. this could probably be more flexibile,
		 * but right now the format is:
		 *
		 *   "%x(ignored): %x %x %x %x %x %x %x %x
		 *
		 * and buf size is hard coded..  this is just for a quick hack
		 * I needed, if txt input is really useful this should be made
		 * less lame..
		 */
#define SZ 40960
		char *strbuf  = calloc(SZ, 1);
		uint32_t *buf = calloc(SZ, 1);
		uint32_t *bufp = buf;
		uint32_t dummy, sizedwords = 0;
		int n;

		io_readn(io, strbuf, SZ);

		do {
			n = sscanf(strbuf, "%x: %x %x %x %x %x %x %x %x", &dummy,
							&bufp[0], &bufp[1], &bufp[2], &bufp[3],
							&bufp[4], &bufp[5], &bufp[6], &bufp[7]);
			if (n <= 0)
				break;

			sizedwords += n - 1;
			bufp += 8;

			/* scan fwd until next newline: */
			while (strbuf[0] != '\n')
				strbuf++;
			strbuf++;

		} while (1);

		init_a3xx();

		printf("############################################################\n");
		printf("cmdstream: %d dwords\n", sizedwords);
		dump_commands(buf, sizedwords, 0);
		printf("############################################################\n");
		printf("vertices: %d\n", vertices);

		return 0;
	}

	struct buffer gpuaddr = {0};

	while (true) {
		uint32_t arr[2];

		ret = io_readn(io, arr, 8);
		if (ret <= 0)
			goto end;

		while ((arr[0] == 0xffffffff) && (arr[1] == 0xffffffff)) {
			ret = io_readn(io, arr, 8);
			if (ret <= 0)
				goto end;
		}

		type = arr[0];
		sz = arr[1];

		if (sz < 0) {
			ret = -1;
			goto end;
		}

		free(buf);

		needs_wfi = false;

		buf = malloc(sz + 1);
		((char *)buf)[sz] = '\0';
		ret = io_readn(io, buf, sz);
		if (ret < 0)
			goto end;

		switch(type) {
		case RD_TEST:
			printl(1, "test: %s\n", (char *)buf);
			break;
		case RD_CMD:
			is_blob = true;
			printl(2, "cmd: %s\n", (char *)buf);
			// hack to skip xserver cmdstream
			//skip = ((char *)buf)[0] == 'X';
			break;
		case RD_VERT_SHADER:
			printl(2, "vertex shader:\n%s\n", (char *)buf);
			break;
		case RD_FRAG_SHADER:
			printl(2, "fragment shader:\n%s\n", (char *)buf);
			break;
		case RD_GPUADDR:
			if (needs_reset) {
				for (i = 0; i < nbuffers; i++) {
					free(buffers[i].hostptr);
					buffers[i].hostptr = NULL;
					buffers[i].len = 0;
				}
				nbuffers = 0;
				needs_reset = false;
			}
			parse_addr(buf, sz, &gpuaddr.len, &gpuaddr.gpuaddr);
			break;
		case RD_BUFFER_CONTENTS:
			for (i = 0; i < nbuffers; i++) {
				if (buffers[i].gpuaddr == gpuaddr.gpuaddr)
					break;
			}
			if (i == nbuffers) {
				/* some traces, like test-perf, with some blob versions,
				 * seem to generate an unreasonable # of gpu buffers (a
				 * leak?), so just ignore them.
				 */
				if (nbuffers >= ARRAY_SIZE(buffers))
					break;
				nbuffers++;
			}
			buffers[i].hostptr = buf;
			buffers[i].len     = gpuaddr.len;
			buffers[i].gpuaddr = gpuaddr.gpuaddr;
			buf = NULL;
			break;
		case RD_CMDSTREAM_ADDR:
			if ((start <= submit) && (submit <= end)) {
				unsigned int sizedwords;
				uint64_t gpuaddr;
				parse_addr(buf, sz, &sizedwords, &gpuaddr);
				printl(2, "############################################################\n");
				printl(2, "cmdstream: %d dwords\n", sizedwords);
				if (!skip) {
					script_start_submit();
					dump_commands(hostptr(gpuaddr), sizedwords, 0);
					script_end_submit();
				}
				printl(2, "############################################################\n");
				printl(2, "vertices: %d\n", vertices);
			}
			needs_reset = true;
			submit++;
			break;
		case RD_GPU_ID:
			if (!got_gpu_id) {
				gpu_id = *((unsigned int *)buf);
				printl(2, "gpu_id: %d\n", gpu_id);
				if (gpu_id >= 600)
					init_a6xx();
				else if (gpu_id >= 500)
					init_a5xx();
				else if (gpu_id >= 400)
					init_a4xx();
				else if (gpu_id >= 300)
					init_a3xx();
				else
					init_a2xx();
				got_gpu_id = 1;
			}
			break;
		default:
			break;
		}
	}

end:
	script_end_cmdstream();

	io_close(io);
	fflush(stdout);

	if (ret < 0) {
		printf("corrupt file\n");
	}
	return 0;
}
