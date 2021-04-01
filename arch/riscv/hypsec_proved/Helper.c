#include <linux/types.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_hyp.h>
#include <linux/mman.h>
#include <linux/kvm_host.h>
#include <linux/io.h>
#include <trace/events/kvm.h>
#include <asm/pgalloc.h>
#include <asm/cacheflush.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_mmio.h>
#include <asm/kvm_emulate.h>
#include <asm/virt.h>
#include <asm/kernel-pgtable.h>
#include <asm/hypsec_host.h>
#include <asm/spinlock_types.h>
#include <linux/serial_reg.h>
#include <linux/amba/serial.h>

#ifdef CONFIG_SERIAL_8250_CONSOLE
static inline void senduart(char word)
{
	unsigned long base, addr;
	int offset, timeout = 10000;
	struct hs_data *hs_data;
	u8 val;

	hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
	base = hs_data->uart_8250_base;
	//TODO: use macro instead
	offset = 5;
	addr = offset + base;

	for (;;) {
		asm volatile(ALTERNATIVE("ldrb %w0, [%1]",
					 "ldarb %w0, [%1]",
					 ARM64_WORKAROUND_DEVICE_LOAD_ACQUIRE)
					: "=r" (val) : "r" (base));
	
		asm volatile("dsb ld"  : : : "memory");
		if ((val & 0x20) == 0x20 || --timeout == 0)
				break ;
	}

	offset = 0;
	addr = offset + base;
	asm volatile("dsb st"  : : : "memory");
	asm volatile("strb %w0, [%1]" : : "rZ" (word), "r" (base));
}

#else
static inline unsigned long waituart(void)
{
	unsigned long ret, base, REG_FR;
	struct hs_data *hs_data;

	hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
	base = hs_data->pl011_base;
	REG_FR = UART01x_FR;

	asm volatile (
		"ldrb   w26, [%1, %2]\n\t"
		"dsb	ld\n\t"
		"mov	%0, x26\n\t"
		:"=r"(ret)
		:"r"(base), "r"(REG_FR)
		:"x26", "cc"
	);

	return ret;
}

static inline void senduart(char word)
{
	unsigned long base;
	struct hs_data *hs_data;

	hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));
	base = hs_data->pl011_base;

	while (waituart() & UART01x_FR_TXFF)
		cpu_relax();

	asm volatile (
		"mov    x14, %0\n\t"
		"strb   w14, [%1, #0]\n\t"
		"dsb    st\n\t"
		:
		:"r"(word), "r"(base)
		:"x14", "cc"
	);
}
#endif

void printhex_ul(unsigned long input)
{
	char word;
	int len = 60;
	struct hs_data *hs_data;

	hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));

	stage2_spin_lock(&hs_data->console_lock);

	word = '\r';
	senduart(word);

	word = '0';
	senduart(word);
	word = 'x';
	senduart(word);

	while (len >= 0) {
		word = (input >> len) & 0xf;
		if (word < 10)
			word += '0';
		else
			word += 'a' - 10;
		senduart(word);
		len -= 4;
	}
	word = '\r';
	senduart(word);

	word = '\n';
	senduart(word);

	stage2_spin_unlock(&hs_data->console_lock);
}

void print_string(char *input)
{
	char *word;
	struct hs_data *hs_data;

	hs_data = kern_hyp_va(kvm_ksym_ref(hs_data_start));

	stage2_spin_lock(&hs_data->console_lock);

	word = input;
	while (*word != '\0') {
		senduart(*word);
		word++;
	}

	stage2_spin_unlock(&hs_data->console_lock);
}

void hs_memset(void *b, int c, int len)
{
	char *s = b;

        while(len--)
            *s++ = c;
}

void hs_memcpy(void *dest, void *src, size_t len)
{
	char *cdest = dest;
	char *csrc = src;

        while(len--)
            *cdest++ = *csrc++;
}

int hs_memcmp(void *dest, void *src, size_t len)
{
	char *cdest = dest;
	char *csrc = src;
	while(len--) {
		if (*cdest++ != *csrc++)
			return 1;
	}
	return 0;
}

/**
 * Assumes lowercase char (if a letter).
 * Copied from lib/hexdump.c
 */
int hs_hex_to_bin(char ch)
{
	if ((ch >= '0') && (ch <= '9'))
		return ch - '0';
	if ((ch >= 'a') && (ch <= 'f'))
		return ch - 'a' + 10;
	return -1;
}

/**
 * hex2bin - convert an ascii hexadecimal string to its binary representation
 * Copied from lib/hexdump.c
 *
 * @dst: binary result
 * @src: ascii hexadecimal string
 * @count: result length
 *
 * Return 0 on success, -1 in case of bad input.
 */
int hs_hex2bin(unsigned char *dst, const char *src, int count)
{
	while (count--) {
		int hi = hs_hex_to_bin(*src++);
		int lo = hs_hex_to_bin(*src++);

		if ((hi < 0) || (lo < 0))
			return -1;

		*dst++ = (hi << 4) | lo;
	}
	return 0;
}
