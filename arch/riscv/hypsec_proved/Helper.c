#include <linux/types.h>
#include <linux/mman.h>
#include <linux/kvm_host.h>
#include <linux/io.h>
#include <trace/events/kvm.h>
#include <asm/pgalloc.h>
#include <asm/cacheflush.h>
#include <asm/hypsec_pgtable.h>
#include <asm/hypsec_host.h>
#include <asm/spinlock_types.h>
#include <asm/sbi.h>

static inline void senduart(char word)
{
	sbi_ecall(SBI_EXT_0_1_CONSOLE_PUTCHAR, 0, word, 0, 0, 0, 0, 0);
}

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
