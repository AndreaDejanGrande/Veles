#define VCRYPT_MIX_BASE "ChaCha20/8"

typedef uint32_t vcrypt_mix_word_t;

#define VCRYPT_WORDTO8_LE U32TO8_LE
#define VCRYPT_WORD_ENDIAN_SWAP U32_SWAP

#define VCRYPT_P 1
#define VCRYPT_R 1
#define VCRYPT_BLOCK_BYTES 64
#define VCRYPT_BLOCK_WORDS (VCRYPT_BLOCK_BYTES / sizeof(vcrypt_mix_word_t))

/* must have these here in case block bytes is ever != 64 */
#include "scrypt-jane-romix-basic.h"

#include "scrypt-jane-mix_chacha.h"

/* cpu agnostic */
#define VCRYPT_ROMIX_FN vcrypt_ROMix_basic
#define VCRYPT_MIX_FN chacha_core_basic
#define VCRYPT_ROMIX_TANGLE_FN vcrypt_romix_convert_endian
#define VCRYPT_ROMIX_UNTANGLE_FN vcrypt_romix_convert_endian
#include "scrypt-jane-romix-template.h"

#if !defined(VCRYPT_CHOOSE_COMPILETIME)
static vcrypt_ROMixfn
vcrypt_getROMix() {
	size_t cpuflags = detect_cpu();

	return vcrypt_ROMix_basic;
}
#endif


#if defined(VCRYPT_TEST_SPEED)
static size_t
available_implementations() {
	size_t cpuflags = detect_cpu();
	size_t flags = 0;

	return flags;
}
#endif

static int
vcrypt_test_mix() {
	static const uint8_t expected[16] = {
		0x48,0x2b,0x2d,0xb8,0xa1,0x33,0x22,0x73,0xcd,0x16,0xc4,0xb4,0xb0,0x7f,0xb1,0x8a,
	};

	int ret = 1;
	size_t cpuflags = detect_cpu();

#if defined(VCRYPT_CHACHA_BASIC)
	ret &= vcrypt_test_mix_instance(vcrypt_ChunkMix_basic, vcrypt_romix_convert_endian, vcrypt_romix_convert_endian, expected);
#endif

	return ret;
}

