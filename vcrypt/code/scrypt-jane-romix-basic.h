#if !defined(VCRYPT_CHOOSE_COMPILETIME)
/* function type returned by vcrypt_getROMix, used with cpu detection */
typedef void (FASTCALL *vcrypt_ROMixfn)(vcrypt_mix_word_t *X/*[chunkWords]*/, vcrypt_mix_word_t *Y/*[chunkWords]*/, vcrypt_mix_word_t *V/*[chunkWords * N]*/, uint32_t N, uint32_t r);
#endif

/* romix pre/post nop function */
static void asm_calling_convention
vcrypt_romix_nop(vcrypt_mix_word_t *blocks, size_t nblocks) {
}

/* romix pre/post endian conversion function */
static void asm_calling_convention
vcrypt_romix_convert_endian(vcrypt_mix_word_t *blocks, size_t nblocks) {
#if !defined(CPU_LE)
	static const union { uint8_t b[2]; uint16_t w; } endian_test = {{1,0}};
	size_t i;
	if (endian_test.w == 0x100) {
		nblocks *= VCRYPT_BLOCK_WORDS;
		for (i = 0; i < nblocks; i++) {
			VCRYPT_WORD_ENDIAN_SWAP(blocks[i]);
		}
	}
#endif
}

/* chunkmix test function */
typedef void (asm_calling_convention *chunkmixfn)(vcrypt_mix_word_t *Bout/*[chunkWords]*/, vcrypt_mix_word_t *Bin/*[chunkWords]*/, vcrypt_mix_word_t *Bxor/*[chunkWords]*/, uint32_t r);
typedef void (asm_calling_convention *blockfixfn)(vcrypt_mix_word_t *blocks, size_t nblocks);

static int
vcrypt_test_mix_instance(chunkmixfn mixfn, blockfixfn prefn, blockfixfn postfn, const uint8_t expected[16]) {
	/* r = 2, (2 * r) = 4 blocks in a chunk, 4 * VCRYPT_BLOCK_WORDS total */
	const uint32_t r = 2, blocks = 2 * r, words = blocks * VCRYPT_BLOCK_WORDS;
	vcrypt_mix_word_t MM16 chunk[2][4 * VCRYPT_BLOCK_WORDS], v;
	uint8_t final[16];
	size_t i;

	for (i = 0; i < words; i++) {
		v = (vcrypt_mix_word_t)i;
		v = (v << 8) | v;
		v = (v << 16) | v;
		chunk[0][i] = v;
	}

	prefn(chunk[0], blocks);
	mixfn(chunk[1], chunk[0], NULL, r);
	postfn(chunk[1], blocks);

	/* grab the last 16 bytes of the final block */
	for (i = 0; i < 16; i += sizeof(vcrypt_mix_word_t)) {
		VCRYPT_WORDTO8_LE(final + i, chunk[1][words - (16 / sizeof(vcrypt_mix_word_t)) + (i / sizeof(vcrypt_mix_word_t))]);
	}

	return vcrypt_verify(expected, final, 16);
}

/* returns a pointer to item i, where item is len vcrypt_mix_word_t's long */
static vcrypt_mix_word_t *
vcrypt_item(vcrypt_mix_word_t *base, vcrypt_mix_word_t i, vcrypt_mix_word_t len) {
	return base + (i * len);
}

/* returns a pointer to block i */
static vcrypt_mix_word_t *
vcrypt_block(vcrypt_mix_word_t *base, vcrypt_mix_word_t i) {
	return base + (i * VCRYPT_BLOCK_WORDS);
}
