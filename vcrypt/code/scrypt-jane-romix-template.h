#if !defined(VCRYPT_CHOOSE_COMPILETIME) || !defined(VCRYPT_HAVE_ROMIX)

#if defined(VCRYPT_CHOOSE_COMPILETIME)
#undef VCRYPT_ROMIX_FN
#define VCRYPT_ROMIX_FN vcrypt_ROMix
#endif

#undef VCRYPT_HAVE_ROMIX
#define VCRYPT_HAVE_ROMIX

#if !defined(VCRYPT_CHUNKMIX_FN)

#define VCRYPT_CHUNKMIX_FN vcrypt_ChunkMix_basic

/*
	Bout = ChunkMix(Bin)

	2*r: number of blocks in the chunk
*/
static void asm_calling_convention
VCRYPT_CHUNKMIX_FN(vcrypt_mix_word_t *Bout/*[chunkWords]*/, vcrypt_mix_word_t *Bin/*[chunkWords]*/, vcrypt_mix_word_t *Bxor/*[chunkWords]*/, uint32_t r) {
	vcrypt_mix_word_t MM16 X[VCRYPT_BLOCK_WORDS], *block;
	uint32_t i, j, blocksPerChunk = r * 2, half = 0;

	/* 1: X = B_{2r - 1} */
	block = vcrypt_block(Bin, blocksPerChunk - 1);
	for (i = 0; i < VCRYPT_BLOCK_WORDS; i++)
		X[i] = block[i];

	if (Bxor) {
		block = vcrypt_block(Bxor, blocksPerChunk - 1);
		for (i = 0; i < VCRYPT_BLOCK_WORDS; i++)
			X[i] ^= block[i];
	}

	/* 2: for i = 0 to 2r - 1 do */
	for (i = 0; i < blocksPerChunk; i++, half ^= r) {
		/* 3: X = H(X ^ B_i) */
		block = vcrypt_block(Bin, i);
		for (j = 0; j < VCRYPT_BLOCK_WORDS; j++)
			X[j] ^= block[j];

		if (Bxor) {
			block = vcrypt_block(Bxor, i);
			for (j = 0; j < VCRYPT_BLOCK_WORDS; j++)
				X[j] ^= block[j];
		}
		VCRYPT_MIX_FN(X);

		/* 4: Y_i = X */
		/* 6: B'[0..r-1] = Y_even */
		/* 6: B'[r..2r-1] = Y_odd */
		block = vcrypt_block(Bout, (i / 2) + half);
		for (j = 0; j < VCRYPT_BLOCK_WORDS; j++)
			block[j] = X[j];
	}
}
#endif

/*
	X = ROMix(X)

	X: chunk to mix
	Y: scratch chunk
	N: number of rounds
	V[N]: array of chunks to randomly index in to
	2*r: number of blocks in a chunk
*/

static void NOINLINE FASTCALL
VCRYPT_ROMIX_FN(vcrypt_mix_word_t *X/*[chunkWords]*/, vcrypt_mix_word_t *Y/*[chunkWords]*/, vcrypt_mix_word_t *V/*[N * chunkWords]*/, uint32_t N, uint32_t r) {
	uint32_t i, j, chunkWords = VCRYPT_BLOCK_WORDS * r * 2;
	vcrypt_mix_word_t *block = V;

	VCRYPT_ROMIX_TANGLE_FN(X, r * 2);

	/* 1: X = B */
	/* implicit */

	/* 2: for i = 0 to N - 1 do */
	memcpy(block, X, chunkWords * sizeof(vcrypt_mix_word_t));
	for (i = 0; i < N - 1; i++, block += chunkWords) {
		/* 3: V_i = X */
		/* 4: X = H(X) */
		VCRYPT_CHUNKMIX_FN(block + chunkWords, block, NULL, r);
	}
	VCRYPT_CHUNKMIX_FN(X, block, NULL, r);

	/* 6: for i = 0 to N - 1 do */
	for (i = 0; i < N; i += 2) {
		/* 7: j = Integerify(X) % N */
		j = X[chunkWords - VCRYPT_BLOCK_WORDS] & (N - 1);

		/* 8: X = H(Y ^ V_j) */
		VCRYPT_CHUNKMIX_FN(Y, X, vcrypt_item(V, j, chunkWords), r);

		/* 7: j = Integerify(Y) % N */
		j = Y[chunkWords - VCRYPT_BLOCK_WORDS] & (N - 1);

		/* 8: X = H(Y ^ V_j) */
		VCRYPT_CHUNKMIX_FN(X, Y, vcrypt_item(V, j, chunkWords), r);
	}

	/* 10: B' = X */
	/* implicit */

	VCRYPT_ROMIX_UNTANGLE_FN(X, r * 2);
}

/*
 * Special version with hard-coded r = 1
 *  - mikaelh
 */
static void NOINLINE FASTCALL
vcrypt_ROMix_1(vcrypt_mix_word_t *X/*[chunkWords]*/, vcrypt_mix_word_t *Y/*[chunkWords]*/, vcrypt_mix_word_t *V/*[N * chunkWords]*/, uint32_t N) {
	const uint32_t r = 1;
	uint32_t i, j, chunkWords = VCRYPT_BLOCK_WORDS * r * 2;
	vcrypt_mix_word_t *block = V;

	VCRYPT_ROMIX_TANGLE_FN(X, r * 2);

	/* 1: X = B */
	/* implicit */

	/* 2: for i = 0 to N - 1 do */
	memcpy(block, X, chunkWords * sizeof(vcrypt_mix_word_t));
	for (i = 0; i < N - 1; i++, block += chunkWords) {
		/* 3: V_i = X */
		/* 4: X = H(X) */
#ifdef VCRYPT_CHUNKMIX_1_FN
		VCRYPT_CHUNKMIX_1_FN(block + chunkWords, block);
#else
		VCRYPT_CHUNKMIX_FN(block + chunkWords, block, NULL, r);
#endif
	}
#ifdef VCRYPT_CHUNKMIX_1_FN
	VCRYPT_CHUNKMIX_1_FN(X, block);
#else
	VCRYPT_CHUNKMIX_FN(X, block, NULL, r);
#endif

	/* 6: for i = 0 to N - 1 do */
	for (i = 0; i < N; i += 2) {
		/* 7: j = Integerify(X) % N */
		j = X[chunkWords - VCRYPT_BLOCK_WORDS] & (N - 1);

		/* 8: X = H(Y ^ V_j) */
#ifdef VCRYPT_CHUNKMIX_1_XOR_FN
		VCRYPT_CHUNKMIX_1_XOR_FN(Y, X, vcrypt_item(V, j, chunkWords));
#else
		VCRYPT_CHUNKMIX_FN(Y, X, vcrypt_item(V, j, chunkWords), r);
#endif

		/* 7: j = Integerify(Y) % N */
		j = Y[chunkWords - VCRYPT_BLOCK_WORDS] & (N - 1);

		/* 8: X = H(Y ^ V_j) */
#ifdef VCRYPT_CHUNKMIX_1_XOR_FN
		VCRYPT_CHUNKMIX_1_XOR_FN(X, Y, vcrypt_item(V, j, chunkWords));
#else
		VCRYPT_CHUNKMIX_FN(X, Y, vcrypt_item(V, j, chunkWords), r);
#endif
	}

	/* 10: B' = X */
	/* implicit */

	VCRYPT_ROMIX_UNTANGLE_FN(X, r * 2);
}

#endif /* !defined(VCRYPT_CHOOSE_COMPILETIME) || !defined(VCRYPT_HAVE_ROMIX) */


#undef VCRYPT_CHUNKMIX_FN
#undef VCRYPT_ROMIX_FN
#undef VCRYPT_MIX_FN
#undef VCRYPT_ROMIX_TANGLE_FN
#undef VCRYPT_ROMIX_UNTANGLE_FN

