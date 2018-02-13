/*
	pick the best algo at runtime or compile time?
	----------------------------------------------
	VCRYPT_CHOOSE_COMPILETIME (gcc only!)
	VCRYPT_CHOOSE_RUNTIME
*/
#define VCRYPT_CHOOSE_RUNTIME


/*
	hash function to use
	-------------------------------
	VCRYPT_BLAKE256
	VCRYPT_BLAKE512
	VCRYPT_SHA256
	VCRYPT_SHA512
	VCRYPT_SKEIN512
*/
//#define VCRYPT_SHA256


/*
	block mixer to use
	-----------------------------
	VCRYPT_CHACHA
	VCRYPT_SALSA
*/
//#define VCRYPT_SALSA
