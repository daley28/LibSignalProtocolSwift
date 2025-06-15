#ifndef __COMMONCRYPTO_BRIDGE__
#define __COMMONCRYPTO_BRIDGE__

#include <CommonCrypto/CommonCrypto.h>
#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonCryptor.h>

// Export CommonCrypto constants as static const values
extern const int kCCKeySizeAES256_Bridge;
extern const int kCCBlockSizeAES128_Bridge;
extern const int kCCAlgorithmAES_Bridge;
extern const int kCCOptionPKCS7Padding_Bridge;
extern const int kCCEncrypt_Bridge;
extern const int kCCDecrypt_Bridge;
extern const int kCCSuccess_Bridge;
extern const int kCCHmacAlgSHA256_Bridge;
extern const int kCCModeCTR_Bridge;
extern const int kCCModeOptionCTR_BE_Bridge;
extern const int ccNoPadding_Bridge;
extern const int CC_SHA256_DIGEST_LENGTH_Bridge;
extern const int CC_SHA512_DIGEST_LENGTH_Bridge;

// Explicitly expose CommonCrypto function signatures
typedef CCCryptorStatus (*CCCryptFunc)(CCOperation op, CCAlgorithm alg, CCOptions options,
                                       const void *key, size_t keyLength, const void *iv,
                                       const void *dataIn, size_t dataInLength,
                                       void *dataOut, size_t dataOutAvailable, size_t *dataOutMoved);

typedef CCCryptorStatus (*CCCryptorCreateWithModeFunc)(CCOperation op, CCMode mode, CCAlgorithm alg,
                                                        CCPadding padding, const void *iv,
                                                        const void *key, size_t keyLength,
                                                        const void *tweak, size_t tweakLength,
                                                        int numRounds, CCModeOptions options,
                                                        CCCryptorRef *cryptorRef);

typedef CCCryptorStatus (*CCCryptorUpdateFunc)(CCCryptorRef cryptorRef, const void *dataIn,
                                               size_t dataInLength, void *dataOut,
                                               size_t dataOutAvailable, size_t *dataOutMoved);

typedef CCCryptorStatus (*CCCryptorFinalFunc)(CCCryptorRef cryptorRef, void *dataOut,
                                              size_t dataOutAvailable, size_t *dataOutMoved);

typedef CCCryptorStatus (*CCCryptorReleaseFunc)(CCCryptorRef cryptorRef);

typedef size_t (*CCCryptorGetOutputLengthFunc)(CCCryptorRef cryptorRef, size_t inputLength, bool final);

typedef void (*CCHmacInitFunc)(CCHmacContext *ctx, CCHmacAlgorithm algorithm,
                               const void *key, size_t keyLength);

typedef void (*CCHmacUpdateFunc)(CCHmacContext *ctx, const void *data, size_t dataLength);

typedef void (*CCHmacFinalFunc)(CCHmacContext *ctx, void *macOut);

typedef int (*CC_SHA512_InitFunc)(CC_SHA512_CTX *c);

typedef int (*CC_SHA512_UpdateFunc)(CC_SHA512_CTX *c, const void *data, CC_LONG len);

typedef int (*CC_SHA512_FinalFunc)(unsigned char *md, CC_SHA512_CTX *c);

#endif /* __COMMONCRYPTO_BRIDGE__ */
