#ifndef __COMMONCRYPTO_BRIDGE__
#define __COMMONCRYPTO_BRIDGE__

#include <CommonCrypto/CommonCrypto.h>
#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonCryptor.h>

// Export CommonCrypto constants
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

#endif /* __COMMONCRYPTO_BRIDGE__ */
