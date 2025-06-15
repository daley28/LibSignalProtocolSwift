//
//  SignalCommonCrypto.swift
//  SignalProtocolSwift
//
//  Created by User on 11.11.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation
import CommonCryptoBridge

/**
 SignalCommonCrypto provides cryptographic functions for the Signal Protocol.
 */
public struct SignalCommonCrypto: SignalCryptoProvider {

    /**
     Create a number of random bytes.
     - parameter bytes: The number of bytes to create
     - returns: The random bytes
     - throws: `SignalError` of type `randomGenerationError`
     */
    public func random(bytes: Int) throws -> Data {
        var random = [UInt8](repeating: 0, count: bytes)
        let result = random.withUnsafeMutableBytes { ptr in
            SecRandomCopyBytes(nil, bytes, ptr.baseAddress!)
        }

        guard result == errSecSuccess else {
            throw SignalError(.noRandomBytes, "Could not generate \(bytes) random bytes")
        }
        return Data(random)
    }

    /**
     Perform HMAC with SHA256.
     - parameter message: The message to authenticate
     - parameter salt: The salt for the authentication
     - returns: The authentication code
     */
    public func hmacSHA256(for message: Data, with salt: Data) -> Data {
        var context = CCHmacContext()

        var bytes = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH_Bridge))
        withUnsafeMutablePointer(to: &context) { (ptr: UnsafeMutablePointer<CCHmacContext>) in
            // Pointer to salt
            salt.withUnsafeBytes { ptr2 in
                let saltPtr = ptr2.baseAddress!
                // Pointer to message
                message.withUnsafeBytes { ptr3 in
                    let messagePtr = ptr3.baseAddress!
                    // Authenticate
                    CCHmacInit(ptr, CCHmacAlgorithm(kCCHmacAlgSHA256_Bridge), saltPtr, salt.count)
                    CCHmacUpdate(ptr, messagePtr, message.count)
                    bytes.withUnsafeMutableBytes { bytesPtr in
                        CCHmacFinal(ptr, bytesPtr.baseAddress!)
                    }
                }
            }
        }
        return Data(bytes)
    }

    /**
     Perform SHA512 on a message.
     - parameter message: The message to hash
     - returns: The hash
     - throws: `SignalError` of type `digestError` or `invalidMessage`
     */
    public func sha512(for message: Data) throws -> Data {
        guard message.count > 0 else {
            throw SignalError(.invalidMessage, "Message length is 0")
        }
        var context = CC_SHA512_CTX()
        return try withUnsafeMutablePointer(to: &context) { contextPtr in
            CC_SHA512_Init(contextPtr)
            // Pointer to message
            let result: Int32 = message.withUnsafeBytes {ptr2 in
                let messagePtr = ptr2.baseAddress!
                return CC_SHA512_Update(contextPtr, messagePtr, CC_LONG(message.count))
            }
            guard result == 1 else {
                throw SignalError(.digestError, "Error on SHA512 Update: \(result)")
            }
            var md = Data(count: Int(CC_SHA512_DIGEST_LENGTH_Bridge))
            let result2: Int32 = md.withUnsafeMutableBytes { ptr4 in
                let a = ptr4.baseAddress!.assumingMemoryBound(to: UInt8.self)
                return CC_SHA512_Final(a, contextPtr)
            }
            guard result2 == 1 else {
                throw SignalError(.digestError, "Error on SHA512 Final: \(result2)")
            }
            return md
        }
    }

    /**
     Encrypt a message.
     - parameter message: The message to encrypt
     - parameter cipher: The cipher to use
     - parameter key: The key for encryption
     - parameter iv: The initialization vector
     - returns: The encrypted message
     - throws: `SignalError` of type `encryptionError`, `invalidKey`, `invalidMessage`, or `invalidIV`
     */
    public func encrypt(message: Data, with cipher: SignalEncryptionScheme, key: Data, iv: Data) throws -> Data {
        guard key.count == kCCKeySizeAES256_Bridge else {
            throw SignalError(.invalidKey, "Invalid key length")
        }
        guard message.count > 0 else {
            throw SignalError(.invalidMessage, "Message length is 0")
        }
        guard iv.count == kCCBlockSizeAES128_Bridge else {
            throw SignalError(.invalidIV, "The length of the IV is not correct")
        }

        switch cipher {
        case .AES_CBCwithPKCS5:
            return try process(cbc: message, key: key, iv: iv, encrypt: true)
        case .AES_CTRnoPadding:
            return try process(ctr: message, key: key, iv: iv, encrypt: true)
        }
    }

    /**
     Decrypt a message.
     - parameter message: The message to decrypt
     - parameter cipher: The cipher to use
     - parameter key: The key for decryption
     - parameter iv: The initialization vector
     - returns: The decrypted message
     - throws: `SignalError` of type `decryptionError`, `invalidKey`, `invalidMessage`, or `invalidIV`
     */
    public func decrypt(message: Data, with cipher: SignalEncryptionScheme, key: Data, iv: Data) throws -> Data {
        guard key.count == kCCKeySizeAES256_Bridge else {
            throw SignalError(.invalidKey, "Invalid key length")
        }
        guard message.count > 0 else {
            throw SignalError(.invalidMessage, "Message length is 0")
        }
        guard iv.count == kCCBlockSizeAES128_Bridge else {
            throw SignalError(.invalidIV, "The length of the IV is not correct")
        }

        switch cipher {
        case .AES_CBCwithPKCS5:
            return try process(cbc: message, key: key, iv: iv, encrypt: false)
        case .AES_CTRnoPadding:
            return try process(ctr: message, key: key, iv: iv, encrypt: false)
        }
    }

    /**
     Process a message with AES in CBC mode.
     - parameter message: The message to process
     - parameter key: The key
     - parameter iv: The initialization vector
     - parameter encrypt: Set to `true` to encrypt, `false` to decrypt
     - returns: The processed message
     - throws: `SignalError` of type `encryptionError` or `decryptionError`
     */
    private func process(cbc message: Data, key: Data, iv: Data, encrypt: Bool) throws -> Data {
        let operation = encrypt ? CCOperation(kCCEncrypt_Bridge) : CCOperation(kCCDecrypt_Bridge)
        // Create output memory that can fit the output data
        let dataLength = message.count + Int(kCCBlockSizeAES128_Bridge)
        let ptr = UnsafeMutableRawPointer.allocate(byteCount: dataLength, alignment: MemoryLayout<UInt8>.alignment)
        defer { ptr.deallocate() }

        var dataOutMoved: Int = 0
        let status: Int32 = withUnsafeMutablePointer(to: &dataOutMoved) { dataOutMovedPtr in
            // Pointer to key
            key.withUnsafeBytes { ptr1 in
                let keyPtr = ptr1.baseAddress!
                // Pointer to IV
                return iv.withUnsafeBytes { ptr2 in
                    let ivPtr = ptr2.baseAddress!
                    // Pointer to message
                    return message.withUnsafeBytes { ptr3 in
                        let messagePtr = ptr3.baseAddress!
                        // Options
                        let algorithm = CCAlgorithm(kCCAlgorithmAES_Bridge)
                        let padding = CCOptions(kCCOptionPKCS7Padding_Bridge)
                        // Encrypt
                        return CCCrypt(operation, algorithm, padding, keyPtr, key.count, ivPtr,
                                       messagePtr, message.count, ptr, dataLength, dataOutMovedPtr)
                    }
                }
            }
        }
        guard status == kCCSuccess_Bridge else {
            if encrypt {
                throw SignalError(.encryptionError, "AES (CBC mode) encryption error: \(status)")
            } else {
                throw SignalError(.decryptionError, "AES (CBC mode) decryption error: \(status)")
            }
        }

        // Convert the pointers to data
        let typedPointer = ptr.bindMemory(to: UInt8.self, capacity: dataOutMoved)
        let typedBuffer = UnsafeMutableBufferPointer<UInt8>(start: typedPointer, count: dataOutMoved)
        return Data(typedBuffer)
    }

    /**
     Process a message with AES in CTR mode.
     - parameter message: The message to process
     - parameter key: The key
     - parameter iv: The initialization vector
     - parameter encrypt: Set to `true` to encrypt, `false` to decrypt
     - returns: The processed message
     - throws: `SignalError` of type `encryptionError` or `decryptionError`
     - note: In CTR mode, encryption and decryption are the same operation.
     However, the `encrypt` parameter is kept for consistency.
     */
    private func process(ctr message: Data, key: Data, iv: Data, encrypt: Bool) throws -> Data {
        var cryptoRef: CCCryptorRef? = nil
        
        var status: Int32 = key.withUnsafeBytes { ptr1 in
            let keyPtr = ptr1.baseAddress!
            return iv.withUnsafeBytes { ptr2 in
                let ivPtr = ptr2.baseAddress!
                let operation = encrypt ? CCOperation(kCCEncrypt_Bridge) : CCOperation(kCCDecrypt_Bridge)
                let mode = CCMode(kCCModeCTR_Bridge)
                let algorithm = CCAlgorithm(kCCAlgorithmAES_Bridge)
                let padding = CCPadding(ccNoPadding_Bridge)
                let options = CCModeOptions(kCCModeOptionCTR_BE_Bridge)
                return CCCryptorCreateWithMode(
                    operation, mode, algorithm, padding, ivPtr, keyPtr, key.count,
                    nil, 0, 0, options , &cryptoRef)
            }
        }

        // Release the reference before the method returns or throws an error
        defer { CCCryptorRelease(cryptoRef) }

        guard status == kCCSuccess_Bridge, let ref = cryptoRef else {
            if encrypt {
                throw SignalError(.encryptionError, "AES (CTR mode) encryption init error: \(status)")
            } else {
                throw SignalError(.decryptionError, "AES (CTR mode) decryption init error: \(status)")
            }
        }

        let outputLength = CCCryptorGetOutputLength(ref, message.count, true)
        let ptr = UnsafeMutableRawPointer.allocate(byteCount: outputLength, alignment: MemoryLayout<UInt8>.alignment)
        // Release the memory before the method returns or throws an error
        defer { ptr.deallocate() }

        var updateMovedLength: Int = 0
        status = withUnsafeMutablePointer(to: &updateMovedLength) { updatedPtr in
            message.withUnsafeBytes { ptr3 in
                let messagePtr = ptr3.baseAddress!
                return CCCryptorUpdate(ref, messagePtr, message.count, ptr, outputLength, updatedPtr)
            }
        }

        guard updateMovedLength <= outputLength else {
            throw SignalError(.encryptionError, "Updated bytes \(updateMovedLength) for \(outputLength) total bytes")
        }
        guard status == kCCSuccess_Bridge else {
            if encrypt {
                throw SignalError(.encryptionError, "AES (CTR mode) encryption update error: \(status)")
            } else {
                throw SignalError(.decryptionError, "AES (CTR mode) decryption update error: \(status)")
            }
        }

        // Finalize
        let ptr2 = ptr.advanced(by: updateMovedLength)
        let available = outputLength - updateMovedLength
        var finalMovedLength: Int = 0
        status = withUnsafeMutablePointer(to: &finalMovedLength) {
                CCCryptorFinal(ref, ptr2, available, $0)
        }
        let finalLength = updateMovedLength + finalMovedLength
        guard status == kCCSuccess_Bridge else {
            if encrypt {
                throw SignalError(.encryptionError, "AES (CTR mode) encryption update error: \(status)")
            } else {
                throw SignalError(.decryptionError, "AES (CTR mode) decryption update error: \(status)")
            }
        }

        // Convert the pointers to data
        let typedPointer = ptr.bindMemory(to: UInt8.self, capacity: finalLength)
        let typedBuffer = UnsafeMutableBufferPointer<UInt8>(start: typedPointer, count: finalLength)
        return Data(typedBuffer)
    }
    
    /**
     Create an instance.
     */
    public init() {
        
    }
}
