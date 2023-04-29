package dev.keiji.keypair_import.sample

/**
 * https://android-review.linaro.org/plugins/gitiles/platform/hardware/interfaces/+/96f2167c4af5aa90333749521cf99b40ee59cb4f/security/keymint/aidl/android/hardware/security/keymint
 */
internal object KeymasterDefs {

    internal enum class Digest(val id: Long) {
        NONE(0),
        MD5(1),
        SHA1(2),
        SHA_2_224(3),
        SHA_2_256(4),
        SHA_2_384(5),
        SHA_2_512(6),
    }

    internal enum class Algorithm(val id: Long) {
        /** Asymmetric algorithms. */
        RSA(1),

        /** 2 removed, do not reuse. */

        /** Elliptic Curve algorithms. */
        EC(3),

        /** Block cipher algorithms */
        AES(32),
        TRIPLE_DES(33),

        /** MAC algorithms */
        HMAC(128),
    }

    internal enum class EcCurve(val id: Long) {
        P224(0),
        P256(1),
        P384(2),
        P521(3),
    }

    internal enum class KeyPurpose(val id: Long) {
        /* Usable with RSA, 3DES and AES keys. */
        ENCRYPT(0),

        /* Usable with RSA, 3DES and AES keys. */
        DECRYPT(1),

        /* Usable with RSA, EC and HMAC keys. */
        SIGN(2),

        /* Usable with RSA, EC and HMAC keys. */
        VERIFY(3),

        /* 4 is reserved */
        /* Usable with wrapping keys. */
        WRAP_KEY(5),

        /* Key Agreement, usable with EC keys. */
        AGREE_KEY(6),

        /* Usable as an attestation signing key.  Keys with this purpose must not have any other
         * purpose. */
        ATTEST_KEY(7),
    }

    internal enum class PaddingMode(val id: Long) {
        NONE(1), /* deprecated */
        RSA_OAEP(2),
        RSA_PSS(3),
        RSA_PKCS1_1_5_ENCRYPT(4),
        RSA_PKCS1_1_5_SIGN(5),
        PKCS7(64),
    }

    internal enum class BlockMode(val id: Long) {
        /*
         * Unauthenticated modes, usable only for encryption/decryption and not generally recommended
         * except for compatibility with existing other protocols.
         */
        ECB(1),
        CBC(2),
        CTR(3),

        /*
         * Authenticated modes, usable for encryption/decryption and signing/verification.
         * Recommended over unauthenticated modes for all purposes.
         */
        GCM(32),
    }

    internal enum class KeyFormat(val id: Long) {
        /** X.509 certificate format, for public key export. */
        X509(0),

        /** PCKS#8 format, asymmetric key pair import. */
        PKCS8(1),

        /** Raw bytes, for symmetric key import. */
        RAW(3),
    }

    internal enum class HardwareAuthenticatorType(val id: Long) {
        NONE(0),
        PASSWORD(1 shl 0),
        FINGERPRINT(1 shl 1),

        // Additional entries must be powers of 2.
        ANY(0xFFFFFFFF),
    }

    internal enum class KeyOrigin(val id: Long) {
        /** Generated in keyMint.  Should not exist outside the TEE. */
        GENERATED(0),

        /** Derived inside keyMint.  Likely exists off-device. */
        DERIVED(1),

        /** Imported into keyMint.  Existed as cleartext in Android. */
        IMPORTED(2),

        /** Previously used for another purpose that is now obsolete. */
        RESERVED(3),

        /**
         * Securely imported into KeyMint.  Was created elsewhere, and passed securely through Android
         * to secure hardware.
         */
        SECURELY_IMPORTED(4),
    }

    internal enum class SecurityLevel(val id: Int) {
        /**
         * The SOFTWARE security level represents a KeyMint implementation that runs in an Android
         * process, or a tag enforced by such an implementation.  An attacker who can compromise that
         * process, or obtain root, or subvert the kernel on the device can defeat it.
         *
         * Note that the distinction between SOFTWARE and KEYSTORE is only relevant on-device.  For
         * attestation purposes, these categories are combined into the software-enforced authorization
         * list.
         */
        SOFTWARE(0),

        /**
         * The TRUSTED_ENVIRONMENT security level represents a KeyMint implementation that runs in an
         * isolated execution environment that is securely isolated from the code running on the kernel
         * and above, and which satisfies the requirements specified in CDD 9.11.1 [C-1-2]. An attacker
         * who completely compromises Android, including the Linux kernel, does not have the ability to
         * subvert it.  An attacker who can find an exploit that gains them control of the trusted
         * environment, or who has access to the physical device and can mount a sophisticated hardware
         * attack, may be able to defeat it.
         */
        TRUSTED_ENVIRONMENT(1),

        /**
         * The STRONGBOX security level represents a KeyMint implementation that runs in security
         * hardware that satisfies the requirements specified in CDD 9.11.2.  Roughly speaking, these
         * are discrete, security-focus computing environments that are hardened against physical and
         * side channel attack, and have had their security formally validated by a competent
         * penetration testing lab.
         */
        STRONGBOX(2),

        /**
         * KeyMint implementations must never return the KEYSTORE security level from getHardwareInfo.
         * It is used to specify tags that are not enforced by the IKeyMintDevice, but are instead
         * to be enforced by Keystore.  An attacker who can subvert the keystore process or gain root or
         * subvert the kernel can prevent proper enforcement of these tags.
         *
         *
         * Note that the distinction between SOFTWARE and KEYSTORE is only relevant on-device.  When
         * KeyMint generates an attestation certificate, these categories are combined into the
         * software-enforced authorization list.
         */
        KEYSTORE(100),
    }

    internal enum class ErrorCode(val id: Long) {
        OK(0),
        ROOT_OF_TRUST_ALREADY_SET(-1),
        UNSUPPORTED_PURPOSE(-2),
        INCOMPATIBLE_PURPOSE(-3),
        UNSUPPORTED_ALGORITHM(-4),
        INCOMPATIBLE_ALGORITHM(-5),
        UNSUPPORTED_KEY_SIZE(-6),
        UNSUPPORTED_BLOCK_MODE(-7),
        INCOMPATIBLE_BLOCK_MODE(-8),
        UNSUPPORTED_MAC_LENGTH(-9),
        UNSUPPORTED_PADDING_MODE(-10),
        INCOMPATIBLE_PADDING_MODE(-11),
        UNSUPPORTED_DIGEST(-12),
        INCOMPATIBLE_DIGEST(-13),
        INVALID_EXPIRATION_TIME(-14),
        INVALID_USER_ID(-15),
        INVALID_AUTHORIZATION_TIMEOUT(-16),
        UNSUPPORTED_KEY_FORMAT(-17),
        INCOMPATIBLE_KEY_FORMAT(-18),
        UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM(-19),

        /** For PKCS8 & PKCS12 */
        UNSUPPORTED_KEY_VERIFICATION_ALGORITHM(-20),

        /** For PKCS8 & PKCS12 */
        INVALID_INPUT_LENGTH(-21),
        KEY_EXPORT_OPTIONS_INVALID(-22),
        DELEGATION_NOT_ALLOWED(-23),
        KEY_NOT_YET_VALID(-24),
        KEY_EXPIRED(-25),
        KEY_USER_NOT_AUTHENTICATED(-26),
        OUTPUT_PARAMETER_NULL(-27),
        INVALID_OPERATION_HANDLE(-28),
        INSUFFICIENT_BUFFER_SPACE(-29),
        VERIFICATION_FAILED(-30),
        TOO_MANY_OPERATIONS(-31),
        UNEXPECTED_NULL_POINTER(-32),
        INVALID_KEY_BLOB(-33),
        IMPORTED_KEY_NOT_ENCRYPTED(-34),
        IMPORTED_KEY_DECRYPTION_FAILED(-35),
        IMPORTED_KEY_NOT_SIGNED(-36),
        IMPORTED_KEY_VERIFICATION_FAILED(-37),
        INVALID_ARGUMENT(-38),
        UNSUPPORTED_TAG(-39),
        INVALID_TAG(-40),
        MEMORY_ALLOCATION_FAILED(-41),
        IMPORT_PARAMETER_MISMATCH(-44),
        SECURE_HW_ACCESS_DENIED(-45),
        OPERATION_CANCELLED(-46),
        CONCURRENT_ACCESS_CONFLICT(-47),
        SECURE_HW_BUSY(-48),
        SECURE_HW_COMMUNICATION_FAILED(-49),
        UNSUPPORTED_EC_FIELD(-50),
        MISSING_NONCE(-51),
        INVALID_NONCE(-52),
        MISSING_MAC_LENGTH(-53),
        KEY_RATE_LIMIT_EXCEEDED(-54),
        CALLER_NONCE_PROHIBITED(-55),
        KEY_MAX_OPS_EXCEEDED(-56),
        INVALID_MAC_LENGTH(-57),
        MISSING_MIN_MAC_LENGTH(-58),
        UNSUPPORTED_MIN_MAC_LENGTH(-59),
        UNSUPPORTED_KDF(-60),
        UNSUPPORTED_EC_CURVE(-61),
        KEY_REQUIRES_UPGRADE(-62),
        ATTESTATION_CHALLENGE_MISSING(-63),
        KEYMINT_NOT_CONFIGURED(-64),
        ATTESTATION_APPLICATION_ID_MISSING(-65),
        CANNOT_ATTEST_IDS(-66),
        ROLLBACK_RESISTANCE_UNAVAILABLE(-67),
        HARDWARE_TYPE_UNAVAILABLE(-68),
        PROOF_OF_PRESENCE_REQUIRED(-69),
        CONCURRENT_PROOF_OF_PRESENCE_REQUESTED(-70),
        NO_USER_CONFIRMATION(-71),
        DEVICE_LOCKED(-72),
        EARLY_BOOT_ENDED(-73),
        ATTESTATION_KEYS_NOT_PROVISIONED(-74),
        ATTESTATION_IDS_NOT_PROVISIONED(-75),
        INVALID_OPERATION(-76),
        STORAGE_KEY_UNSUPPORTED(-77),
        INCOMPATIBLE_MGF_DIGEST(-78),
        UNSUPPORTED_MGF_DIGEST(-79),
        MISSING_NOT_BEFORE(-80),
        MISSING_NOT_AFTER(-81),
        MISSING_ISSUER_SUBJECT(-82),
        INVALID_ISSUER_SUBJECT(-83),
        BOOT_LEVEL_EXCEEDED(-84),
        HARDWARE_NOT_YET_AVAILABLE(-85),
        UNIMPLEMENTED(-100),
        VERSION_MISMATCH(-101),
        UNKNOWN_ERROR(-1000),
        // Implementer's namespace for error codes starts at -10000.
    }
}
