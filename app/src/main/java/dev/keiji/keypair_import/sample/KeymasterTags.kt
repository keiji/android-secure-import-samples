package dev.keiji.keypair_import.sample

/**
 * https://android-review.linaro.org/plugins/gitiles/platform/hardware/interfaces/+/96f2167c4af5aa90333749521cf99b40ee59cb4f/security/keymint/aidl/android/hardware/security/keymint
 */
internal object KeymasterTags {

    internal enum class TagType(val value: Long) {
        /** Invalid type, used to designate a tag as uninitialized. */
        INVALID(0 shl 28),

        /** Enumeration value. */
        ENUM(1 shl 28),

        /** Repeatable enumeration value. */
        ENUM_REP(2 shl 28),

        /** 32-bit unsigned integer. */
        UINT(3 shl 28),

        /** Repeatable 32-bit unsigned integer. */
        UINT_REP(4 shl 28),

        /** 64-bit unsigned integer. */
        ULONG(5 shl 28),

        /** 64-bit unsigned integer representing a date and time, in milliseconds since 1 Jan 1970. */
        DATE(6 shl 28),

        /** Boolean.  If a tag with this type is present, the value is "true".  If absent, "false". */
        BOOL(7 shl 28),

        /**
         * Byte string containing an arbitrary-length integer, in a two's-complement big-endian
         * ordering.  The byte array contains the minimum number of bytes needed to represent the
         * integer, including at least one sign bit (so zero encodes as the single byte 0x00.  This
         * matches the encoding of both java.math.BigInteger.toByteArray() and contents octets for an
         * ASN.1 INTEGER value (X.690 section 8.3).  Examples:
         * - value 65536 encodes as 0x01 0x00 0x00
         * - value 65535 encodes as 0x00 0xFF 0xFF
         * - value   255 encodes as 0x00 0xFF
         * - value     1 encodes as 0x01
         * - value     0 encodes as 0x00
         * - value    -1 encodes as 0xFF
         * - value  -255 encodes as 0xFF 0x01
         * - value  -256 encodes as 0xFF 0x00
         */
        BIGNUM(8 shl 28),

        /** Byte string */
        BYTES(9 shl 28),

        /** Repeatable 64-bit unsigned integer */
        ULONG_REP(10 shl 28),
    }

    internal class Tag {
        companion object {
            // Authorization list tags. The list is in this AOSP file:
            // hardware/libhardware/include/hardware/keymaster_defs.h
            const val KM_TAG_PURPOSE = 1
            const val KM_TAG_ALGORITHM = 2
            const val KM_TAG_KEY_SIZE = 3
            const val KM_TAG_BLOCK_MODE = 4
            const val KM_TAG_DIGEST = 5
            const val KM_TAG_PADDING = 6
            const val KM_TAG_EC_CURVE = 10
            const val KM_TAG_RSA_PUBLIC_EXPONENT = 200
            const val KM_TAG_ROLLBACK_RESISTANCE = 303
            const val KM_TAG_ACTIVE_DATE_TIME = 400
            const val KM_TAG_ORIGINATION_EXPIRE_DATE_TIME = 401
            const val KM_TAG_USAGE_EXPIRE_DATE_TIME = 402
            const val KM_TAG_NO_AUTH_REQUIRED = 503
            const val KM_TAG_USER_AUTH_TYPE = 504
            const val KM_TAG_AUTH_TIMEOUT = 505
            const val KM_TAG_ALLOW_WHILE_ON_BODY = 506
            const val KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED = 507
            const val KM_TAG_TRUSTED_CONFIRMATION_REQUIRED = 508
            const val KM_TAG_UNLOCKED_DEVICE_REQUIRED = 509
            const val KM_TAG_ALL_APPLICATIONS = 600
            const val KM_TAG_APPLICATION_ID = 601
            const val KM_TAG_CREATION_DATE_TIME = 701
            const val KM_TAG_ORIGIN = 702
            const val KM_TAG_ROLLBACK_RESISTANT = 703
            const val KM_TAG_ROOT_OF_TRUST = 704
            const val KM_TAG_OS_VERSION = 705
            const val KM_TAG_OS_PATCH_LEVEL = 706
            const val KM_TAG_ATTESTATION_APPLICATION_ID = 709
            const val KM_TAG_ATTESTATION_ID_BRAND = 710
            const val KM_TAG_ATTESTATION_ID_DEVICE = 711
            const val KM_TAG_ATTESTATION_ID_PRODUCT = 712
            const val KM_TAG_ATTESTATION_ID_SERIAL = 713
            const val KM_TAG_ATTESTATION_ID_IMEI = 714
            const val KM_TAG_ATTESTATION_ID_MEID = 715
            const val KM_TAG_ATTESTATION_ID_MANUFACTURER = 716
            const val KM_TAG_ATTESTATION_ID_MODEL = 717
            const val KM_TAG_VENDOR_PATCH_LEVEL = 718
            const val KM_TAG_BOOT_PATCH_LEVEL = 719
            const val KM_TAG_DEVICE_UNIQUE_ATTESTATION = 720
            const val ROOT_OF_TRUST_VERIFIED_BOOT_KEY_INDEX = 0
            const val ROOT_OF_TRUST_DEVICE_LOCKED_INDEX = 1
            const val ROOT_OF_TRUST_VERIFIED_BOOT_STATE_INDEX = 2
            const val ROOT_OF_TRUST_VERIFIED_BOOT_HASH_INDEX = 3
            const val ATTESTATION_APPLICATION_ID_PACKAGE_INFOS_INDEX = 0
            const val ATTESTATION_APPLICATION_ID_SIGNATURE_DIGESTS_INDEX = 1
            const val ATTESTATION_PACKAGE_INFO_PACKAGE_NAME_INDEX = 0
            const val ATTESTATION_PACKAGE_INFO_VERSION_INDEX = 1

            // Some security values. The complete list is in this AOSP file:
            // hardware/libhardware/include/hardware/keymaster_defs.h
            const val KM_SECURITY_LEVEL_SOFTWARE = 0
            const val KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT = 1
            const val KM_SECURITY_LEVEL_STRONG_BOX = 2
            const val KM_VERIFIED_BOOT_STATE_VERIFIED = 0
            const val KM_VERIFIED_BOOT_STATE_SELF_SIGNED = 1
            const val KM_VERIFIED_BOOT_STATE_UNVERIFIED = 2
            const val KM_VERIFIED_BOOT_STATE_FAILED = 3

            // Unsigned max value of 32-bit integer, 2^32 - 1
            const val UINT32_MAX = (Int.MAX_VALUE.toLong() shl 1) + 1
        }
    }
}
