package dev.keiji.keypair_import.sample

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.WrappedKeyEntry
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERSet
import org.bouncycastle.asn1.DERTaggedObject
import java.nio.charset.StandardCharsets
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PublicKey
import java.security.SecureRandom
import java.security.spec.InvalidKeySpecException
import java.security.spec.MGF1ParameterSpec
import java.util.Arrays
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.SecretKeySpec

class MainViewModel : ViewModel() {
    data class UiState(
        val status: String = ""
    )

    private val _uiState: MutableStateFlow<UiState> = MutableStateFlow(UiState())
    val uiState: StateFlow<UiState>
        get() = _uiState

    private val secureRandom = SecureRandom.getInstanceStrong()

    private val keyAlias = UUID.randomUUID().toString()

    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).also {
        it.load(null)
    }

    fun generateKey(isStrongBoxEnabled: Boolean) {
        viewModelScope.launch {
            internalGenerateKey(isStrongBoxEnabled)
        }
    }

    private suspend fun internalGenerateKey(isStrongBoxEnabled: Boolean) =
        withContext(Dispatchers.IO) {
            _uiState.value = _uiState.value.copy(
                status = "Wrapping keypair generating..."
            )

            val aesKeyMaterial = ByteArray(AES_KEY_SIZE_IN_BYTES).also {
                secureRandom.nextBytes(it)
            }
            val wrappingKeyPair =
                generateKeyPairInKeyStore(
                    WRAPPING_KEY_ALIAS,
                    isStrongBoxBacked = isStrongBoxEnabled
                )

            _uiState.value = _uiState.value.copy(
                status = "Wrapping key..."
            )

            val wrappedKeyMaterial = wrapKey(
                wrappingKeyPair.public,
                aesKeyMaterial,
                makeAuthList(aesKeyMaterial.size * Byte.SIZE_BITS, KeymasterDefs.Algorithm.AES),
            )

            _uiState.value = _uiState.value.copy(
                status = "Importing key..."
            )

            importWrappedKey(
                wrappedKeyMaterial,
                WRAPPING_KEY_ALIAS,
                keyAlias,
                isStrongBoxEnabled = isStrongBoxEnabled,
            )

            _uiState.value = _uiState.value.copy(
                status = "Key has been Imported."
            )
        }

    private fun importWrappedKey(
        wrappedKeyMaterial: ByteArray,
        wrappingKeyAlias: String,
        keyAlias: String,
        isStrongBoxEnabled: Boolean,
    ) {
        val spec = KeyGenParameterSpec.Builder(
            wrappingKeyAlias,
            KeyProperties.PURPOSE_WRAP_KEY
        )
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setIsStrongBoxBacked(isStrongBoxEnabled)
            .build()

        val wrappedKeyEntry = WrappedKeyEntry(
            wrappedKeyMaterial,
            wrappingKeyAlias,
            "RSA/ECB/OAEPPadding",
            spec
        )
        keyStore.setEntry(keyAlias, wrappedKeyEntry, null)
    }

    private fun wrapKey(
        publicKey: PublicKey,
        keyMaterial: ByteArray,
        authorizationList: DERSequence?,
    ): ByteArray {
        // Build description
        val descriptionItems = ASN1EncodableVector().apply {
            add(ASN1Integer(KeymasterDefs.KeyFormat.RAW.id))
            add(authorizationList)
        }

        val wrappedKeyDescription = DERSequence(descriptionItems)

        val iv = ByteArray(INITIALIZATION_VECTOR_LENGTH).also {
            secureRandom.nextBytes(it)
        }
        val aesKeyBytes = ByteArray(AES_KEY_SIZE_IN_BYTES).also {
            secureRandom.nextBytes(it)
        }

        val spec = OAEPParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec.SHA1,
            PSource.PSpecified.DEFAULT
        )
        val pkCipher = Cipher.getInstance("RSA/ECB/OAEPPadding").also {
            it.init(Cipher.ENCRYPT_MODE, publicKey, spec)
        }

        val encryptedEphemeralKeys = pkCipher.doFinal(aesKeyBytes)
        val secretKeySpec = SecretKeySpec(aesKeyBytes, KeyProperties.KEY_ALGORITHM_AES)
        val gcmParameterSpec = GCMParameterSpec(GCM_TAG_SIZE, iv)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding").also {
            it.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec)
        }

        val aad = wrappedKeyDescription.encoded
        cipher.updateAAD(aad)

        var encryptedSecureKey = cipher.doFinal(keyMaterial)

        val len = encryptedSecureKey.size
        val tagSize: Int = GCM_TAG_SIZE / Byte.SIZE_BITS
        val tag: ByteArray = Arrays.copyOfRange(encryptedSecureKey, len - tagSize, len)

        encryptedSecureKey = Arrays.copyOfRange(encryptedSecureKey, 0, len - tagSize)

        val items = ASN1EncodableVector().apply {
            add(ASN1Integer(WRAPPED_FORMAT_VERSION))
            add(DEROctetString(encryptedEphemeralKeys))
            add(DEROctetString(iv))
            add(wrappedKeyDescription)
            add(DEROctetString(encryptedSecureKey))
            add(DEROctetString(tag))
        }
        return DERSequence(items).encoded
    }

    private fun makeAuthList(
        sizeInBit: Int,
        _algorithm: KeymasterDefs.Algorithm,
    ): DERSequence {
        // Make an AuthorizationList to describe the secure key
        // https://developer.android.com/training/articles/security-key-attestation.html#verifying
        val allPurposes = ASN1EncodableVector().apply {
            add(ASN1Integer(KeymasterDefs.KeyPurpose.ENCRYPT.id))
            add(ASN1Integer(KeymasterDefs.KeyPurpose.DECRYPT.id))
        }

        val purposeSet = DERSet(allPurposes)
        val purpose = DERTaggedObject(true, KeymasterTags.Tag.KM_TAG_PURPOSE, purposeSet)
        val algorithm = DERTaggedObject(
            true,
            KeymasterTags.Tag.KM_TAG_ALGORITHM,
            ASN1Integer(_algorithm.id)
        )
        val keySize =
            DERTaggedObject(
                true,
                KeymasterTags.Tag.KM_TAG_KEY_SIZE,
                ASN1Integer(sizeInBit.toLong())
            )

        val allBlockModes = ASN1EncodableVector().apply {
            add(ASN1Integer(KeymasterDefs.BlockMode.ECB.id))
            add(ASN1Integer(KeymasterDefs.BlockMode.CBC.id))
        }

        val blockModeSet = DERSet(allBlockModes)
        val blockMode = DERTaggedObject(true, KeymasterTags.Tag.KM_TAG_BLOCK_MODE, blockModeSet)

        val allPaddings = ASN1EncodableVector().apply {
            add(ASN1Integer(KeymasterDefs.PaddingMode.PKCS7.id))
            add(ASN1Integer(KeymasterDefs.PaddingMode.NONE.id))
        }

        val paddingSet = DERSet(allPaddings)
        val padding = DERTaggedObject(true, KeymasterTags.Tag.KM_TAG_PADDING, paddingSet)
        val noAuthRequired =
            DERTaggedObject(true, KeymasterTags.Tag.KM_TAG_NO_AUTH_REQUIRED, DERNull.INSTANCE)

        // Build sequence
        val allItems = ASN1EncodableVector().apply {
            add(purpose)
            add(algorithm)
            add(keySize)
            add(blockMode)
            add(padding)
            add(noAuthRequired)
        }
        return DERSequence(allItems)
    }

    private fun generateKeyPairInKeyStore(alias: String, isStrongBoxBacked: Boolean): KeyPair {
        val keyPairGenerator =
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE)
        keyPairGenerator.initialize(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_WRAP_KEY)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                .setIsStrongBoxBacked(isStrongBoxBacked)
                .build()
        )
        return keyPairGenerator.generateKeyPair()
    }

    fun useKey(plainText: String) {
        val secretKey = keyStore.getKey(keyAlias, null) as SecretKey

        val factory = SecretKeyFactory.getInstance(secretKey.algorithm, ANDROID_KEYSTORE)
        val keyInfo = try {
            factory.getKeySpec(secretKey, KeyInfo::class.java) as KeyInfo
        } catch (exception: InvalidKeySpecException) {
            return
        }

        val encipher = Cipher.getInstance(ENCRYPTION_TRANSFORMATION).also {
            it.init(Cipher.ENCRYPT_MODE, secretKey)
        }

        val encrypted = encipher.doFinal(plainText.toByteArray(charset = StandardCharsets.UTF_8))
        val iv = encipher.iv

        val decipher = Cipher.getInstance(ENCRYPTION_TRANSFORMATION).also {
            it.init(Cipher.DECRYPT_MODE, secretKey, IvParameterSpec(iv))
        }

        val result = decipher.doFinal(encrypted)
        val decrypted = String(result, charset = StandardCharsets.UTF_8)

        val keyDescription = keyInfo.description()

        val status = "decrypted: $decrypted\n" +
                "description: $keyDescription\n" +
                ""
        _uiState.value = _uiState.value.copy(
            status = status
        )
    }

    private fun KeyInfo.description(): String {
        return StringBuffer().let { sb ->
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                val securityLevel = getSecurityLevelText(this.securityLevel)
                sb.append("securityLevel: ${securityLevel ?: "Unknown"}")
            } else {
                sb.append("isInsideSecureHardware: ${this.isInsideSecureHardware}")
            }
            sb.append("\n")
            sb.toString()
        }
    }

    private fun getSecurityLevelText(securityLevel: Int): KeymasterDefs.SecurityLevel? {
        return when (securityLevel) {
            KeymasterDefs.SecurityLevel.SOFTWARE.id -> KeymasterDefs.SecurityLevel.SOFTWARE
            KeymasterDefs.SecurityLevel.KEYSTORE.id -> KeymasterDefs.SecurityLevel.KEYSTORE
            KeymasterDefs.SecurityLevel.TRUSTED_ENVIRONMENT.id -> KeymasterDefs.SecurityLevel.TRUSTED_ENVIRONMENT
            KeymasterDefs.SecurityLevel.STRONGBOX.id -> KeymasterDefs.SecurityLevel.STRONGBOX
            else -> null
        }
    }

    companion object {
        private const val TAG = "MainViewModel"

        private const val ANDROID_KEYSTORE = "AndroidKeyStore"

        private const val ENCRYPTION_TRANSFORMATION = "AES/CBC/PKCS7Padding"
        private const val AES_KEY_SIZE_IN_BYTES = 256 / Byte.SIZE_BITS
        private const val INITIALIZATION_VECTOR_LENGTH = 12

        private const val WRAPPING_KEY_ALIAS = "wrapping_key_alias"

        private const val WRAPPED_FORMAT_VERSION = 0L
        private const val GCM_TAG_SIZE = 128
    }
}
