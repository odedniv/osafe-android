package me.odedniv.osafe.models.encryption

import me.odedniv.osafe.models.random
import java.security.MessageDigest
import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

data class Content(
        val cipherType: CipherType,
        val digestType: DigestType,
        val iv: ByteArray,
        val digest: ByteArray,
        val content: ByteArray) {

    enum class CipherType {
        AES_128;

        companion object {
            val ALGORITHMS = hashMapOf(
                    AES_128 to "AES"
            )
            val BLOCK_MODES = hashMapOf(
                    AES_128 to "CBC"
            )
            val PADDINGS = hashMapOf(
                    AES_128 to "PKCS7Padding"
            )
        }

        val algorithm by lazy { ALGORITHMS[this]!! }
        val blockMode by lazy { BLOCK_MODES[this]!! }
        val padding by lazy { PADDINGS[this]!! }
        val transformation by lazy { "$algorithm/$blockMode/$padding" }
    }

    enum class DigestType {
        SHA_1;

        companion object {
            val ALGORITHMS = hashMapOf(
                    SHA_1 to "SHA-1"
            )
        }

        val algorithm by lazy { ALGORITHMS[this]!! }
    }

    companion object {
        val DEFAULT_CIPHER_TYPE = CipherType.AES_128
        val DEFAULT_DIGEST_TYPE = DigestType.SHA_1

        fun encrypt(key: ByteArray, content: ByteArray): Content {
            val cipher = Cipher.getInstance(DEFAULT_CIPHER_TYPE.transformation)
            cipher.init(
                    Cipher.ENCRYPT_MODE,
                    SecretKeySpec(key.copyOf(cipher.blockSize), DEFAULT_CIPHER_TYPE.algorithm)
            )
            return encrypt(cipher, content)
        }

        fun encrypt(cipher: Cipher, content: ByteArray): Content {
            return Content(
                    cipherType = DEFAULT_CIPHER_TYPE,
                    digestType = DEFAULT_DIGEST_TYPE,
                    iv = cipher.iv,
                    digest = MessageDigest.getInstance(DEFAULT_DIGEST_TYPE.algorithm).digest(content),
                    content = cipher.doFinal(content)
            )
        }
    }

    fun decrypt(key: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(cipherType.transformation)
        cipher.init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(key.copyOf(cipher.blockSize), cipherType.algorithm),
                IvParameterSpec(iv)
        )
        return decrypt(cipher)
    }

    fun decrypt(cipher: Cipher): ByteArray {
        val content = cipher.doFinal(content)
        if (!digest.contentEquals(MessageDigest.getInstance(digestType.algorithm).digest(content))) {
            throw RuntimeException("Signature verification failed")
        }
        return content
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Content

        if (cipherType != other.cipherType) return false
        if (digestType != other.digestType) return false
        if (!Arrays.equals(iv, other.iv)) return false
        if (!Arrays.equals(digest, other.digest)) return false
        if (!Arrays.equals(content, other.content)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = cipherType.hashCode()
        result = 31 * result + digestType.hashCode()
        result = 31 * result + Arrays.hashCode(iv)
        result = 31 * result + Arrays.hashCode(digest)
        result = 31 * result + Arrays.hashCode(content)
        return result
    }
}