package me.odedniv.osafe.models

import android.os.AsyncTask
import android.os.Parcel
import android.os.Parcelable
import com.google.android.gms.tasks.Task
import com.google.android.gms.tasks.Tasks
import me.odedniv.osafe.models.encryption.Content
import me.odedniv.osafe.models.encryption.Key
import me.odedniv.osafe.models.encryption.Message
import java.security.MessageDigest
import java.util.concurrent.Callable
import javax.crypto.Cipher

class Encryption(private val keyLabel: Key.Label, private var key: ByteArray): Parcelable {
    private var original: Message? = null
    private var baseKey: ByteArray? = null

    constructor(passphrase: String): this(Key.Label.PASSPHRASE, generateKey(passphrase))

    fun encrypt(content: String): Task<Message> {
        return Tasks.call(AsyncTask.THREAD_POOL_EXECUTOR, Callable {
            if (baseKey == null) {
                baseKey = random(64)
            }
            original = Message(
                    keys = original?.keys ?: Array(1, {
                        Key(
                                label = Key.Label.PASSPHRASE,
                                content = Content.encrypt(
                                        key = key,
                                        content = baseKey!!
                                )
                        )
                    }),
                    content = Content.encrypt(
                            key = baseKey!!,
                            content = content.toByteArray(Charsets.UTF_8)
                    )
            )
            original!!
        })
    }

    /*
     Checks the encryption against the message's keys, and assumes the baseKey after successful decryption.
     Returns the key's index in the message, fails the task if the key is invalid.
     */
    private fun check(message: Message): Task<Int> {
        return Tasks.call(AsyncTask.THREAD_POOL_EXECUTOR, Callable {
            var keyIndex: Int? = null
            message.keys.withIndex().any {
                if (it.value.label != keyLabel) return@any false
                try {
                    baseKey = it.value.content.decrypt(key)
                } catch (e: Exception) {
                    return@any false
                }
                keyIndex = it.index
                true
            }
            if (keyIndex == null) throw RuntimeException("Decryption failed")
            original = message
            keyIndex!!
        })
    }

    fun decrypt(message: Message): Task<String> {
        return check(message)
                .onSuccessTask {
                    Tasks.call(AsyncTask.THREAD_POOL_EXECUTOR, Callable {
                        message.content.decrypt(baseKey!!).toString(Charsets.UTF_8)
                    })
                }
    }

    fun changeKey(message: Message, passphrase: String): Task<Message> {
        return check(message)
                .onSuccessTask { keyIndex ->
                    Tasks.call(AsyncTask.THREAD_POOL_EXECUTOR, Callable {
                        key = generateKey(passphrase)
                        val keys = message.keys.copyOf()
                        keys[keyIndex!!] = Key(
                                label = Key.Label.PASSPHRASE,
                                content = Content.encrypt(
                                        key = key,
                                        content = baseKey!!
                                )
                        )
                        original = Message(
                                keys = keys,
                                content = message.content
                        )
                        original!!
                    })
                }
    }

    fun addKey(message: Message, label: Key.Label, cipher: Cipher): Task<Message> {
        return check(message)
                .onSuccessTask { _ ->
                    Tasks.call(AsyncTask.THREAD_POOL_EXECUTOR, Callable {
                        val keys = message.keys + Key(
                                label = label,
                                content = Content.encrypt(
                                        cipher = cipher,
                                        content = baseKey!!
                                )
                        )
                        original = Message(
                                keys = keys,
                                content = message.content
                        )
                        original!!
                    })
                }
    }

    fun removeKey(message: Message, key: Key): Task<Message> {
        val keys = message.keys.toMutableList()
        keys.remove(key)
        return Tasks.forResult(
                Message(
                        keys = keys.toTypedArray(),
                        content = message.content
                )
        )
    }

    /*
    Parcelable implementation
     */

    private constructor(parcel: Parcel) : this(
            keyLabel = Key.Label.valueOf(parcel.readString()),
            key = readParcelByteArray(parcel)
    )

    override fun writeToParcel(parcel: Parcel, flags: Int) {
        parcel.writeString(keyLabel.toString())
        parcel.writeInt(key.size)
        parcel.writeByteArray(key)
    }

    override fun describeContents(): Int {
        return 0
    }

    companion object CREATOR : Parcelable.Creator<Encryption> {
        private fun generateKey(passphrase: String): ByteArray {
            return MessageDigest
                    .getInstance("SHA-512")
                    .digest(passphrase.toByteArray(Charsets.UTF_8))
        }

        override fun createFromParcel(parcel: Parcel): Encryption {
            return Encryption(parcel)
        }

        override fun newArray(size: Int): Array<Encryption?> {
            return arrayOfNulls(size)
        }
    }
}
