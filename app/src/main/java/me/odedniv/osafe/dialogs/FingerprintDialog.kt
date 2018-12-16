package me.odedniv.osafe.dialogs

import android.content.Context
import android.os.Build
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.support.annotation.RequiresApi
import android.support.v4.app.DialogFragment
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import kotlinx.android.synthetic.main.dialog_fingerprint.*
import me.odedniv.osafe.R
import me.odedniv.osafe.controllers.FingerprintController
import me.odedniv.osafe.models.encryption.Content
import java.io.IOException
import java.security.*
import java.security.cert.CertificateException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.NoSuchPaddingException
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

/**
 * DialogFragment that prompts the user to authenticate their fingerprint.
 */
class FingerprintDialog : DialogFragment(), FingerprintController.Callback {
    interface OnFingerprintReceivedListener {
        fun onFingerprintReceived(cryptoObject: FingerprintManagerCompat.CryptoObject)
    }

    private lateinit var listener: OnFingerprintReceivedListener

    private val controller: FingerprintController by lazy {
        FingerprintController(
                FingerprintManagerCompat.from(context),
                this,
                titleTextView,
                subtitleTextView,
                errorTextView,
                iconFAB
        )
    }

    /**
     * CryptoObject is a wrapper class for any cryptography required by the FingerprintManager.
     * https://developer.android.com/reference/android/support/v4/hardware/fingerprint/FingerprintManagerCompat.CryptoObject.html
     */
    private var cryptoObject: FingerprintManagerCompat.CryptoObject? = null

    /**
     * KeyStore is the device's storage for any cryptographic keys and certificates. We use this to get a key for the fingerprint manager.
     * https://developer.android.com/reference/java/security/KeyStore.html
     */
    private var keyStore: KeyStore? = null

    /**
     * This class is used to generate the keys that were reference from the [keyStore].
     * https://developer.android.com/reference/javax/crypto/KeyGenerator.html
     */
    private var keyGenerator: KeyGenerator? = null

    override fun onCreateView(inflater: LayoutInflater?, container: ViewGroup?, savedInstanceState: Bundle?): View? =
            inflater?.inflate(R.layout.dialog_fingerprint, container, false)


    override fun onViewCreated(view: View?, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        controller.setTitle(arguments.getString(ARG_TITLE))
        controller.setSubtitle(arguments.getString(ARG_SUBTITLE))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return

        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore")
        } catch (e: KeyStoreException) {
            throw RuntimeException("Failed to get an instance of KeyStore", e)
        }

        try {
            keyGenerator = KeyGenerator
                    .getInstance(Content.DEFAULT_CIPHER_TYPE.algorithm, "AndroidKeyStore")
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException("Failed to get an instance of KeyGenerator", e)
        } catch (e: NoSuchProviderException) {
            throw RuntimeException("Failed to get an instance of KeyGenerator", e)
        }

        createKey(DEFAULT_KEY_NAME, false)

        val defaultCipher: Cipher
        try {
            defaultCipher = Cipher.getInstance(Content.DEFAULT_CIPHER_TYPE.transformation)
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException("Failed to get an instance of Cipher", e)
        } catch (e: NoSuchPaddingException) {
            throw RuntimeException("Failed to get an instance of Cipher", e)
        }

        if (initCipher(defaultCipher, DEFAULT_KEY_NAME)) {
            cryptoObject = FingerprintManagerCompat.CryptoObject(defaultCipher)
        }
    }

    override fun onAttach(context: Context) {
        super.onAttach(context)
        try {
            listener = context as OnFingerprintReceivedListener
        } catch (e: ClassCastException) {
            throw ClassCastException(context.toString() + " must implement OnFingerprintReceivedListener")
        }

    }

    override fun onResume() {
        super.onResume()

        dialog?.window?.setLayout(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
        cryptoObject?.let {
            controller.startListening(it)
        }
    }

    override fun onPause() {
        super.onPause()
        controller.stopListening()
    }

    override fun onAuthenticated(cryptoObject: FingerprintManagerCompat.CryptoObject) {
        listener.onFingerprintReceived(cryptoObject)
        dismiss()
    }

    override fun onError() {
        //TODO:
    }

    /**
     * Lifted code from the Google samples - https://github.com/googlesamples/android-FingerprintDialog/blob/master/kotlinApp/app/src/main/java/com/example/android/fingerprintdialog/MainActivity.kt
     *
     * Initialize the [Cipher] instance with the created key in the
     * [.createKey] method.
     *
     * @param keyName the key name to init the cipher
     * @return `true` if initialization is successful, `false` if the lock screen has
     * been disabled or reset after the key was generated, or if a fingerprint got enrolled after
     * the key was generated.
     */
    @RequiresApi(Build.VERSION_CODES.M)
    private fun initCipher(cipher: Cipher, keyName: String): Boolean {
        try {
            keyStore?.load(null)
            val key = keyStore?.getKey(keyName, null) as SecretKey
            // If IV is not supplied it means encryption mode, otherwise decryption
            if (!arguments.containsKey(ARG_IV)) {
                cipher.init(Cipher.ENCRYPT_MODE, key)
            } else {
                cipher.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(arguments.getByteArray(ARG_IV)))
            }
            return true
        } catch (e: KeyPermanentlyInvalidatedException) {
            return false
        } catch (e: KeyStoreException) {
            throw RuntimeException("Failed to init Cipher", e)
        } catch (e: CertificateException) {
            throw RuntimeException("Failed to init Cipher", e)
        } catch (e: UnrecoverableKeyException) {
            throw RuntimeException("Failed to init Cipher", e)
        } catch (e: IOException) {
            throw RuntimeException("Failed to init Cipher", e)
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException("Failed to init Cipher", e)
        } catch (e: InvalidKeyException) {
            throw RuntimeException("Failed to init Cipher", e)
        }
    }

    /**
     * Lifted code from the Google Samples - https://github.com/googlesamples/android-FingerprintDialog/blob/master/kotlinApp/app/src/main/java/com/example/android/fingerprintdialog/MainActivity.kt
     *
     * Creates a symmetric key in the Android Key Store which can only be used after the user has
     * authenticated with fingerprint.
     *
     * @param keyName the name of the key to be created
     * @param invalidatedByBiometricEnrollment if `false` is passed, the created key will not
     * be invalidated even if a new fingerprint is enrolled.
     * The default value is `true`, so passing
     * `true` doesn't change the behavior
     * (the key will be invalidated if a new fingerprint is
     * enrolled.). Note that this parameter is only valid if
     * the app works on Android N developer preview.
     */
    @RequiresApi(Build.VERSION_CODES.M)
    private fun createKey(keyName: String, invalidatedByBiometricEnrollment: Boolean) {
        // The enrolling flow for fingerprint. This is where you ask the user to set up fingerprint
        // for your flow. Use of keys is necessary if you need to know if the set of
        // enrolled fingerprints has changed.
        try {
            keyStore?.load(null)
            // Set the alias of the entry in Android KeyStore where the key will appear
            // and the constrains (purposes) in the constructor of the Builder

            val builder = KeyGenParameterSpec.Builder(keyName, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(Content.DEFAULT_CIPHER_TYPE.blockMode)
                    // Require the user to authenticate with a fingerprint to authorize every use
                    // of the key
                    .setUserAuthenticationRequired(true)
                    .setUserAuthenticationValidityDurationSeconds(10000)
                    .setEncryptionPaddings(Content.DEFAULT_CIPHER_TYPE.padding)

            // This is a workaround to avoid crashes on devices whose API level is < 24
            // because KeyGenParameterSpec.Builder#setInvalidatedByBiometricEnrollment is only
            // visible on API level +24.
            // Ideally there should be a compat library for KeyGenParameterSpec.Builder but
            // which isn't available yet.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                builder.setInvalidatedByBiometricEnrollment(invalidatedByBiometricEnrollment)
            }
            keyGenerator?.init(builder.build())
            keyGenerator?.generateKey()
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException(e)
        } catch (e: InvalidAlgorithmParameterException) {
            throw RuntimeException(e)
        } catch (e: CertificateException) {
            throw RuntimeException(e)
        } catch (e: IOException) {
            throw RuntimeException(e)
        }

    }

    companion object {
        /**
         * Fragment tag that is used when this dialog is shown.
         */
        val FRAGMENT_TAG: String = FingerprintDialog::class.java.simpleName

        // Bundle keys for each of the arguments of the newInstance method.
        private const val ARG_TITLE = "ArgTitle"
        private const val ARG_SUBTITLE = "ArgSubtitle"
        private const val ARG_IV = "ArgIV" // when not supplied means encryption, when supplied means decryption

        private const val DEFAULT_KEY_NAME = "default_key"

        fun newEncryptionInstance(title: String, subtitle: String): FingerprintDialog {
            val args = Bundle()
            args.putString(ARG_TITLE, title)
            args.putString(ARG_SUBTITLE, subtitle)
            // IV not supplied means encryption mode

            val fragment = FingerprintDialog()
            fragment.arguments = args

            return fragment
        }

        fun newDecryptionInstance(title: String, subtitle: String, iv: ByteArray): FingerprintDialog {
            val args = Bundle()
            args.putString(ARG_TITLE, title)
            args.putString(ARG_SUBTITLE, subtitle)
            args.putByteArray(ARG_IV, iv)

            val fragment = FingerprintDialog()
            fragment.arguments = args

            return fragment
        }
    }
}