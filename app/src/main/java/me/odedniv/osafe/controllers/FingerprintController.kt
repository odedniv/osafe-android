package me.odedniv.osafe.controllers

import android.content.Context
import android.support.v4.content.ContextCompat
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat
import android.support.v4.os.CancellationSignal
import android.widget.ImageView
import android.widget.TextView
import me.odedniv.osafe.R

class FingerprintController(
        private val fingerprintManager: FingerprintManagerCompat,
        private val callback: Callback,
        private val title: TextView,
        private val subtitle: TextView,
        private val errorText: TextView,
        private val icon: ImageView) : FingerprintManagerCompat.AuthenticationCallback() {

    interface Callback {
        fun onAuthenticated(cryptoObject: FingerprintManagerCompat.CryptoObject)
        fun onError()
    }

    /*
     * Properties
     */

    /**
     * Helper variable to get the context from one of the views. The view used is arbitrary.
     */
    private val context: Context
        get() = errorText.context

    private var cancellationSignal: CancellationSignal? = null
    private var selfCancelled = false

    private val isFingerprintAuthAvailable: Boolean
        get() = fingerprintManager.isHardwareDetected && fingerprintManager.hasEnrolledFingerprints()

    private val resetErrorTextRunnable: Runnable = Runnable {
        errorText.setTextColor(ContextCompat.getColor(context, R.color.hint_color))
        errorText.text = context.getString(R.string.touch_sensor)
        icon.setImageResource(R.drawable.ic_fingerprint)
    }

    /*
     * Methods
     */

    init {
        errorText.post(resetErrorTextRunnable)
    }

    fun setTitle(text: String) {
        title.text = text
    }

    fun setSubtitle(text: String) {
        subtitle.text = text
    }

    fun startListening(cryptoObject: FingerprintManagerCompat.CryptoObject) {
        if (!isFingerprintAuthAvailable) return

        cancellationSignal = CancellationSignal()
        selfCancelled = false
        fingerprintManager.authenticate(cryptoObject, 0, cancellationSignal, this, null)
    }

    fun stopListening() {
        cancellationSignal?.let {
            selfCancelled = true
            it.cancel()
            cancellationSignal = null
        }
    }

    private fun showError(text: CharSequence?) {
        icon.setImageResource(R.drawable.ic_error)
        errorText.text = text
        errorText.setTextColor(ContextCompat.getColor(errorText.context, R.color.warning_color))
        errorText.removeCallbacks(resetErrorTextRunnable)
        errorText.postDelayed(resetErrorTextRunnable, ERROR_TIMEOUT_MILLIS)
    }

    /*
     * AuthenticationCallback
     */

    override fun onAuthenticationError(errMsgId: Int, errString: CharSequence?) {
        if (!selfCancelled) {
            showError(errString)
            icon.postDelayed({
                callback.onError()
            }, ERROR_TIMEOUT_MILLIS)
        }
    }

    override fun onAuthenticationSucceeded(result: FingerprintManagerCompat.AuthenticationResult) {
        errorText.removeCallbacks(resetErrorTextRunnable)
        icon.setImageResource(R.drawable.ic_check)
        errorText.setTextColor(ContextCompat.getColor(errorText.context, R.color.success_color))
        errorText.text = errorText.context.getString(R.string.fingerprint_recognized)
        icon.postDelayed({
            callback.onAuthenticated(result.cryptoObject)
        }, SUCCESS_DELAY_MILLIS)
    }

    override fun onAuthenticationHelp(helpMsgId: Int, helpString: CharSequence?) {
        showError(helpString)
    }

    override fun onAuthenticationFailed() {
        showError(errorText.context.getString(R.string.fingerprint_not_recognized))
    }

    companion object {
        private const val ERROR_TIMEOUT_MILLIS = 1600L
        private const val SUCCESS_DELAY_MILLIS = 1300L
    }
}