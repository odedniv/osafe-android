package me.odedniv.osafe.activities

import android.support.v7.app.AppCompatActivity
import android.os.Bundle
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat
import android.support.v7.widget.LinearLayoutManager
import android.widget.Toast
import kotlinx.android.synthetic.main.activity_manage_fingerprints.*
import me.odedniv.osafe.R
import me.odedniv.osafe.adapters.FingerprintsAdapter
import me.odedniv.osafe.dialogs.FingerprintDialog
import me.odedniv.osafe.extensions.logFailure
import me.odedniv.osafe.models.Encryption
import me.odedniv.osafe.models.Storage
import me.odedniv.osafe.models.encryption.Key
import me.odedniv.osafe.models.encryption.Message

class ManageFingerprintsActivity :
        AppCompatActivity(), FingerprintDialog.OnFingerprintReceivedListener, FingerprintsAdapter.OnFingerprintClickedListener {
    private lateinit var storage: Storage
    private lateinit var message: Message
    private lateinit var adapter: FingerprintsAdapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_manage_fingerprints)

        storage = Storage(this)
        storage.state = intent.getParcelableExtra(BaseActivity.EXTRA_STORAGE)
        storage.get()
                .addOnSuccessListener { message ->
                    this.message = message!!
                    adapter = FingerprintsAdapter(relevantKeys.toMutableList(), this)
                    list_devices.apply {
                        setHasFixedSize(true)
                        layoutManager = LinearLayoutManager(this@ManageFingerprintsActivity)
                        adapter = this@ManageFingerprintsActivity.adapter
                    }
                    button_add.isEnabled = true
                }.logFailure(this, "Load", "Failed loading")

        button_add.setOnClickListener {
            val manager = FingerprintManagerCompat.from(this)

            if (manager.isHardwareDetected && manager.hasEnrolledFingerprints()) {
                val dialog = FingerprintDialog.newEncryptionInstance(
                        "Authorize this device's fingerprint",
                        "Confirm fingerprint to continue."
                )
                dialog.show(supportFragmentManager, FingerprintDialog.FRAGMENT_TAG)
            } else {
                Toast.makeText(this, "Fingerprint authentication is not supported.", Toast.LENGTH_SHORT).show()
            }
        }
    }

    override fun onFingerprintReceived(cryptoObject: FingerprintManagerCompat.CryptoObject) {
        encryption.addKey(message, Key.Label.FINGERPRINT, cryptoObject.cipher)
                .onSuccessTask {
                    message = it!!
                    storage.set(message)
                }
                .addOnSuccessListener {
                    adapter.add(message.keys.last())
                }.logFailure(this, "AddFingerprint", "Failed adding key")
    }


    override fun onFingerprintClicked(key: Key) {
        encryption.removeKey(message, key)
                .onSuccessTask {
                    message = it!!
                    storage.set(message)
                }
                .addOnSuccessListener {
                    adapter.remove(key)
                }.logFailure(this, "RemoveFingerprint", "Failed removing key")
    }

    private val relevantKeys: List<Key>
        get() = message.keys.filter { it.label == Key.Label.FINGERPRINT }

    private val encryption by lazy { intent.getParcelableExtra<Encryption>(BaseActivity.EXTRA_ENCRYPTION) }
}
