package me.odedniv.osafe.activities

import android.app.Activity
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.IBinder
import android.text.Editable
import android.text.TextWatcher
import android.util.Log
import android.view.View
import android.view.WindowManager
import android.widget.Toast
import com.google.android.gms.auth.api.signin.GoogleSignIn
import com.google.android.gms.auth.api.signin.GoogleSignInOptions
import com.google.android.gms.common.ConnectionResult
import com.google.android.gms.common.GoogleApiAvailability
import com.google.android.gms.drive.Drive
import com.google.android.gms.tasks.Task
import com.google.android.gms.tasks.Tasks
import kotlinx.android.synthetic.main.activity_content.*
import me.odedniv.osafe.R
import me.odedniv.osafe.models.Encryption
import me.odedniv.osafe.models.Storage
import me.odedniv.osafe.services.EncryptionStorageService
import java.util.*
import javax.crypto.BadPaddingException

class ContentActivity : BaseActivity() {
    companion object {
        private const val REQUEST_GOOGLE_SIGN_IN = 1
        private const val REQUEST_ENCRYPTION = 2
    }

    private val storage = Storage(this)
    private var googleSignInReceived = false
    private var started = false
    private var encryption: Encryption? = null
    private var encryptionStorage : EncryptionStorageService.EncryptionStorageBinder? = null
    private var lastStored: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        setContentView(R.layout.activity_content)
        setSupportActionBar(toolbar_content)

        startService(encryptionStorageIntent)
        bindService(
                encryptionStorageIntent,
                encryptionStorageConnection,
                Context.BIND_AUTO_CREATE
        )

        edit_content.addTextChangedListener(object : TextWatcher {
            override fun afterTextChanged(s: Editable?) {
                dumpLater()
            }
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) { }
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) { }
        })
    }

    override fun onDestroy() {
        unbindService(encryptionStorageConnection)
        super.onDestroy()
    }

    override fun onStart() {
        super.onStart()
        started = true
        getGoogleSignInAccount()
        getEncryptionAndLoad()
    }

    override fun onStop() {
        started = false
        encryption = null
        super.onStop()
    }

    override fun onPause() {
        dump()
        super.onPause()
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)

        when (requestCode) {
            REQUEST_GOOGLE_SIGN_IN -> {
                if (resultCode != RESULT_OK) {
                    googleSignInReceived = true
                    getEncryptionAndLoad()
                    return
                }
                GoogleSignIn.getSignedInAccountFromIntent(intent)
                        .addOnSuccessListener {
                            storage.setGoogleSignInAccount(it)
                        }
                        .addOnFailureListener {
                            Log.e("GoogleSignIn", "Failed getting Google account", it)
                        }
                        .addOnCompleteListener {
                            googleSignInReceived = true
                            getEncryptionAndLoad()
                        }
            }
            REQUEST_ENCRYPTION -> {
                if (resultCode != Activity.RESULT_OK) {
                    finish()
                    return
                }
                data!!
                encryption = data.getParcelableExtra(EXTRA_ENCRYPTION)
                encryptionStorage?.set(
                        encryption = encryption!!,
                        timeout = data.getLongExtra(EXTRA_ENCRYPTION_TIMEOUT, 0)
                )
                getEncryptionAndLoad()
            }
        }
    }

    private fun getGoogleSignInAccount() {
        if (GoogleApiAvailability.getInstance().isGooglePlayServicesAvailable(this) != ConnectionResult.SUCCESS) {
            googleSignInReceived = true
            return
        }
        val googleSignInAccount = GoogleSignIn.getLastSignedInAccount(this)
        if (googleSignInAccount != null) {
            storage.setGoogleSignInAccount(googleSignInAccount)
            googleSignInReceived = true
            return
        }
        startActivityForResult(
                GoogleSignIn.getClient(
                        this,
                        GoogleSignInOptions.Builder(GoogleSignInOptions.DEFAULT_SIGN_IN)
                                .requestScopes(Drive.SCOPE_FILE)
                                .build()
                ).signInIntent,
                REQUEST_GOOGLE_SIGN_IN
        )
    }

    private fun getEncryptionAndLoad() {
        if (!started || !googleSignInReceived || encryptionStorage == null) return
        if (encryption == null) encryption = encryptionStorage?.encryption
        if (encryption != null) {
            // from EncryptionStorageService
            load()
        } else {
            // either timed out, never set
            storage.messageExists
                    .addOnSuccessListener { exists ->
                        val activity =
                                if (exists)
                                    ExistingPassphraseActivity::class.java
                                else
                                    NewPassphraseActivity::class.java
                        startActivityForResult(
                                Intent(this@ContentActivity, activity),
                                REQUEST_ENCRYPTION
                        )
                    }
        }
    }

    private var dumpLaterTimer: Timer? = null

    private fun dumpLater() {
        encryption ?: return

        if (dumpLaterTimer != null) {
            dumpLaterTimer?.cancel()
            dumpLaterTimer = null
        }

        if (lastStored == edit_content.text.toString()) return

        dumpLaterTimer = Timer()
        dumpLaterTimer!!.schedule(object : TimerTask() {
            override fun run() {
                runOnUiThread {
                    progress_spinner.visibility = View.VISIBLE
                    dump().addOnSuccessListener {
                        progress_spinner.visibility = View.GONE
                    }
                }
            }
        }, 5000)
    }

    private fun dump(): Task<Unit> {
        encryption ?: return Tasks.forResult(Unit)

        if (dumpLaterTimer != null) {
            dumpLaterTimer?.cancel()
            dumpLaterTimer = null
        }

        val content = edit_content.text.toString()
        if (lastStored == content) return Tasks.forResult(Unit)
        lastStored = content

        return encryption!!.encrypt(content, storage.message)
                .onSuccessTask { message ->
                    storage.setMessage(message)
                }
    }

    private fun load() {
        storage.getMessage { message ->
            if (message == null) return@getMessage

            encryption!!.decrypt(message)
                    .addOnSuccessListener { content ->
                        lastStored = content
                        edit_content.setText(content)
                    }
                    .addOnFailureListener { e ->
                        when (e) {
                            is BadPaddingException -> {
                                encryption = null
                                encryptionStorage?.clear()
                                Toast.makeText(this, R.string.wrong_passphrase, Toast.LENGTH_SHORT).show()
                                getEncryptionAndLoad()
                            }
                            else -> throw e
                        }
                    }
        }.addOnSuccessListener {
            edit_content.isEnabled = true
            progress_spinner.visibility = View.GONE
        }
    }

    private val encryptionStorageConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
            encryptionStorage = service as EncryptionStorageService.EncryptionStorageBinder
            getEncryptionAndLoad()
        }
        override fun onServiceDisconnected(name: ComponentName?) {
            encryptionStorage = null
        }
    }

    private val encryptionStorageIntent: Intent
        get() = Intent(this, EncryptionStorageService::class.java)
}
