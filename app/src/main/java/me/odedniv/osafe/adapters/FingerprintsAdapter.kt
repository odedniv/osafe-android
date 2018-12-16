package me.odedniv.osafe.adapters

import android.support.v7.widget.RecyclerView
import android.view.LayoutInflater
import android.view.ViewGroup
import android.widget.TextView
import me.odedniv.osafe.R
import me.odedniv.osafe.models.encryption.Key

class FingerprintsAdapter(private val keys: MutableList<Key>, private val onFingerprintClickedListener: OnFingerprintClickedListener) :
        RecyclerView.Adapter<FingerprintsAdapter.ViewHolder>() {
    class ViewHolder(val text_fingerprint: TextView) : RecyclerView.ViewHolder(text_fingerprint)

    interface OnFingerprintClickedListener {
        fun onFingerprintClicked(key: Key)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        return ViewHolder(
                LayoutInflater.from(parent.context)
                        .inflate(R.layout.text_fingerprint, parent, false) as TextView
        )
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val key = keys[position]
        holder.text_fingerprint.apply {
            // representing each key as hexadecimal of its IV
            text = key.content.iv.joinToString(separator = ":") {
                it.toInt().and(0xff).toString(16).padStart(2, '0')
            }
            setOnClickListener {
                onFingerprintClickedListener.onFingerprintClicked(key)
            }
        }
    }

    override fun getItemCount() = keys.size

    fun add(key: Key) {
        keys.add(key)
        notifyItemInserted(keys.size - 1)
    }

    fun remove(key: Key) {
        val position = keys.indexOf(key)
        keys.removeAt(position)
        notifyItemRemoved(position)
    }
}