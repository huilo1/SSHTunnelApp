package com.sshtunnel.ui

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.sshtunnel.data.AuthMethod
import com.sshtunnel.data.ServerProfile
import com.sshtunnel.databinding.ItemServerBinding

class ServerAdapter(
    private val onSelect: (ServerProfile) -> Unit,
    private val onEdit: (ServerProfile) -> Unit,
    private val onDelete: (ServerProfile) -> Unit
) : ListAdapter<ServerProfile, ServerAdapter.ViewHolder>(DIFF) {

    var selectedId: String? = null
        set(value) {
            field = value
            notifyDataSetChanged()
        }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val binding = ItemServerBinding.inflate(LayoutInflater.from(parent.context), parent, false)
        return ViewHolder(binding)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val profile = getItem(position)
        holder.bind(profile)
    }

    inner class ViewHolder(private val binding: ItemServerBinding) :
        RecyclerView.ViewHolder(binding.root) {

        fun bind(profile: ServerProfile) {
            binding.serverName.text = profile.name
            val authLabel = if (profile.authMethod == AuthMethod.KEY) "key" else "pass"
            binding.serverAddress.text = "${profile.username}@${profile.host}:${profile.port} ($authLabel)"
            binding.radioSelect.isChecked = profile.id == selectedId

            binding.root.setOnClickListener { onSelect(profile) }
            binding.radioSelect.setOnClickListener { onSelect(profile) }
            binding.editButton.setOnClickListener { onEdit(profile) }
            binding.deleteButton.setOnClickListener { onDelete(profile) }
        }
    }

    companion object {
        val DIFF = object : DiffUtil.ItemCallback<ServerProfile>() {
            override fun areItemsTheSame(a: ServerProfile, b: ServerProfile) = a.id == b.id
            override fun areContentsTheSame(a: ServerProfile, b: ServerProfile) = a == b
        }
    }
}
