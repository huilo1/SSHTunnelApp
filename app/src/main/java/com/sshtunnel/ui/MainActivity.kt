package com.sshtunnel.ui

import android.Manifest
import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.view.View
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.LinearLayoutManager
import com.google.gson.Gson
import com.sshtunnel.R
import com.sshtunnel.data.AuthMethod
import com.sshtunnel.data.ProfileRepository
import com.sshtunnel.data.ServerProfile
import com.sshtunnel.databinding.ActivityMainBinding
import com.sshtunnel.databinding.DialogEditServerBinding
import com.sshtunnel.service.SshVpnService
import com.sshtunnel.service.VpnState

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var repo: ProfileRepository
    private lateinit var adapter: ServerAdapter
    private val gson = Gson()

    private val vpnLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            startVpn()
        } else {
            Toast.makeText(this, R.string.vpn_permission_denied, Toast.LENGTH_SHORT).show()
        }
    }

    private val notifPermLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { /* proceed regardless */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        repo = ProfileRepository(this)

        adapter = ServerAdapter(
            onSelect = { profile ->
                repo.setSelectedId(profile.id)
                adapter.selectedId = profile.id
                updateConnectButton()
            },
            onEdit = { showEditDialog(it) },
            onDelete = { confirmDelete(it) }
        )

        binding.serverList.layoutManager = LinearLayoutManager(this)
        binding.serverList.adapter = adapter

        binding.addButton.setOnClickListener { showEditDialog(null) }

        binding.connectButton.setOnClickListener {
            when (SshVpnService.currentState) {
                is VpnState.CONNECTED, is VpnState.CONNECTING -> stopVpn()
                else -> requestVpnPermission()
            }
        }

        // Toolbar menu: tap title area to show logs
        binding.toolbar.setOnClickListener { showLogDialog() }

        // Request notification permission on Android 13+
        if (Build.VERSION.SDK_INT >= 33) {
            if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                notifPermLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }

        SshVpnService.stateListener = { state -> runOnUiThread { updateUi(state) } }

        refreshList()
        updateUi(SshVpnService.currentState)
    }

    override fun onResume() {
        super.onResume()
        refreshList()
        updateUi(SshVpnService.currentState)
    }

    override fun onDestroy() {
        super.onDestroy()
        SshVpnService.stateListener = null
    }

    private fun refreshList() {
        val profiles = repo.getAll()
        adapter.selectedId = repo.getSelectedId()
        adapter.submitList(profiles)
        binding.emptyText.visibility = if (profiles.isEmpty()) View.VISIBLE else View.GONE
        binding.serverList.visibility = if (profiles.isEmpty()) View.GONE else View.VISIBLE
        updateConnectButton()
    }

    private fun updateConnectButton() {
        val hasSelection = repo.getSelectedId() != null &&
                repo.getAll().any { it.id == repo.getSelectedId() }
        val state = SshVpnService.currentState
        binding.connectButton.isEnabled = hasSelection || state is VpnState.CONNECTED || state is VpnState.CONNECTING
        binding.connectButton.text = when (state) {
            is VpnState.CONNECTED, is VpnState.CONNECTING -> getString(R.string.disconnect)
            else -> getString(R.string.connect)
        }
    }

    private fun updateUi(state: VpnState) {
        val indicator = binding.statusIndicator.background as? GradientDrawable
            ?: GradientDrawable().also {
                it.shape = GradientDrawable.OVAL
                binding.statusIndicator.background = it
            }

        when (state) {
            is VpnState.DISCONNECTED -> {
                indicator.setColor(ContextCompat.getColor(this, R.color.disconnected_gray))
                binding.statusText.text = getString(R.string.status_disconnected)
                binding.statusDetail.visibility = View.GONE
            }
            is VpnState.CONNECTING -> {
                indicator.setColor(ContextCompat.getColor(this, R.color.connecting_orange))
                binding.statusText.text = getString(R.string.status_connecting)
                binding.statusDetail.visibility = View.GONE
            }
            is VpnState.CONNECTED -> {
                indicator.setColor(ContextCompat.getColor(this, R.color.connected_green))
                binding.statusText.text = getString(R.string.status_connected)
                val profile = repo.getAll().find { it.id == repo.getSelectedId() }
                if (profile != null) {
                    binding.statusDetail.text = "${profile.username}@${profile.host}"
                    binding.statusDetail.visibility = View.VISIBLE
                }
            }
            is VpnState.ERROR -> {
                indicator.setColor(ContextCompat.getColor(this, R.color.error_red))
                binding.statusText.text = getString(R.string.status_error)
                binding.statusDetail.text = state.message
                binding.statusDetail.visibility = View.VISIBLE
            }
        }
        updateConnectButton()
    }

    private fun showLogDialog() {
        val scrollView = ScrollView(this).apply {
            setPadding(24, 16, 24, 16)
        }
        val textView = TextView(this).apply {
            typeface = Typeface.MONOSPACE
            textSize = 11f
            setTextIsSelectable(true)
        }
        scrollView.addView(textView)

        val logLines = SshVpnService.logBuffer.getAll()
        val logText = if (logLines.isEmpty()) "(no logs yet — connect to a server first)" else logLines.joinToString("\n")
        textView.text = logText

        val dialog = AlertDialog.Builder(this)
            .setTitle("Connection Logs")
            .setView(scrollView)
            .setPositiveButton("Close", null)
            .setNeutralButton("Copy") { _, _ ->
                val clipboard = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(ClipData.newPlainText("SSH Tunnel Logs", logText))
                Toast.makeText(this, "Logs copied", Toast.LENGTH_SHORT).show()
            }
            .setNegativeButton("Clear") { _, _ ->
                SshVpnService.logBuffer.clear()
            }
            .create()

        // Live-update the log as new lines come in
        val listener: (String) -> Unit = { line ->
            runOnUiThread {
                textView.append("\n$line")
                scrollView.post { scrollView.fullScroll(View.FOCUS_DOWN) }
            }
        }
        SshVpnService.logBuffer.onNewLine = listener
        dialog.setOnDismissListener { SshVpnService.logBuffer.onNewLine = null }

        dialog.show()
        // Scroll to bottom
        scrollView.post { scrollView.fullScroll(View.FOCUS_DOWN) }
    }

    private fun requestVpnPermission() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnLauncher.launch(intent)
        } else {
            startVpn()
        }
    }

    private fun startVpn() {
        val selectedId = repo.getSelectedId() ?: return
        val profile = repo.getAll().find { it.id == selectedId } ?: return

        val intent = Intent(this, SshVpnService::class.java).apply {
            action = SshVpnService.ACTION_START
            putExtra(SshVpnService.EXTRA_PROFILE_JSON, gson.toJson(profile))
        }
        startForegroundService(intent)
    }

    private fun stopVpn() {
        val intent = Intent(this, SshVpnService::class.java).apply {
            action = SshVpnService.ACTION_STOP
        }
        startService(intent)
    }

    private fun showEditDialog(existing: ServerProfile?) {
        val dialogBinding = DialogEditServerBinding.inflate(layoutInflater)
        val isNew = existing == null
        val profile = existing ?: ServerProfile()

        dialogBinding.inputName.setText(profile.name)
        dialogBinding.inputHost.setText(profile.host)
        dialogBinding.inputPort.setText(profile.port.toString())
        dialogBinding.inputUsername.setText(profile.username)
        dialogBinding.inputPassword.setText(profile.password)
        dialogBinding.inputPrivateKey.setText(profile.privateKey)
        dialogBinding.inputKeyPassphrase.setText(profile.keyPassphrase)
        dialogBinding.inputDns.setText(profile.dnsServer)

        if (profile.tunnelMode == com.sshtunnel.data.TunnelMode.SSH_TUN) {
            dialogBinding.tunnelModeToggle.check(dialogBinding.btnModeTun.id)
        } else {
            dialogBinding.tunnelModeToggle.check(dialogBinding.btnModeSocks.id)
        }

        val showPassword = {
            dialogBinding.passwordLayout.visibility = View.VISIBLE
            dialogBinding.keyLayout.visibility = View.GONE
            dialogBinding.keyPassphraseLayout.visibility = View.GONE
        }
        val showKey = {
            dialogBinding.passwordLayout.visibility = View.GONE
            dialogBinding.keyLayout.visibility = View.VISIBLE
            dialogBinding.keyPassphraseLayout.visibility = View.VISIBLE
        }

        if (profile.authMethod == AuthMethod.KEY) {
            dialogBinding.authToggle.check(dialogBinding.btnAuthKey.id)
            showKey()
        } else {
            dialogBinding.authToggle.check(dialogBinding.btnAuthPassword.id)
            showPassword()
        }

        dialogBinding.authToggle.addOnButtonCheckedListener { _, checkedId, isChecked ->
            if (isChecked) {
                when (checkedId) {
                    dialogBinding.btnAuthPassword.id -> showPassword()
                    dialogBinding.btnAuthKey.id -> showKey()
                }
            }
        }

        AlertDialog.Builder(this)
            .setTitle(if (isNew) R.string.add_server else R.string.edit_server)
            .setView(dialogBinding.root)
            .setPositiveButton(R.string.save) { _, _ ->
                val authMethod = if (dialogBinding.authToggle.checkedButtonId == dialogBinding.btnAuthKey.id)
                    AuthMethod.KEY else AuthMethod.PASSWORD
                val tunnelMode = if (dialogBinding.tunnelModeToggle.checkedButtonId == dialogBinding.btnModeTun.id)
                    com.sshtunnel.data.TunnelMode.SSH_TUN else com.sshtunnel.data.TunnelMode.SOCKS5

                val updated = profile.copy(
                    name = dialogBinding.inputName.text.toString().trim().ifEmpty { dialogBinding.inputHost.text.toString().trim() },
                    host = dialogBinding.inputHost.text.toString().trim(),
                    port = dialogBinding.inputPort.text.toString().toIntOrNull() ?: 22,
                    username = dialogBinding.inputUsername.text.toString().trim(),
                    authMethod = authMethod,
                    password = dialogBinding.inputPassword.text.toString(),
                    privateKey = dialogBinding.inputPrivateKey.text.toString(),
                    keyPassphrase = dialogBinding.inputKeyPassphrase.text.toString(),
                    dnsServer = dialogBinding.inputDns.text.toString().trim().ifEmpty { "8.8.8.8" },
                    tunnelMode = tunnelMode
                )
                repo.save(updated)
                if (isNew && repo.getAll().size == 1) {
                    repo.setSelectedId(updated.id)
                }
                refreshList()
            }
            .setNegativeButton(R.string.cancel, null)
            .show()
    }

    private fun confirmDelete(profile: ServerProfile) {
        AlertDialog.Builder(this)
            .setMessage(getString(R.string.confirm_delete, profile.name))
            .setPositiveButton(R.string.delete_server) { _, _ ->
                repo.delete(profile.id)
                if (repo.getSelectedId() == profile.id) {
                    repo.setSelectedId(repo.getAll().firstOrNull()?.id)
                }
                refreshList()
            }
            .setNegativeButton(R.string.cancel, null)
            .show()
    }
}
