package com.unbihex.vpn

import android.app.Activity
import android.app.PendingIntent
import android.content.Context
import android.content.ComponentName
import android.content.Intent
import android.graphics.drawable.Icon
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import android.widget.Toast
import androidx.core.content.ContextCompat
import java.util.concurrent.Executors

private fun startHeadless(context: Context) {
    val generation = UnbihexVpnService.reserve(context) ?: return
    try {
        ContextCompat.startForegroundService(context, Intent(context, UnbihexVpnService::class.java)
            .setAction(UnbihexVpnService.ACTION_TILE_START)
            .putExtra(UnbihexVpnService.EXTRA_GENERATION, generation))
    } catch (e: Exception) {
        UnbihexVpnService.cancel(context, generation)
        Toast.makeText(context, "Не удалось запустить VPN: ${e.message}", Toast.LENGTH_LONG).show()
    }
}

class VpnTileService : TileService() {
    companion object {
        private val main = Handler(Looper.getMainLooper())
        // The label comes from the native side, which may read the data file: off the main thread.
        private val labels = Executors.newSingleThreadExecutor()
        // Last known label (main thread): shown at once, replaced when the new one arrives.
        private var label = "Unbihex"
        // Accessed only on the main thread; cleared when SystemUI stops listening.
        private var listening: VpnTileService? = null

        fun refresh(context: Context) {
            val app = context.applicationContext
            main.post {
                // requestListeningState alone does not re-enter an already listening tile.
                listening?.update()
                requestListeningState(app, ComponentName(app, VpnTileService::class.java))
            }
        }
    }
    override fun onStartListening() {
        super.onStartListening()
        listening = this
        update()
    }
    override fun onStopListening() {
        if (listening === this) listening = null
        super.onStopListening()
    }
    override fun onDestroy() {
        if (listening === this) listening = null
        super.onDestroy()
    }
    /**
     * Active or inactive shows the state; the label names the server in use (with
     * auto-select, the one working now), else the selected one. Quick settings
     * labels cannot scroll, so the native side drops leading flags and emoji.
     */
    private fun update() {
        show()
        val dir = applicationInfo.dataDir
        labels.execute {
            val next = try { NativeVpn.label(dir) } catch (e: Throwable) { null }
            if (!next.isNullOrBlank()) main.post {
                if (next != label) {
                    label = next
                    if (listening === this) show()
                }
            }
        }
    }
    private fun show() {
        val vpnState = UnbihexVpnService.state
        qsTile?.apply {
            val connected = vpnState == "connected"
            state = if (connected) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
            icon = Icon.createWithResource(this@VpnTileService,
                if (connected) R.drawable.ic_unbihex_vpn else R.drawable.ic_unbihex_vpn_outline)
            label = VpnTileService.label
            contentDescription = "Unbihex: ${VpnTileService.label}"
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) subtitle = null
            updateTile()
        }
    }
    override fun onClick() {
        super.onClick()
        if (isLocked) unlockAndRun { toggle() } else toggle()
    }
    private fun toggle() {
        if (UnbihexVpnService.state != "disconnected") {
            UnbihexVpnService.cancel(this)
            try {
                startService(
                    Intent(this, UnbihexVpnService::class.java)
                        .setAction(UnbihexVpnService.ACTION_STOP)
                        .putExtra(UnbihexVpnService.EXTRA_GENERATION, -1L)
                )
            } catch (_: Exception) {
            }
            update()
            return
        }
        if (VpnService.prepare(this) == null) startHeadless(this)
        else {
            val intent = Intent(this, VpnConsentActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            if (Build.VERSION.SDK_INT >= 34) {
                startActivityAndCollapse(PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE))
            } else {
                @Suppress("DEPRECATION")
                startActivityAndCollapse(intent)
            }
        }
    }
}

class VpnConsentActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (savedInstanceState != null) return
        val permission = VpnService.prepare(this)
        if (permission == null) { startHeadless(this); finish() }
        else @Suppress("DEPRECATION") startActivityForResult(permission, 1)
    }
    @Deprecated("Android activity result")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 1 && resultCode == RESULT_OK) startHeadless(this)
        else UnbihexVpnService.refresh(this)
        finish()
    }
}

class VpnTilePreferencesActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        packageManager.getLaunchIntentForPackage(packageName)?.let { startActivity(it) }
        finish()
    }
}
