package com.unbihex.vpn

import android.app.Activity
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import android.widget.Toast
import androidx.core.content.ContextCompat

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
    override fun onStartListening() { super.onStartListening(); update() }
    private fun update() {
        qsTile?.apply {
            state = if (UnbihexVpnService.state == "connected") Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
            label = "Unbihex"
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) subtitle = when (UnbihexVpnService.state) {
                "connecting" -> "Подключение"; "connected" -> "Подключено"; else -> "Отключено"
            }
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
            try { startService(Intent(this, UnbihexVpnService::class.java).setAction(UnbihexVpnService.ACTION_STOP).putExtra(UnbihexVpnService.EXTRA_GENERATION, -1L)) } catch (_: Exception) {}
            update(); return
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
