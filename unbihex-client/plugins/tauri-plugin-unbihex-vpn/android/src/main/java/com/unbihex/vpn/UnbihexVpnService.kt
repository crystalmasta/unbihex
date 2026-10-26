package com.unbihex.vpn

import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log

/**
 * Owns the TUN interface. The descriptor stays open here; the engine works on a
 * dup() of it, so closing this one (stop or revoke) plus stopping the engine tears
 * the interface down.
 *
 * The app's own package is excluded from the VPN, which keeps the engine's sockets
 * (to the proxy server, DNS and direct sites) out of the tunnel without protect().
 */
class UnbihexVpnService : VpnService() {
    companion object {
        const val ACTION_START = "com.unbihex.vpn.START"
        const val ACTION_STOP = "com.unbihex.vpn.STOP"
        const val EXTRA_MTU = "mtu"
        const val EXTRA_ADDRESS = "address"
        const val EXTRA_PREFIX = "prefix"
        const val EXTRA_DNS = "dns"
        const val EXTRA_SESSION = "session"
        private const val TAG = "UnbihexVpn"

        /** True while the interface is up. Read by the plugin's `status`. */
        @Volatile
        var isActive: Boolean = false

        /** Called once with (fd, null) or (null, error) after a start request. */
        @Volatile
        var onEstablished: ((Int?, String?) -> Unit)? = null
    }

    private var tun: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent == null || intent.action == ACTION_STOP) {
            // A null intent is a restart after the process died: the engine is gone too.
            shutdown()
            stopSelf()
            return START_NOT_STICKY
        }
        val callback = onEstablished
        onEstablished = null
        try {
            closeTun()
            val builder = Builder()
                .setSession(intent.getStringExtra(EXTRA_SESSION) ?: "Unbihex")
                .setMtu(intent.getIntExtra(EXTRA_MTU, 1500))
                .addAddress(
                    intent.getStringExtra(EXTRA_ADDRESS) ?: "10.199.233.1",
                    intent.getIntExtra(EXTRA_PREFIX, 30)
                )
                .addRoute("0.0.0.0", 0)
                .addDnsServer(intent.getStringExtra(EXTRA_DNS) ?: "10.199.233.2")
            // Route IPv6 into the tunnel too, otherwise it would leak around the VPN.
            try {
                builder.addAddress("fdb5:2f3c:9a17::1", 126)
                builder.addRoute("::", 0)
            } catch (e: Exception) {
                Log.w(TAG, "IPv6 is not available: ${e.message}")
            }
            builder.addDisallowedApplication(packageName)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setMetered(false)
            }
            val pfd = builder.establish()
                ?: throw IllegalStateException("система не создала VPN-интерфейс (разрешение отозвано?)")
            tun = pfd
            isActive = true
            callback?.invoke(pfd.fd, null)
        } catch (e: Exception) {
            Log.e(TAG, "establish failed", e)
            shutdown()
            callback?.invoke(null, e.message ?: e.toString())
        }
        return START_NOT_STICKY
    }

    private fun closeTun() {
        try {
            tun?.close()
        } catch (_: Exception) {
        }
        tun = null
    }

    private fun shutdown() {
        isActive = false
        closeTun()
    }

    override fun onRevoke() {
        // Another VPN took over or the user switched us off in Settings.
        shutdown()
        stopSelf()
    }

    override fun onDestroy() {
        shutdown()
        super.onDestroy()
    }
}
