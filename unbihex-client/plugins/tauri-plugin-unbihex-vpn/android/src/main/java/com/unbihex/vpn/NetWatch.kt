package com.unbihex.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.Network
import android.os.Build
import android.os.PowerManager
import android.util.Log
import java.util.concurrent.Executors

/**
 * Tells the operator whitelist checks (client-core `whitelist`) what the phone
 * does: another default network means "check now"; with the screen on they run
 * once a minute, with it off every 5 minutes. Started with the plugin and again by the VPN
 * service, which also covers a tile start without the app.
 */
object NetWatch {
    private const val TAG = "UnbihexNetWatch"
    private const val NETWORK = 0
    private const val SCREEN_ON = 1
    private const val SCREEN_OFF = 2
    private val worker = Executors.newSingleThreadExecutor()
    private var started = false

    private fun send(kind: Int) {
        worker.execute {
            try {
                NativeVpn.netEvent(kind)
            } catch (e: Throwable) {
                Log.w(TAG, "netEvent failed", e)
            }
        }
    }

    /** Registers the callbacks once and reports the screen's state now. */
    @Synchronized
    fun start(context: Context) {
        val app = context.applicationContext
        val interactive = app.getSystemService(PowerManager::class.java)?.isInteractive ?: true
        send(if (interactive) SCREEN_ON else SCREEN_OFF)
        if (started) return
        started = true
        try {
            app.getSystemService(ConnectivityManager::class.java).registerDefaultNetworkCallback(
                object : ConnectivityManager.NetworkCallback() {
                    private var last: Network? = null
                    override fun onAvailable(network: Network) {
                        if (network != last) {
                            last = network
                            send(NETWORK)
                        }
                    }
                })
        } catch (e: Exception) {
            Log.w(TAG, "network callback refused", e)
        }
        val screen = object : BroadcastReceiver() {
            override fun onReceive(c: Context, intent: Intent) {
                send(if (intent.action == Intent.ACTION_SCREEN_ON) SCREEN_ON else SCREEN_OFF)
            }
        }
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_ON)
            addAction(Intent.ACTION_SCREEN_OFF)
        }
        try {
            if (Build.VERSION.SDK_INT >= 33) app.registerReceiver(screen, filter, Context.RECEIVER_NOT_EXPORTED)
            else app.registerReceiver(screen, filter)
        } catch (e: Exception) {
            Log.w(TAG, "screen receiver refused", e)
        }
    }
}
