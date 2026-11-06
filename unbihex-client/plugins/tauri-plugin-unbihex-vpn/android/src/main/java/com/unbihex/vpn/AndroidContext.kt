package com.unbihex.vpn

import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import java.net.Inet6Address

/** What both the plugin and the tile's headless start need from Android. */
object AndroidContext {
    // By dubr1k (github.com/dubr1k), PR #36.
    fun physicalDns(context: android.content.Context): List<String> {
        val cm = context.applicationContext.getSystemService(ConnectivityManager::class.java)
            ?: return emptyList()
        return try {
            // Prefer the active Wi-Fi/mobile network; never pick another VPN's
            // DNS, even while replacing an existing VPN connection.
            val networks = (listOfNotNull(cm.activeNetwork) + cm.allNetworks.toList()).distinct()
            val physical = networks.firstOrNull { network ->
                val caps = cm.getNetworkCapabilities(network)
                caps != null && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                    caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            }
            physical?.let { cm.getLinkProperties(it)?.dnsServers }
                ?.mapNotNull { address ->
                    val host = address.hostAddress?.substringBefore('%') ?: return@mapNotNull null
                    if (address is Inet6Address) {
                        val scope = if (address.scopeId > 0) "%${address.scopeId}" else ""
                        "[$host$scope]:53"
                    } else {
                        "$host:53"
                    }
                }
                ?.distinct() ?: emptyList()
        } catch (_: SecurityException) {
            // Preserve the existing system/public-DNS fallback on restricted devices.
            emptyList()
        }
    }
}
