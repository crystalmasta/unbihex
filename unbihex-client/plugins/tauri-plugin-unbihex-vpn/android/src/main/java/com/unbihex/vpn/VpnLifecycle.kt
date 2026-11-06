package com.unbihex.vpn

/** Caller serializes access together with VPN resource ownership. */
internal class VpnLifecycle {
    var generation: Long = 0
        private set
    var state: String = "disconnected"
        private set

    fun reserve(): Long? {
        if (state != "disconnected") return null
        generation++
        state = "connecting"
        return generation
    }

    fun isConnecting(value: Long) = generation == value && state == "connecting"

    /** A stale foreground-service intent still needs promotion, using current state. */
    fun foregroundConnecting(): Boolean =
        state != "connected"

    fun connected(value: Long): Boolean {
        if (!isConnecting(value)) return false
        state = "connected"
        return true
    }

    fun cancel(expected: Long? = null): Long? {
        if (state == "disconnected" || (expected != null && expected != generation)) return null
        val stopped = generation
        generation++
        state = "disconnected"
        return stopped
    }
}
