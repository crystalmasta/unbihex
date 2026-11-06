package com.unbihex.vpn

/** Access is serialized by the service's lifecycle lock. */
internal class VpnStartCallbacks {
    private var pending: Pair<Long, (Int?, Int?, Long, String?) -> Unit>? = null

    fun register(value: Long, callback: (Int?, Int?, Long, String?) -> Unit) {
        pending = value to callback
    }

    fun take(value: Long): ((Int?, Int?, Long, String?) -> Unit)? {
        val item = pending
        if (item?.first != value) return null
        pending = null
        return item.second
    }
}
