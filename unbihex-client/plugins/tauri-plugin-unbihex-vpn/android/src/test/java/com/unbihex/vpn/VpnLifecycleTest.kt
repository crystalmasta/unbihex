package com.unbihex.vpn

import org.junit.Assert.*
import org.junit.Test

class VpnLifecycleTest {
    @Test fun cancelledReservationCannotEstablish() {
        val lifecycle = VpnLifecycle()
        val first = lifecycle.reserve()!!
        assertEquals(first, lifecycle.cancel(first))
        assertFalse(lifecycle.isConnecting(first))
        assertFalse(lifecycle.connected(first))
        assertEquals("disconnected", lifecycle.state)
    }

    @Test fun lateOldCompletionAndStopCannotAffectNewConnection() {
        val lifecycle = VpnLifecycle()
        val old = lifecycle.reserve()!!
        lifecycle.cancel(old)
        val current = lifecycle.reserve()!!
        assertTrue(current > old)
        assertFalse(lifecycle.connected(old))
        assertNull(lifecycle.cancel(old))
        assertTrue(lifecycle.connected(current))
        assertEquals("connected", lifecycle.state)
    }

    @Test fun repeatedStartIsRejectedUntilCancelled() {
        val lifecycle = VpnLifecycle()
        val first = lifecycle.reserve()!!
        assertNull(lifecycle.reserve())
        assertEquals("connecting", lifecycle.state)
        lifecycle.cancel(first)
        assertNotNull(lifecycle.reserve())
    }

    @Test fun connectedSessionRejectsAnotherStart() {
        val lifecycle = VpnLifecycle()
        val first = lifecycle.reserve()!!
        assertTrue(lifecycle.connected(first))
        assertNull(lifecycle.reserve())
        assertEquals("connected", lifecycle.state)
    }
    @Test fun oldIntentCannotConsumeNewUiCallback() {
        val callbacks = VpnStartCallbacks()
        var result: String? = null
        callbacks.register(2) { _, _, _, error -> result = error }
        assertNull(callbacks.take(1))
        callbacks.take(2)!!.invoke(null, null, 2, "cancelled")
        assertEquals("cancelled", result)
        assertNull(callbacks.take(2))
    }

    @Test fun stalePromotionPreservesCurrentConnectedPresentation() {
        val lifecycle = VpnLifecycle()
        val old = lifecycle.reserve()!!
        lifecycle.cancel(old)
        val current = lifecycle.reserve()!!
        assertTrue(lifecycle.connected(current))
        assertFalse(lifecycle.foregroundConnecting())
        lifecycle.cancel(current)
        assertTrue(lifecycle.foregroundConnecting())
    }

}
