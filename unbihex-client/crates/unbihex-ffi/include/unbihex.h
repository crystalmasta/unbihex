/* Unbihex engine C ABI (SPEC §14.1). Used by the iOS Packet Tunnel extension. */
#ifndef UNBIHEX_H
#define UNBIHEX_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Android VpnService.protect-style callback; may be NULL. Return false to refuse the socket. */
typedef bool (*unbihex_protect_cb)(int32_t fd, void *ctx);

/* Error codes. */
#define UNBIHEX_ERR_CONFIG   (-1)
#define UNBIHEX_ERR_TUN      (-2)
#define UNBIHEX_ERR_NETWORK  (-3)
#define UNBIHEX_ERR_RUNNING  (-4)
#define UNBIHEX_ERR_HANDLE   (-5)
#define UNBIHEX_ERR_PANIC    (-99)

/* Starts the engine with a JSON config on the given TUN descriptor (-1: no TUN).
 * Returns a handle > 0 or a negative error code. Non-blocking: runs its own
 * tokio runtime with 2 worker threads. One instance at a time. */
int32_t unbihex_start(const char *config_json, int32_t tun_fd, unbihex_protect_cb protect, void *ctx);

/* Stops the engine (waits up to 5 s). 0 = ok. Not from an engine thread (such as the
   protect callback): that returns UNBIHEX_ERR_RUNNING. */
int32_t unbihex_stop(int32_t handle);

/* Traffic counters of the running engine; returns false when nothing runs. */
bool unbihex_stats(uint64_t *proxy_up, uint64_t *proxy_down, uint64_t *direct_up, uint64_t *direct_down);

/* Last error of this thread; valid until the next call on the same thread. Never NULL. */
const char *unbihex_last_error(void);

/* Static version string. */
const char *unbihex_version(void);

#ifdef __cplusplus
}
#endif

#endif /* UNBIHEX_H */
