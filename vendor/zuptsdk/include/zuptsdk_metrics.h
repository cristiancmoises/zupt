/* zuptsdk observability — metrics & structured logging hooks
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef ZUPTSDK_METRICS_H
#define ZUPTSDK_METRICS_H

#include "zuptsdk.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t encrypt_pq_count;
    uint64_t decrypt_pq_count;
    uint64_t encrypt_password_count;
    uint64_t decrypt_password_count;
    uint64_t encrypt_field_count;
    uint64_t decrypt_field_count;
    uint64_t encrypt_failures;
    uint64_t decrypt_failures;
    uint64_t mac_failures;
    uint64_t commitment_failures;
    uint64_t fault_detections;
    uint64_t bytes_encrypted;
    uint64_t bytes_decrypted;
    uint64_t total_latency_ns;
} zuptsdk_metrics_t;

/** Get a snapshot of accumulated metrics (thread-safe, atomic read). */
void zuptsdk_metrics_snapshot(zuptsdk_metrics_t *out);

/** Reset all counters to zero. */
void zuptsdk_metrics_reset(void);

/** Render snapshot in Prometheus exposition format to a buffer.
 * Returns bytes written, or -1 if buf too small.
 * If out is NULL, returns required size. */
int zuptsdk_metrics_render_prometheus(char *buf, size_t buf_sz);

/** Structured log callback for ops. Called on each encrypt/decrypt with
 * outcome and timing. Set to NULL to disable.
 * @param op   "encrypt_pq" / "decrypt_pq" / "encrypt_password" / etc.
 * @param rc   error code (0 = OK)
 * @param bytes plaintext bytes processed
 * @param duration_ns elapsed time
 */
typedef void (*zuptsdk_op_log_t)(const char *op, int rc, size_t bytes,
                                  uint64_t duration_ns, void *userdata);

void zuptsdk_set_op_log(zuptsdk_op_log_t cb, void *userdata);

#ifdef __cplusplus
}
#endif

#endif
