/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2026 Cristian Cezar Moisés
 *
 * Minimal libvuptsdk declarations for the SDK adapter boundary test.
 */
#ifndef TESTS_SDK_ADAPTER_STUBS_ZUPTSDK_H
#define TESTS_SDK_ADAPTER_STUBS_ZUPTSDK_H

#include <stddef.h>
#include <stdint.h>

typedef struct zuptsdk_ctx zuptsdk_ctx_t;
typedef struct zuptsdk_keypair zuptsdk_keypair_t;

int zuptsdk_ctx_create(zuptsdk_ctx_t **ctx_out);
void zuptsdk_ctx_destroy(zuptsdk_ctx_t *ctx);
int zuptsdk_keypair_generate(zuptsdk_ctx_t *ctx,
                             zuptsdk_keypair_t **keypair_out);
int zuptsdk_keypair_save_private(const zuptsdk_keypair_t *keypair,
                                 const char *path);
int zuptsdk_keypair_save_public(const zuptsdk_keypair_t *keypair,
                                const char *path);
void zuptsdk_keypair_destroy(zuptsdk_keypair_t *keypair);

void zuptsdk_free(void *pointer);
void zuptsdk_secure_zero(void *buffer, size_t bytes);

#endif
