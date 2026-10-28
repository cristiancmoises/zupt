/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2026 Cristian Cezar Moisés
 *
 * Minimal libvuptsdk easy-API declarations for the SDK adapter boundary test.
 */
#ifndef TESTS_SDK_ADAPTER_STUBS_ZUPTSDK_EASY_H
#define TESTS_SDK_ADAPTER_STUBS_ZUPTSDK_EASY_H

#include "zuptsdk.h"

int zuptsdk_easy_encrypt(const char *recipient_pubkey_path,
                         const uint8_t *plaintext, size_t plaintext_size,
                         uint8_t **blob_out, size_t *blob_size);
int zuptsdk_easy_decrypt(const char *recipient_privkey_path,
                         const uint8_t *blob, size_t blob_size,
                         uint8_t **plaintext_out, size_t *plaintext_size);
int zuptsdk_easy_derive_key(const char *password, const uint8_t salt[16],
                            uint8_t key_out[32]);
int zuptsdk_easy_random_salt(uint8_t salt_out[16]);

#endif
