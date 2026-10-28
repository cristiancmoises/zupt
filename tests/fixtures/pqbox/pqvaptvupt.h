/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2026 Cristian Cezar Moisés
 */
#ifndef TEST_PQVAPTVUPT_H
#define TEST_PQVAPTVUPT_H

#include <stddef.h>
#include <stdint.h>

#define PQVV_PUBLICKEYBYTES 1216
#define PQVV_SECRETKEYBYTES 2432
#define PQVV_OVERHEAD 1184

enum {
    PQVV_OK = 0,
    PQVV_ERR_CORRUPT = -4
};

int pqvv_keygen(uint8_t pk[PQVV_PUBLICKEYBYTES],
                uint8_t sk[PQVV_SECRETKEYBYTES]);
int pqvv_seal(const uint8_t pk[PQVV_PUBLICKEYBYTES],
              const uint8_t *pt, size_t pt_len,
              uint8_t **out, size_t *out_len);
int pqvv_open(const uint8_t sk[PQVV_SECRETKEYBYTES],
              const uint8_t *ct, size_t ct_len,
              uint8_t **out, size_t *out_len);

#endif
