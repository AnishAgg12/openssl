/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Regression test: a DTLS handshake fragment with frag_len == 0 and
 * msg_len > 0 must not be delivered to the state machine as a complete
 * message. Such a fragment carries no payload bytes at all; the reassembly
 * path already treats frag_len == 0 as DTLS1_HM_FRAGMENT_RETRY, and the
 * in-order fast path in dtls_get_reassembled_message() must route it there
 * too instead of handing a zero-filled phantom message of the attacker's
 * claimed length to the handshake layer.
 *
 * The test drives a DTLS 1.2 server over memory BIOs with crafted epoch-0
 * records and counts handshake messages handed to the state machine on
 * the read side via SSL_set_msg_callback().
 */

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include "testutil.h"

static int deliveries;

/* write_p == 0 && content_type == SSL3_RT_HANDSHAKE means a handshake
 * message was handed to the state machine on read */
static void msg_cb(int write_p, int version, int content_type,
                   const void *buf, size_t len, SSL *ssl, void *arg)
{
    (void)version;
    (void)buf;
    (void)len;
    (void)ssl;
    (void)arg;
    if (!write_p && content_type == SSL3_RT_HANDSHAKE)
        deliveries++;
}

/*
 * Feed one crafted epoch-0 DTLS 1.2 handshake record to a fresh server and
 * report (deliveries, SSL_get_error(SSL_accept())). Returns 1 on success.
 */
static int run_case(const unsigned char *rec, size_t reclen,
                    int *pdeliveries, int *perr)
{
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    BIO *rbio = NULL, *wbio = NULL;
    int r, ret = 0;

    deliveries = 0;
    if (!TEST_ptr(ctx = SSL_CTX_new(DTLS_server_method()))
            || !TEST_true(SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION))
            || !TEST_true(SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION))
            || !TEST_ptr(ssl = SSL_new(ctx)))
        goto err;
    SSL_set_msg_callback(ssl, msg_cb);
    if (!TEST_ptr(rbio = BIO_new(BIO_s_mem()))
            || !TEST_ptr(wbio = BIO_new(BIO_s_mem())))
        goto err;
    SSL_set_bio(ssl, rbio, wbio);
    rbio = wbio = NULL;
    if (!TEST_int_eq(BIO_write(SSL_get_rbio(ssl), rec, (int)reclen),
                     (int)reclen))
        goto err;

    r = SSL_accept(ssl);
    *pdeliveries = deliveries;
    *perr = SSL_get_error(ssl, r);
    ret = 1;
 err:
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    BIO_free(rbio);
    BIO_free(wbio);
    return ret;
}

/* frag_len = 0, msg_len = 100: must be swallowed, server stays waiting */
static int test_zero_len_fragment(void)
{
    static const unsigned char rec[] = {
        0x16, 0xfe, 0xff,             /* handshake, DTLS 1.2 */
        0x00, 0x00,                   /* epoch 0 */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* sequence number 0 */
        0x00, 0x0c,                   /* length 12 = header only */
        0x01,                         /* msg_type ClientHello */
        0x00, 0x00, 0x64,             /* msg_len = 100 */
        0x00, 0x00,                   /* msg_seq = 0 */
        0x00, 0x00, 0x00,             /* frag_off = 0 */
        0x00, 0x00, 0x00              /* frag_len = 0 */
    };
    int d = -1, e = -1;

    if (!TEST_true(run_case(rec, sizeof(rec), &d, &e)))
        return 0;
    /* No phantom message may reach the state machine ... */
    if (!TEST_int_eq(d, 0))
        return 0;
    /* ... and the server must still be waiting for input */
    return TEST_int_eq(e, SSL_ERROR_WANT_READ);
}

/* Control: a genuine partial fragment is buffered, nothing is delivered */
static int test_partial_fragment(void)
{
    static const unsigned char rec[] = {
        0x16, 0xfe, 0xff,
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x11,                   /* length 17 = header + 5 */
        0x01,
        0x00, 0x00, 0x64,             /* msg_len = 100 */
        0x00, 0x00,                   /* msg_seq = 0 */
        0x00, 0x00, 0x00,             /* frag_off = 0 */
        0x00, 0x00, 0x05,             /* frag_len = 5 */
        0x01, 0x02, 0x03, 0x04, 0x05  /* 5 body bytes */
    };
    int d = -1, e = -1;

    if (!TEST_true(run_case(rec, sizeof(rec), &d, &e)))
        return 0;
    if (!TEST_int_eq(d, 0))
        return 0;
    return TEST_int_eq(e, SSL_ERROR_WANT_READ);
}

int setup_tests(void)
{
    ADD_TEST(test_zero_len_fragment);
    ADD_TEST(test_partial_fragment);
    return 1;
}
