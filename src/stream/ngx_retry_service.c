
/*
 * Copyright (C) Martin Duke
 * Copyright (C) F5 Networks, Inc.
 */

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <ngx_core.h>
#include <openssl/evp.h>


#define NGX_QUIC_LB_INITIAL 0x0
#define NGX_QUIC_LB_0RTT    0x1
#define NGX_QUIC_LB_RSCIL     8 /* The length of SCIDs in Retries */
#define NGX_QUIC_LB_TOKEN_TIMEOUT 2 /* In seconds */


/* "after" points to the end of the varint */
static inline uint64_t
ngx_parse_varint(u_char *field, u_char **after)
{
    uint64_t retval = 0;
    u_char   bitshift = 0;
    u_char   length = (1 << ((*field & 0xc0) >> 6));

    *after = field + length;
    while (length > 1) {
        retval += ((*(field + length - 1)) << bitshift);
        length--;
        bitshift += 8;
    }
    retval += ((*field & 0x3f) << bitshift);
    return retval;
}


static ngx_int_t
ngx_retry_service_encrypt_decrypt(int encrypt, u_char *input, int input_len,
        u_char *output, int *output_len, u_char *aad, int aad_len, u_char *key,
        u_char *iv, int iv_len, u_char *tag, ngx_log_t *log)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int (*init_fn)(EVP_CIPHER_CTX *, const EVP_CIPHER *, ENGINE *,
            const unsigned char *, const unsigned char *) =
            (encrypt ? &EVP_EncryptInit_ex : & EVP_DecryptInit_ex);
    int (*update_fn)(EVP_CIPHER_CTX *, unsigned char *, int *,
            const unsigned char *, int) =
            (encrypt ? &EVP_EncryptUpdate : &EVP_DecryptUpdate);


    if (!(ctx = EVP_CIPHER_CTX_new())) {
        /* If crypto library is hosed, we can't tell if it's valid. Can't
           send 2 RETRYs, so just drop it */
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, log, 0,
                "evp_new failed");
        return NGX_DECLINED;
    }
    if (!init_fn(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, log, 0,
                "evp_init failed");
        goto fail;
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL)) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, log, 0,
                "evp_ctrl failed");
        goto fail;
    }
    if (!(*init_fn)(ctx, NULL, NULL, key, iv)) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, log, 0,
                "evp_init failed");
        goto fail;
    }
    if (!(*update_fn)(ctx, NULL, &len, aad, aad_len)) {
        /* Load all plaintext fields as AAD */
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, log, 0,
                "evp_update (aad) failed");
        goto fail;
    }
    if (!(*update_fn)(ctx, output, output_len, input, input_len)) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, log, 0,
                "evp_update (input) failed");
        goto fail;
    }
    if (encrypt) {
        if (!EVP_EncryptFinal_ex(ctx, output + *output_len, &len)) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, log, 0,
                "evp_encrypt_final failed");
            goto fail;
        }
        *output_len += len;
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) {
            ngx_log_debug0(NGX_LOG_DEBUG_STREAM, log, 0,
                    "evp get_tag failed");
            goto fail;
        }
    } else {
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)) {
            ngx_log_debug0(NGX_LOG_DEBUG_STREAM, log, 0,
                    "evp set_tag failed");
            goto fail;
        }
        if (!EVP_DecryptFinal_ex(ctx, output + *output_len, &len)) {
            ngx_log_debug0(NGX_LOG_DEBUG_STREAM, log, 0,
                    "evp_decrypt_final failed");
            goto fail;
        }
        *output_len += len;
    }
    /* Valid token! */
    EVP_CIPHER_CTX_free(ctx);
    return NGX_OK;

fail:
    EVP_CIPHER_CTX_free(ctx);
    return NGX_DECLINED; /* Drop the packet */
}


/* Returns length of token. If key_seq == NULL, it's non-shared-state. */
static ngx_uint_t
ngx_retry_service_build_token(ngx_connection_t *c, u_char *token,
        u_char odcil, u_char rscil, u_char *odcid, u_char *rscid,
        u_char *key, u_char *iv, u_char *key_seq)
{
    time_t  expiration;
    int     len, i;
    u_char  full_iv[16], tag[16], scratch[255];;
    u_char *pt, *token_start, *write = scratch;

    /* Token pseudoheader, not on the wire */
    switch(c->sockaddr->sa_family) {
    case AF_INET:
        memcpy(write, &((struct sockaddr_in *)(c->sockaddr))->sin_addr, 4);
        write += 4;
        memset(write, 0, 12);
        write += 12;
        break;
    case AF_INET6:
        memcpy(write, &((struct sockaddr_in6 *)(c->sockaddr))->sin6_addr, 16);
        write += 16;
        break;
    default:
        return 0; /* No address to verify! */
    }
    token_start = write;
    if (key_seq != NULL) {
        for (len = 0; len < 12; len += sizeof(int)) { /* Unique token number */
            *(int *)(write + len) = rand();
        }
        write += 12;
        *write = *key_seq;
        write++;
        pt = write;
        *write = odcil;
    } else {
        *write = odcil & 0x7f;
    }
    write++;
    *write = rscil;
    write++;
    if (key_seq != NULL) {
        if (c->sockaddr->sa_family == AF_INET) {
            memcpy(write, &((struct sockaddr_in *)(c->sockaddr))->sin_port, 2);
        } else {
            memcpy(write, &((struct sockaddr_in6 *)(c->sockaddr))->sin6_port,
                    2);
        }
        write += 2;
    }
    memcpy(write, odcid, odcil);
    write += odcil;
    memcpy(write, rscid, rscil);
    write += rscil;
    if (key_seq == NULL) {
        for (len = 0; len < 12; len += sizeof(int)) { /* Unique token number */
            *(int *)(write + len) = rand();
        }
        write += 12;
        pt = write;
    }
    expiration = ngx_time() + NGX_QUIC_LB_TOKEN_TIMEOUT;
    memcpy(write, &expiration, sizeof(expiration));
    write += sizeof(expiration);
    /* Encrypt Token */
    memcpy(full_iv, iv, 16);
    for (i = 0; i < 12; i++) { /* XOR with the nonce */
        if (key_seq != NULL) {
            full_iv[i+4] ^= *(token_start + i);
        } else {
            full_iv[i+4] ^= *(pt - 12 + i);
        }
    }
    if (ngx_retry_service_encrypt_decrypt(1, pt, write - pt, pt, &len, scratch,
             pt - scratch, key, full_iv, 16, tag, c->log) == NGX_DECLINED) {
        return 0;
    }
    write = pt + len;
    memcpy(write, tag, 16);
    write += 16;
    memcpy(token, token_start, write - token_start);
    return (write - token_start);
}


/* Returns NGX_OK if valid, NGX_DECLINED if should trigger retry, NGX_ABORT if
   silently dropped */
static ngx_int_t
ngx_retry_service_validate_token(ngx_connection_t *c, u_char *token,
    uint64_t token_len, u_char *key, u_char *iv, u_char *key_seq, u_char *dcid)
{
    int     len, i;
    u_char  pt[255], full_iv[16], scratch[255];
    u_char  odcil, *token_end, *read = scratch;

    switch(c->sockaddr->sa_family) {
    case AF_INET:
        memcpy(read, &((struct sockaddr_in *)(c->sockaddr))->sin_addr, 4);
        read += 4;
        memset(read, 0, 12);
        read += 12;
        break;
    case AF_INET6:
        memcpy(read, &((struct sockaddr_in6 *)(c->sockaddr))->sin6_addr, 16);
        read += 16;
        break;
    default:
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "mangled addr family");
        return NGX_ABORT; /* No address to verify! */
    }
    token_end = read + token_len;
    memcpy(read, token, token_len);
    memcpy(full_iv, iv, 16);
    if (key_seq != NULL) {
        for (i = 0; i < 12; i++) {
            full_iv[i+4] ^= *(read + i);
        }
        read += 12;
        if (*read != *key_seq) {
            return NGX_ABORT;
        }
        read++;
        /* Decrypt */
        if (ngx_retry_service_encrypt_decrypt(0, read, token_end - read - 16,
                 pt, &len, scratch, read - scratch, key, full_iv, 16,
                 token_end - 16, c->log) == NGX_DECLINED) {
            ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "decrypt fail");
            return NGX_ABORT;
        }
        read = pt;
        odcil = *read;
        read++;
        if (odcil == 0) {
            if (*read == 0) { /* NEW_TOKEN token, no port */
                read++;
                goto no_port;
            } else {
                return NGX_ABORT;
            }
        }
    } else {
        if (*read & 0x80) {
            /* It's a NEW_TOKEN token */
            ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "NEW_TOKEN token");
            return NGX_DECLINED;
        }
        odcil = (*read & 0x7f);
        read++;
    }
    if (odcil < 8) {
        return NGX_ABORT;
    }
    if (*read != NGX_QUIC_LB_RSCIL) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "Not my CID len");
        return NGX_ABORT;
    }
    read++;
    if (key_seq != NULL) {
        if (((c->sockaddr->sa_family == AF_INET) && memcmp(read,
                &((struct sockaddr_in *)(c->sockaddr))->sin_port, 2) != 0) ||
            ((c->sockaddr->sa_family == AF_INET6) && memcmp(read,
                &((struct sockaddr_in6 *)(c->sockaddr))->sin6_port, 2) != 0)) {
            return NGX_ABORT; /* Port doesn't match */
        }
        read += 2;
    }
    read += odcil;
    if (memcmp(dcid, read, NGX_QUIC_LB_RSCIL) != 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "no CID match");
        return NGX_ABORT;
    }
    read += NGX_QUIC_LB_RSCIL;
no_port:
    if (key_seq == NULL) {
        /* Decrypt token to authenticate & check timestamp */
        for (i = 0; i < 12; i++) {
            full_iv[i+4] ^= *(read + i);
        }
        read += 12;
        if (ngx_retry_service_encrypt_decrypt(0, read, token_end - read - 16,
                 pt, &len, scratch, read - scratch, key, full_iv, 16,
                 token_end - 16, c->log) == NGX_DECLINED) {
            ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "decrypt fail");
            return NGX_ABORT;
        }
        read = pt;
    }
    /* Verify plaintext */
    if (ngx_time() > *(time_t *)read + ((key_seq != NULL) ? 2 : 0)) {
        /* If shared-state, allow 2 seconds of drift */
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "token expire");
        return NGX_ABORT; /* Token expired */
    }
    return NGX_OK;
}


/*
 * Process an Initial Packet. Arguments:
 * - pkt: points to the first byte of the packet
 * Returns NGX_DECLINED to drop the packet, NGX_OK to admit it.
 */
ngx_int_t
ngx_retry_service_process_initial(ngx_connection_t *c, u_char *key, u_char *iv,
        u_char *key_seq)
{
    const u_char retry_integrity_key[] = {
        0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
        0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
    };
    const u_char retry_integrity_nonce[] = {
        0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2,
        0x23, 0x98, 0x25, 0xbb,
    };

    u_char        dcid[20], scid[20], token[255], retry[255];
    u_char        rscid[NGX_QUIC_LB_RSCIL];
    u_char        dcidl, scidl, pkt_type;
    u_char       *read = c->buffer->pos;
    uint64_t      token_len;
    int           pos, len, i;
    ssize_t       n;


    /* XXX We should check datagram length, but this is weirdly hard to find */
    if (c->buffer->end - read < 31) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "pkt too short");
        return NGX_DECLINED;
    }
    if ((*read & 0x80) == 0) {
        /*
           XXX Admit all short headers arriving first on the four-tuple. This
           preserves address migration while putting some more stress on the
           servers we're protecting. An improvement would be to use QUIC-LB to
           admit only CIDs with a valid SID.
        */
        return NGX_OK;
#if 0
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                "retry dropping short header");
        return NGX_DECLINED; /* Drop short headers */
#endif
    }
    pkt_type = (*read & 0x30) >> 4; 
    if (pkt_type != NGX_QUIC_LB_INITIAL) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                "retry dropping Handshake");
        return NGX_DECLINED; /* Initial Only */
    }
    read++;
    if (ntohl(*(uint32_t *)read) != 1) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                "retry admitting unknown version");
        return NGX_OK; /* Not version 1, admit */
    }
    read += 4;
    dcidl = *read;
    read++;
    memcpy(dcid, read, dcidl);
    read += dcidl;
    scidl = *read;
    read++;
    if (c->buffer->end - read < scidl) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                "pkt too short for scid");
        return NGX_DECLINED;
    }
    memcpy(scid, read, scidl);
    read += scidl;
    token_len = ngx_parse_varint(read, &read);
    if (token_len == 0) {
        goto send_retry;
    }
    if ((uint64_t)(c->buffer->end - read) < token_len) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                "pkt too short for token");
        return NGX_DECLINED;
    }
    switch (ngx_retry_service_validate_token(c, read, token_len, key, iv,
            key_seq, dcid)) {
    case NGX_DECLINED:
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                "no retry token, sending retry");
        goto send_retry;
    case NGX_ABORT:
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                "retry token invalid, dropping");
        return NGX_DECLINED;
    default:
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                "retry token valid");
        return NGX_OK;
    }

send_retry:
    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
            "sending retry");
    retry[0] = dcidl; /* Pseudoheader field */
    memcpy(&retry[1], dcid, dcidl); /* Pseudoheader field */
    pos = 1 + dcidl;
    /* Packet starts here */
    retry[pos++] = 0xf0 | (rand() & 0x0f);
    retry[pos++] = 0;
    retry[pos++] = 0;
    retry[pos++] = 0;
    retry[pos++] = 0x1;
    retry[pos++] = scidl;
    memcpy(&retry[pos], scid, scidl);
    pos += scidl;
    retry[pos] = NGX_QUIC_LB_RSCIL;
    pos++;
    for (i = 0; i < NGX_QUIC_LB_RSCIL; i++) {
        rscid[i] = rand() & 0xff;
    }
    memcpy(&retry[pos], rscid, NGX_QUIC_LB_RSCIL);
    pos += NGX_QUIC_LB_RSCIL;
    token_len = (uint64_t)ngx_retry_service_build_token(c, &retry[pos], dcidl,
            NGX_QUIC_LB_RSCIL, dcid, rscid, key, iv, key_seq);
    if (token_len == 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                "couldn't build token");
        return NGX_DECLINED;
    }
    pos += token_len;
    /* Add the integrity tag */
    if (ngx_retry_service_encrypt_decrypt(1, token, 0, token, &len, retry, pos,
            (u_char *)retry_integrity_key, (u_char *)retry_integrity_nonce, 12,
            &retry[pos], c->log) == NGX_DECLINED) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                "couldn't add integrity tag");
        return NGX_DECLINED;
    }
    pos += 16;
    /* Send the packet, drop the inbound */
    n = c->send(c, &retry[1 + dcidl], pos - 1 - dcidl);
    if (n != pos - 1 - dcidl) {
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                "failed to send %d", n);
    }
    return NGX_DECLINED;
}
