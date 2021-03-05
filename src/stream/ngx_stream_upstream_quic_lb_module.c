
/*
 * Copyright (C) Martin Duke
 * Copyright (C) F5 Networks, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <quic_lb.h>


typedef struct {
    ngx_rbtree_t                          rbtree;
    ngx_rbtree_node_t                     sentinel;
} ngx_stream_upstream_quic_lb_server_tree_t;

/* One assignment of SID to peer, in the red-black tree */
typedef struct {
    ngx_rbtree_node_t                     rbnode;
    u_char                                sid[QUIC_LB_MAX_CID_LEN];
    ngx_stream_upstream_rr_peer_t        *peer;
} ngx_stream_upstream_quic_lb_server_node_t;

/* Global configuration */
typedef struct {
    void                                     *quic_lb_ctx[3];
    ngx_int_t                                 min_cidl[3];
    ngx_stream_upstream_quic_lb_server_tree_t tree[3];
    ngx_int_t                                 retry_service; /* Boolean */
    u_char                                    retry_key[16];
    u_char                                    retry_iv[8];
} ngx_stream_upstream_quic_lb_srv_conf_t;

/* Passed up on every connect event, provides access to all you need */
typedef struct {
    /* the round robin data must be first */
    ngx_stream_upstream_rr_peer_data_t      rrp;
    ngx_stream_upstream_quic_lb_srv_conf_t *conf;
    ngx_connection_t                       *connection; /* Clientside conn */
    ngx_event_get_peer_pt                   get_rr_peer;
} ngx_stream_upstream_quic_lb_peer_data_t;

extern ngx_int_t ngx_retry_service_process_initial(ngx_connection_t *c,
        u_char *key, u_char *iv);

static ngx_int_t ngx_stream_upstream_init_quic_lb_peer(ngx_stream_session_t *s,
    ngx_stream_upstream_srv_conf_t *us);
static ngx_int_t ngx_stream_upstream_init_quic_lb(ngx_conf_t *cf,
    ngx_stream_upstream_srv_conf_t *us);
static ngx_int_t ngx_stream_upstream_get_quic_lb_peer(ngx_peer_connection_t *pc,
    void *data);

static char *ngx_stream_upstream_quic_lb(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static void *ngx_stream_upstream_quic_lb_create_conf(ngx_conf_t *cf);

static ngx_command_t  ngx_stream_upstream_quic_lb_commands[] = {

    { ngx_string("quic-lb"),
      NGX_STREAM_UPS_CONF|NGX_CONF_TAKE2|NGX_CONF_TAKE3|NGX_CONF_TAKE4,
      ngx_stream_upstream_quic_lb,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_stream_module_t  ngx_stream_upstream_quic_lb_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_stream_upstream_quic_lb_create_conf,  /* create server configuration */
    NULL                                   /* merge server configuration */
};


ngx_module_t  ngx_stream_upstream_quic_lb_module = {
    NGX_MODULE_V1,
    &ngx_stream_upstream_quic_lb_module_ctx,  /* module context */
    ngx_stream_upstream_quic_lb_commands,     /* module directives */
    NGX_STREAM_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_stream_upstream_init_quic_lb(ngx_conf_t *cf,
    ngx_stream_upstream_srv_conf_t *us)
{
    ngx_stream_upstream_quic_lb_srv_conf_t    *qlbcf;
    ngx_stream_upstream_rr_peer_t             *peer;
    ngx_stream_upstream_rr_peers_t            *peers;
    ngx_stream_upstream_quic_lb_server_node_t *server_node;
    ngx_rbtree_node_t                         *node;
    size_t                                     size;
    ngx_uint_t                                 i;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, cf->log, 0, "init quic-lb");

    if (ngx_stream_upstream_init_round_robin(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }

    us->peer.init = ngx_stream_upstream_init_quic_lb_peer;

    qlbcf = ngx_stream_conf_upstream_srv_conf(us,
            ngx_stream_upstream_quic_lb_module);
    peers = us->peer.data;

    size = sizeof(ngx_stream_upstream_quic_lb_server_node_t);

    for (peer = peers->peer; peer; peer = peer->next) {
        for (i = 0; i < 3; i++) {
            if (qlbcf->quic_lb_ctx[i] == NULL) {
                continue;
            }
            if (peer->sidl[i] == 0) {
                /* Not configured */
                continue;
            }
            server_node = cf->pool ? ngx_palloc(cf->pool, size) :
                ngx_alloc(size, ngx_cycle->log);
            if (server_node == NULL) {
                return NGX_ERROR;
            }

            node = &server_node->rbnode;
            node->key = 0; /* Use the SID instead */
            memcpy(server_node->sid, peer->sid[i], peer->sidl[i]);
            server_node->peer = peer;
            ngx_rbtree_insert(&(qlbcf->tree[i].rbtree), node);

        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_upstream_init_quic_lb_peer(ngx_stream_session_t *s,
    ngx_stream_upstream_srv_conf_t *us)
{
    ngx_stream_upstream_quic_lb_srv_conf_t   *qlbcf;
    ngx_stream_upstream_quic_lb_peer_data_t  *qlbp;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
            "init quic-lb peer");

    qlbcf = ngx_stream_conf_upstream_srv_conf(us,
        ngx_stream_upstream_quic_lb_module);

    qlbp = ngx_palloc(s->connection->pool,
                    sizeof(ngx_stream_upstream_quic_lb_peer_data_t));
    if (qlbp == NULL) {
        return NGX_ERROR;
    }

    s->upstream->peer.data = &qlbp->rrp;

    if (ngx_stream_upstream_init_round_robin_peer(s, us) != NGX_OK) {
        return NGX_ERROR;
    }

    s->upstream->peer.get = ngx_stream_upstream_get_quic_lb_peer;

    qlbp->conf = qlbcf;
    qlbp->connection = s->connection;
    qlbp->get_rr_peer = ngx_stream_upstream_get_round_robin_peer;

    ngx_stream_upstream_rr_peers_unlock(qlbp->rrp.peers);

    return NGX_OK;
}


static ngx_int_t
ngx_stream_upstream_get_quic_lb_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_stream_upstream_quic_lb_peer_data_t *qlbp = data;

    time_t                                     now;
    u_char                                    *cid;
    u_char                                     sid[QUIC_LB_MAX_CID_LEN];
    ngx_uint_t                                 sidl;
    ngx_uint_t                                 long_hdr;
    ngx_uint_t                                 config_rot;
    ngx_stream_upstream_rr_peer_t             *peer;
    /* Tree traversal variables */
    ngx_stream_upstream_quic_lb_server_node_t *server;
    ngx_int_t                                  compare;
    ngx_rbtree_node_t                         *node, *sentinel;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                   "get quic-lb peer, try: %ui", pc->tries);
    if (qlbp->conf->retry_service && (ngx_retry_service_process_initial(
            qlbp->connection, qlbp->conf->retry_key, qlbp->conf->retry_iv)
            == NGX_DECLINED)) {
        /* No Retry token, or an invalid one. We may have sent a Retry, but
           abort the stream. */
        return NGX_ERROR;
    }

    ngx_stream_upstream_rr_peers_rlock(qlbp->rrp.peers);
    now = ngx_time();
    pc->connection = NULL;

    cid = qlbp->connection->buffer->pos;
    /* Find the CID */
    long_hdr = *cid & 0x80;
    if ((qlbp->connection->buffer->last - cid) < (long_hdr ? 7 : 2)) {
        goto round_robin; /* Can't even find a first CID byte */
    }
    cid++;
    if (long_hdr) {
        cid += 5;
    }
    /* cid now points to the connection ID */
    config_rot = (*cid & 0xc0) >> 6;
    if ((config_rot == 3) || ((qlbp->connection->buffer->last - cid) <
            qlbp->conf->min_cidl[config_rot]) ||
            (qlbp->conf->quic_lb_ctx[config_rot] == NULL)) {
        goto round_robin;
    }
    sidl = quic_lb_decrypt_cid(qlbp->conf->quic_lb_ctx[config_rot], cid, sid,
            NULL);
    if (sidl == 0) {
        goto round_robin;
    }


    /* Traverse the red-black tree to find the SID */
    node = qlbp->conf->tree[config_rot].rbtree.root;
    sentinel = &qlbp->conf->tree[config_rot].sentinel;
    while (node != sentinel) {
        server = (ngx_stream_upstream_quic_lb_server_node_t *)node;
        compare = ngx_memcmp(sid, server->sid, sidl);
        if (compare == 0) {
            peer = server->peer;
            break;
        }
        node = (compare < 0) ? node->left : node->right;
    }
    if (node == sentinel) {
        /* If a short header, CID should be compliant. Drop instead */
        if (!long_hdr) {
            return NGX_ERROR;
        }
        goto round_robin; /* Invalid SID */
    }

    ngx_stream_upstream_rr_peer_lock(qlbp->rrp.peers, peer);

    if (peer->down) {
        ngx_stream_upstream_rr_peer_unlock(qlbp->rrp.peers, peer);
        goto round_robin;
    }

    if (peer->max_fails
        && peer->fails >= peer->max_fails
        && now - peer->checked <= peer->fail_timeout)
    {
        ngx_stream_upstream_rr_peer_unlock(qlbp->rrp.peers, peer);
        goto round_robin;
    }

    if (peer->max_conns && peer->conns >= peer->max_conns) {
        ngx_stream_upstream_rr_peer_unlock(qlbp->rrp.peers, peer);
        goto round_robin;
    }

    qlbp->rrp.current = peer;

    pc->sockaddr = peer->sockaddr;
    pc->socklen = peer->socklen;
    pc->name = &peer->name;

    peer->conns++;

    if (now - peer->checked > peer->fail_timeout) {
        peer->checked = now;
    }

    ngx_stream_upstream_rr_peer_unlock(qlbp->rrp.peers, peer);
    ngx_stream_upstream_rr_peers_unlock(qlbp->rrp.peers);

    return NGX_OK;

round_robin:
    return ngx_stream_upstream_get_round_robin_peer(pc, &(qlbp->rrp));
}


static void *
ngx_stream_upstream_quic_lb_create_conf(ngx_conf_t *cf)
{
    ngx_stream_upstream_quic_lb_srv_conf_t  *conf;

    conf = ngx_palloc(cf->pool, sizeof(ngx_stream_upstream_quic_lb_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    ngx_memzero(conf, sizeof(ngx_stream_upstream_quic_lb_srv_conf_t));

    return conf;
}


void
ngx_rbtree_insert_sid(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
        ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t                          **p;
    ngx_stream_upstream_quic_lb_server_node_t   *snode;
    u_char                                      *sid;

    sid = ((ngx_stream_upstream_quic_lb_server_node_t *)node)->sid;

    for ( ;; ) {
        
        snode = (ngx_stream_upstream_quic_lb_server_node_t *)temp;
        p = (ngx_memcmp(sid, snode->sid, sizeof(snode->sid)) < 0) ? &temp->left :
                &temp->right;
        
        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


static char *
ngx_stream_upstream_quic_lb(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_upstream_quic_lb_srv_conf_t  *qlbcf = conf;

    ngx_str_t                           *value;
    ngx_stream_upstream_srv_conf_t      *uscf;
    enum quic_lb_alg                     alg;
    ngx_int_t                            sidl = -1, nonce_len = -1, byte = -1;
    ngx_int_t                            iv_byte = -1, cr = -1;
    ngx_int_t                            retry_service = 0;
    ngx_uint_t                           i, j;
    u_char                               key[16], iv[8];

    value = cf->args->elts;

    uscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_upstream_module);

    if ((uscf->peer.init_upstream) &&
            (uscf->peer.init_upstream != ngx_stream_upstream_init_quic_lb)) {
        /* Not QUIC-LB! */
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "load balancing method redefined");
    }

    uscf->flags = NGX_STREAM_UPSTREAM_CREATE
                  |NGX_STREAM_UPSTREAM_WEIGHT
                  |NGX_STREAM_UPSTREAM_MAX_CONNS
                  |NGX_STREAM_UPSTREAM_MAX_FAILS
                  |NGX_STREAM_UPSTREAM_FAIL_TIMEOUT
                  |NGX_STREAM_UPSTREAM_DOWN;

    /* Number of parameters defines the algorithm used */
    switch(cf->args->nelts) {
    case 5:
        alg = QUIC_LB_SCID;
        break;
    case 4:
        alg = QUIC_LB_BCID;
        break;
    case 3:
        alg = QUIC_LB_PCID;
        break;
    default:
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "Incorrect number of parameters");
        return NGX_CONF_ERROR;
    }

    /* Allow parameters in any order */
    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "retry-service", 13) == 0) {
            /* It's a retry service, ignore the rest */
            retry_service = 1;
            continue;
        }

        if (ngx_strncmp(value[i].data, "iv=", 3) == 0) {
            for (j = 0; j < 8; j++) {
                iv_byte = ngx_hextoi(&value[i].data[3 + j*2], 2);
                if (iv_byte == NGX_ERROR) {
                    printf("byte = %ld\n", byte);
                    goto invalid;
                }
                iv[j] = (u_char)iv_byte;
            }
            continue;
        } 

        if (ngx_strncmp(value[i].data, "cr=", 3) == 0) {
            cr = ngx_atoi(&value[i].data[3], value[i].len - 3);
            if ((cr == NGX_ERROR) || (cr < 0)  || (cr > 2)) {
                goto invalid;
            }
            continue;
        }

        if (ngx_strncmp(value[i].data, "sidl=", 5) == 0) {
            sidl = ngx_atoi(&value[i].data[5], value[i].len - 5);
            if ((sidl == NGX_ERROR) || (sidl < 0) ||
                    (sidl >= QUIC_LB_MAX_CID_LEN)) {
                goto invalid;
            }
            if ((alg == QUIC_LB_BCID) && (sidl > 16)) {
                goto invalid;
            }
            continue;
        }

        if (ngx_strncmp(value[i].data, "key=", 4) == 0) {
            if (alg == QUIC_LB_PCID) {
                continue;
            }
            if (value[i].len < 36) {
                goto invalid;
            }
            for (j = 0; j < 16; j++) {
                byte = ngx_hextoi(&value[i].data[4 + j*2], 2);
                if (byte == NGX_ERROR) {
                    printf("byte = %ld\n", byte);
                    goto invalid;
                }
                key[j] = (u_char)byte;
            }
            continue;
        }

        if (ngx_strncmp(value[i].data, "nonce_len=", 10) == 0) {
            if (alg != QUIC_LB_SCID) {
                continue;
            }
            nonce_len = ngx_hextoi(&value[i].data[10], value[i].len - 10);
            if ((nonce_len == NGX_ERROR) || (nonce_len < 8) ||
                    (nonce_len > 16)) {
                goto invalid;
            }
            continue;
        }

    }

    if (retry_service) {
        /* Do Retry Service stuff, skip the rest */
        if ((byte == -1) || (iv_byte == -1)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "Missing key or iv for retry token");
            return NGX_CONF_ERROR;
        }
        qlbcf->retry_service = 1;
        memcpy(qlbcf->retry_key, key, 16);
        memcpy(qlbcf->retry_iv, iv, 8);
        return NGX_CONF_OK;
    }

    /* Make sure we got the right parameters */
    if (cr == -1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "Missing config rotation code (cr)");
        return NGX_CONF_ERROR;
    }
    if (sidl == -1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "Missing server id length (sidl)");
        return NGX_CONF_ERROR;
    }
    if ((alg > QUIC_LB_PCID) && (byte == -1)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "Missing key");
        return NGX_CONF_ERROR;
    }
    if (alg == QUIC_LB_SCID) {
        if (nonce_len == -1) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "Missing nonce_len");
            return NGX_CONF_ERROR;
        }
        if ((nonce_len + sidl) >= QUIC_LB_MAX_CID_LEN) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "nonce_len + sidl is too long");
            return NGX_CONF_ERROR;
        }
    }

    if (qlbcf->quic_lb_ctx[cr] != NULL) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "Same value for cr appears twice");
        quic_lb_lb_ctx_free(qlbcf->quic_lb_ctx[cr]);
        qlbcf->quic_lb_ctx[cr] = NULL;
    }
    /* Set up tree that stores servers */
    ngx_rbtree_init(&qlbcf->tree[cr].rbtree, &qlbcf->tree[cr].sentinel,
            &ngx_rbtree_insert_sid);

    qlbcf->quic_lb_ctx[cr] = quic_lb_lb_ctx_init(alg, FALSE, (ngx_uint_t)sidl,
            key, (ngx_uint_t)nonce_len);
    if (qlbcf->quic_lb_ctx[cr] == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "QUIC-LB config invalid");
        return NGX_CONF_ERROR;
    }

    switch(alg) {
    case QUIC_LB_PCID:
        qlbcf->min_cidl[cr] = 1 + sidl;
        break;
    case QUIC_LB_BCID:
        qlbcf->min_cidl[cr] = 17;
        break;
    case QUIC_LB_SCID:
        qlbcf->min_cidl[cr] = 1 + sidl + nonce_len;
        break;
    }

    uscf->peer.init_upstream = ngx_stream_upstream_init_quic_lb;

    return NGX_CONF_OK;

invalid:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid parameter \"%V\"", &value[i]);
    return NGX_CONF_ERROR;
}
