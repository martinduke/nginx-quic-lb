
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
    time_t                                last_time; /* Dynamic only (sec) */
} ngx_stream_upstream_quic_lb_server_node_t;

/* Global configuration */
typedef struct {
    void                                     *quic_lb_ctx[3];
    ngx_uint_t                                min_cidl[3];
    ngx_stream_upstream_quic_lb_server_tree_t tree[3];
    ngx_uint_t                                sidl[3];
    ngx_uint_t                                lb_timeout[3];
    ngx_pool_t                               *config_pool;
    ngx_int_t                                 retry_service; /* 1=NSS, 2=SS */
    u_char                                    retry_key[16];
    u_char                                    retry_iv[16];
    u_char                                    retry_key_seq; /* Shared state */
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
        u_char *key, u_char *iv, u_char *key_seq);

ngx_int_t ngx_stream_upstream_init_quic_lb_peer(ngx_stream_session_t *s,
    ngx_stream_upstream_srv_conf_t *us);
ngx_int_t ngx_stream_upstream_init_quic_lb(ngx_conf_t *cf,
    ngx_stream_upstream_srv_conf_t *us);
ngx_int_t ngx_stream_upstream_get_quic_lb_peer(ngx_peer_connection_t *pc,
    void *data);
void ngx_stream_upstream_notify_quic_lb_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t type);

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


static ngx_stream_upstream_quic_lb_server_node_t *
ngx_stream_upstream_add_node_to_tree(ngx_pool_t *pool,
        ngx_stream_upstream_rr_peer_t *peer,
        ngx_stream_upstream_quic_lb_server_tree_t *tree,
        u_char *sid, ngx_uint_t sidl, time_t timenow)
{
    ngx_stream_upstream_quic_lb_server_node_t *server_node;
    ngx_rbtree_node_t                         *node;
    size_t                                     size;

    size = sizeof(ngx_stream_upstream_quic_lb_server_node_t);
    server_node = pool ? ngx_palloc(pool, size) :
        ngx_alloc(size, ngx_cycle->log);
    if (server_node == NULL) {
        return server_node;
    }

    node = &server_node->rbnode;
    node->key = 0; /* Use the SID instead */
    memcpy(server_node->sid, sid, sidl);
    server_node->peer = peer;
    server_node->last_time = timenow;
    ngx_rbtree_insert(&tree->rbtree, node);
    return server_node;
}


ngx_int_t
ngx_stream_upstream_init_quic_lb(ngx_conf_t *cf,
    ngx_stream_upstream_srv_conf_t *us)
{
    ngx_stream_upstream_quic_lb_srv_conf_t    *qlbcf;
    ngx_stream_upstream_quic_lb_server_node_t *snode;
    ngx_stream_upstream_rr_peer_t             *peer;
    ngx_stream_upstream_rr_peers_t            *peers;
    ngx_uint_t                                 i;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, cf->log, 0, "init quic-lb");

    if (ngx_stream_upstream_init_round_robin(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }

    us->peer.init = ngx_stream_upstream_init_quic_lb_peer;

    qlbcf = ngx_stream_conf_upstream_srv_conf(us,
            ngx_stream_upstream_quic_lb_module);
    peers = us->peer.data;
    qlbcf->config_pool = cf->pool;

    for (i = 0; i < 3; i++) {
        if (qlbcf->quic_lb_ctx[i] == NULL) {
            continue;
        }
        if (qlbcf->lb_timeout[i] > 0) {
            /* Dynamically allocated! */
            continue;
        }
        for (peer = peers->peer; peer; peer = peer->next) {
            if (peer->sidl[i] > 0) {
                /* Configured */
                snode = ngx_stream_upstream_add_node_to_tree(cf->pool, peer,
                        &(qlbcf->tree[i]), peer->sid[i], peer->sidl[i], 0);
                if (snode == NULL) {
                    return NGX_ERROR;
                }
            }
        }
    }

    return NGX_OK;
}


ngx_int_t
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
    s->upstream->peer.notify = ngx_stream_upstream_notify_quic_lb_peer;

    qlbp->conf = qlbcf;
    qlbp->connection = s->connection;
    qlbp->get_rr_peer = ngx_stream_upstream_get_round_robin_peer;

    ngx_stream_upstream_rr_peers_unlock(qlbp->rrp.peers);

    return NGX_OK;
}


struct cid_metadata_t {
    u_char     long_hdr; /* Boolean */
    ngx_uint_t cr;
    u_char     cid[20];
    ngx_uint_t cidl;
};


/* Returns NGX_ERROR if packet should not be processed; NGX_DECLINED if we
   cannot extract a decodable CID */
static ngx_int_t
ngx_stream_upstream_extract_quic_lb_cid(ngx_peer_connection_t *pc,
       void *data, u_char *pkt_start, ngx_uint_t pkt_len,
       struct cid_metadata_t *info)
{
    u_char                                   *read = pkt_start;
    ngx_stream_upstream_quic_lb_peer_data_t  *qlbp = data;

    if (pkt_len < 21) {
        return NGX_ERROR; /* Too small to be a QUIC packet */
    }
    info->long_hdr = (*read & 0x80);
    read++;
    if (info->long_hdr) {
       read += 4;
       info->cidl = *read;
       read++;
    } else {
       info->cidl = 21; /* More than any min_cidl */
    }
    info->cr = ((*read & 0xc0) >> 6);
    if ((info->cr == 3) || (qlbp->conf->quic_lb_ctx[info->cr] == NULL)) {
        /* We don't know how long the CID has to be */
        return NGX_DECLINED;
    }
    if (info->cidl > qlbp->conf->min_cidl[info->cr]) {
       info->cidl = qlbp->conf->min_cidl[info->cr]; /* Only need this much */
    } else {
       if (qlbp->conf->lb_timeout[info->cr] == 0) {
           return NGX_DECLINED; /* Static SIDs */
       }
       /* It's a long header but CID isn't long enough. Just pull SIDL + 1 */
       info->cidl = 1 + qlbp->conf->sidl[info->cr];
    }
    memcpy(info->cid, read, info->cidl);
    return NGX_OK;
}


/* Returns length of the SID, 0 if failed. SID copied into *sid */
static ngx_uint_t
ngx_stream_upstream_extract_quic_lb_sid(ngx_peer_connection_t *pc,
       void *data, struct cid_metadata_t *cid, u_char *sid)
{
    u_char                                   *read = cid->cid;
    ngx_stream_upstream_quic_lb_peer_data_t  *qlbp = data;

    if (cid->cidl < qlbp->conf->min_cidl[cid->cr]) {
        if (qlbp->conf->lb_timeout[cid->cr] > 0) { /* Dynamic SIDs */
            memcpy(sid, read+1, qlbp->conf->sidl[cid->cr]);
            return qlbp->conf->sidl[cid->cr];
        } else {
            return 0; /* Cannot decode */
        }
    }
    return quic_lb_decrypt_cid(qlbp->conf->quic_lb_ctx[cid->cr],
               cid->cid, sid, NULL);
}


/* Returns NULL if SID is not present */
static ngx_stream_upstream_quic_lb_server_node_t *
ngx_stream_upstream_quic_lb_find_tree_node(u_char *sid, ngx_uint_t sidl,
        ngx_stream_upstream_quic_lb_server_tree_t *tree, ngx_uint_t timeout)
{
    ngx_rbtree_node_t                         *node, *old_node;
    ngx_stream_upstream_quic_lb_server_node_t *server;
    ngx_int_t                                  compare;

    /* Traverse the red-black tree to find the SID */
    node = tree->rbtree.root;
    while (node != &(tree->sentinel)) {
        server = (ngx_stream_upstream_quic_lb_server_node_t *)node;
        compare = ngx_memcmp(sid, server->sid, sidl);
        if (compare == 0) {
            break;
        }
        old_node = node;
        node = (compare < 0) ? node->left : node->right;\
        if ((timeout > 0) &&
                ((ngx_uint_t)(ngx_time() - server->last_time) > timeout)) {
            /* Purge expired allocations */
            ngx_rbtree_delete(&(tree->rbtree), old_node);
        }
    }
    return ((node == &(tree->sentinel)) ? NULL : server);
}


void
ngx_stream_upstream_notify_quic_lb_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t type)
{
    ngx_stream_upstream_quic_lb_peer_data_t *qlbp = data;
    ngx_buf_t                               *buf;
    struct cid_metadata_t                    info;
    u_char                                   sid[20];
    ngx_uint_t                               sidl = 0;
    ngx_stream_upstream_quic_lb_server_node_t *server, *new_server;

    if (type == NGX_STREAM_UPSTREAM_NOTIFY_FORWARD) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                "Notifying QUIC of new packet");
        /* The following line is heavily dependent on downstream_buf being
           directly below peer in ngx_stream_upstream_t */
        buf = (ngx_buf_t *)(pc + 1);
        switch(ngx_stream_upstream_extract_quic_lb_cid(pc, data, buf->last,
                buf->end - buf->last, &info)) {
        case NGX_ERROR:
        case NGX_DECLINED:
            /* Can't get an SID to figure out anything */
            break;
        case NGX_OK:
            if (qlbp->conf->lb_timeout[info.cr] == 0) {
                break; /* Static SIDs, nothing to do */
            }
            server = (ngx_stream_upstream_quic_lb_server_node_t *)
                    (pc->sid_node);
            if ((info.cidl == pc->cidl) && (memcmp(pc->cid, info.cid,
                        pc->cidl) == 0)) {
                /* CID matches, update time and we're done */
                ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                        "no change in SID, updating time");
                server->last_time = ngx_time();
                break;
            }
            sidl = ngx_stream_upstream_extract_quic_lb_sid(pc, data,
                    &info, sid);
            if (sidl == 0) {
                break;
            }
            pc->cidl = info.cidl;
            memcpy(pc->cid, info.cid, info.cidl);
            /* Traverse the red-black tree to find the SID */
            new_server = ngx_stream_upstream_quic_lb_find_tree_node(sid, sidl,
                    &(qlbp->conf->tree[info.cr]),
                    qlbp->conf->lb_timeout[info.cr]);
            if (new_server != NULL) {
                /* Migrating to another known SID */
                ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                        "Migrating peer to a known SID");
                new_server->last_time = ngx_time();
                pc->sid_node = new_server;
                break;
            }
            /* Add allocation to the tree */
            new_server = ngx_stream_upstream_add_node_to_tree(
                    qlbp->conf->config_pool, server->peer,
                    &(qlbp->conf->tree[info.cr]), sid, sidl, ngx_time());
            if (new_server == NULL) {
                break;
            }
            ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                    "Allocating a new SID to peer mid-connection");
            new_server->peer = server->peer;
            new_server->last_time = ngx_time();
            /* Copy active info into the connection */
            pc->sid_node = new_server;
            memcpy(pc->cid, info.cid, info.cidl);
            pc->cidl = info.cidl;
            break;
        }
    }
}


ngx_int_t
ngx_stream_upstream_get_quic_lb_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_stream_upstream_quic_lb_peer_data_t *qlbp = data;

    time_t                                     now;
    struct cid_metadata_t                      info;
    ngx_int_t                                  dynamic = 0; /* Boolean */
    ngx_stream_upstream_rr_peer_t             *peer = NULL;
    /* Tree traversal variables */
    ngx_stream_upstream_quic_lb_server_node_t *server = NULL;
    ngx_int_t                                  result;
    u_char                                     sid[QUIC_LB_MAX_CID_LEN];
    ngx_uint_t                                 sidl = 0;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                   "get quic-lb peer, try: %ui", pc->tries);
    if (qlbp->conf->retry_service && (ngx_retry_service_process_initial(
            qlbp->connection, qlbp->conf->retry_key, qlbp->conf->retry_iv,
            (qlbp->conf->retry_service == 1) ? NULL :
            &qlbp->conf->retry_key_seq) == NGX_DECLINED)) {
        /* No Retry token, or an invalid one. We may have sent a Retry, but
           abort the stream. */
        return NGX_ERROR;
    }

    ngx_stream_upstream_rr_peers_rlock(qlbp->rrp.peers);
    now = ngx_time();
    pc->connection = NULL;

    /* Find the CID */
    result = ngx_stream_upstream_extract_quic_lb_cid(pc, data,
            qlbp->connection->buffer->pos,
            qlbp->connection->buffer->end - qlbp->connection->buffer->pos,
            &info);
    if (result == NGX_ERROR) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0, "no cid");
        return NGX_DECLINED; /* Not QUIC; don't process */
    }
    if (result == NGX_DECLINED) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0, "no sid");
        goto round_robin; /* Can't get an SID */
    }
    sidl = ngx_stream_upstream_extract_quic_lb_sid(pc, data, &info, sid);
    if (sidl == 0) {
        goto round_robin;
    }
    dynamic = (qlbp->conf->lb_timeout[info.cr] > 0);
    /* Traverse the red-black tree to find the SID */
    server = ngx_stream_upstream_quic_lb_find_tree_node(sid, sidl,
            &(qlbp->conf->tree[info.cr]), qlbp->conf->lb_timeout[info.cr]);
    if (server == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0, "not in tree");
        if (!info.long_hdr) {
            /* If a short header, CID should be compliant. Drop instead */
            return NGX_ERROR;
        }
        goto round_robin;
    }
    /* Check for expired dynamic allocation */
    if (dynamic && ((ngx_uint_t)(now - server->last_time) >
            qlbp->conf->lb_timeout[info.cr])) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0, "expired allocation");
        goto round_robin;
    }
    peer = server->peer;

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
    server->last_time = now;
    if (dynamic) {
        /* Copy active info into the connection */
        pc->sid_node = server;
        memcpy(pc->cid, info.cid, info.cidl);
        pc->cidl = info.cidl;
    }

    return NGX_OK;

round_robin:
    result = ngx_stream_upstream_get_round_robin_peer(pc, &(qlbp->rrp));
    if ((result == NGX_OK) && dynamic) {
        /* Dynamic; add allocation to the tree */
        peer = qlbp->rrp.current; /* Round Robin result */
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0,
               "assigning new SID to peer");
        if (server == NULL) { /* Node for this SID doesn't exist */
            server = ngx_stream_upstream_add_node_to_tree(
                    qlbp->conf->config_pool, peer,
                    &(qlbp->conf->tree[info.cr]), sid, sidl, now);
            if (server == NULL) {
                return NGX_ERROR;
            }
        }
        server->peer = peer;
        server->last_time = now;
        /* Copy active info into the connection */
        pc->sid_node = server;
        memcpy(pc->cid, info.cid, info.cidl);
        pc->cidl = info.cidl;
    }
    return result;
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
    ngx_int_t                            lb_timeout = 0, key_seq = -1;
    ngx_uint_t                           i, j, nelts, sidl_limit;
    u_char                               key[16], iv[8];;
    ngx_int_t                            iv_byte = -1, cr = -1;
    ngx_int_t                            retry_service = 0;

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

    /* Allow parameters in any order */
    nelts = cf->args->nelts;
    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "retry-service", 13) == 0) {
            /* It's a retry service, ignore the rest */
            retry_service = 1;
            continue;
        }

        if (ngx_strncmp(value[i].data, "iv=", 3) == 0) {
            for (j = 0; j < (value[i].len - 3)/2; j++) {
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
            if ((sidl == NGX_ERROR) || (sidl <= 0)) {
                goto invalid;
            }
            continue;
        }

        if (ngx_strncmp(value[i].data, "key=", 4) == 0) {
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
            nonce_len = ngx_hextoi(&value[i].data[10], value[i].len - 10);
            if ((nonce_len == NGX_ERROR) || (nonce_len < 8) ||
                    (nonce_len > 16)) {
                goto invalid;
            }
            continue;
        }

        if (ngx_strncmp(value[i].data, "lb_timeout=", 11) == 0) {
            nelts--; /* Used for determining algorithm */
            lb_timeout = ngx_atoi(&value[i].data[11], value[i].len - 11);
            if ((lb_timeout == NGX_ERROR) || (lb_timeout < 0)) {
                goto invalid;
            }
        }

        if (ngx_strncmp(value[i].data, "retry-key-sequence=", 19) == 0) {
            key_seq = ngx_atoi(&value[i].data[19], value[i].len - 19);
            if ((key_seq == NGX_ERROR) || (key_seq < 0)) {
                goto invalid;
            }
        }
    }

    /* Number of parameters defines the algorithm used */
    switch(nelts) {
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
        if (key_seq > -1) {
            qlbcf->retry_service++;
            qlbcf->retry_key_seq = (u_char)key_seq;
        }
        return NGX_CONF_OK;
    }

    /* Check SID length is valid */
    sidl_limit = (lb_timeout > 0) ? 7 : ((alg == QUIC_LB_PCID) ? 16 :
         ((alg == QUIC_LB_SCID) ? 11 : 12));
    if (((ngx_uint_t)sidl) > sidl_limit) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "SID Length is too large");
        return NGX_CONF_ERROR;
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
    qlbcf->sidl[cr] = sidl;
    qlbcf->lb_timeout[cr] = (ngx_uint_t)lb_timeout;

    uscf->peer.init_upstream = ngx_stream_upstream_init_quic_lb;

    return NGX_CONF_OK;

invalid:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid parameter \"%V\"", &value[i]);
    return NGX_CONF_ERROR;
}
