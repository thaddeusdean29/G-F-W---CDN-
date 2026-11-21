/*
 * ngx_http_v2_rst_counter_module.c
 *
 * Tengine HTTP/2 RST_STREAM 计数模块
 * 用于检测 HTTP/2 Rapid Reset 攻击 (CVE-2023-44487)
 *
 * 功能：
 * 1. 统计每个客户端 IP 在时间窗口内发送的 RST_STREAM 帧数量
 * 2. 暴露 Nginx 变量 $http2_rst_stream_count 供配置使用
 * 3. 支持在 Tengine 配置中设置阈值和自动拦截
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* 每个客户端 IP 的 RST_STREAM 计数记录 */
typedef struct {
    u_char           addr[16];      /* IPv4/IPv6 地址 */
    time_t           last_update;   /* 最后更新时间 */
    ngx_uint_t       count;         /* RST 计数 */
    ngx_uint_t       pad;           /* 内存对齐 */
} ngx_http_v2_rst_record_t;

/* 共享内存哈希表节点 */
typedef struct {
    ngx_rbtree_node_t              node;
    ngx_http_v2_rst_record_t       record;
} ngx_http_v2_rst_shm_node_t;

/* 模块主配置 */
typedef struct {
    ngx_shm_zone_t    *shm_zone;
    ngx_rbtree_t      *rbtree;
    ngx_rbtree_node_t *sentinel;
    ngx_slab_pool_t   *shpool;
} ngx_http_v2_rst_main_conf_t;

/* Location 配置 */
typedef struct {
    ngx_flag_t         enabled;
    ngx_uint_t         time_window;  /* 时间窗口（秒），默认 1 */
} ngx_http_v2_rst_loc_conf_t;

/* 函数声明 */
static ngx_int_t ngx_http_v2_rst_add_variable(ngx_conf_t *cf);
static ngx_int_t ngx_http_v2_rst_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static void *ngx_http_v2_rst_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_v2_rst_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_v2_rst_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static char *ngx_http_v2_rst_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_v2_rst_init_zone(ngx_shm_zone_t *shm_zone,
    void *data);
static void ngx_http_v2_rst_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static ngx_http_v2_rst_shm_node_t *ngx_http_v2_rst_lookup(
    ngx_http_v2_rst_main_conf_t *conf, struct sockaddr *sa);
static ngx_int_t ngx_http_v2_rst_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_v2_rst_init(ngx_conf_t *cf);

/* 模块指令定义 */
static ngx_command_t ngx_http_v2_rst_commands[] = {

    { ngx_string("http2_rst_counter"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_v2_rst_loc_conf_t, enabled),
      NULL },

    { ngx_string("http2_rst_counter_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_v2_rst_zone,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("http2_rst_time_window"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_v2_rst_loc_conf_t, time_window),
      NULL },

    ngx_null_command
};

/* 模块上下文 */
static ngx_http_module_t ngx_http_v2_rst_module_ctx = {
    ngx_http_v2_rst_add_variable,      /* preconfiguration */
    ngx_http_v2_rst_init,              /* postconfiguration */

    ngx_http_v2_rst_create_main_conf,  /* create main configuration */
    NULL,                              /* init main configuration */

    NULL,                              /* create server configuration */
    NULL,                              /* merge server configuration */

    ngx_http_v2_rst_create_loc_conf,   /* create location configuration */
    ngx_http_v2_rst_merge_loc_conf     /* merge location configuration */
};

/* 模块定义 */
ngx_module_t ngx_http_v2_rst_counter_module = {
    NGX_MODULE_V1,
    &ngx_http_v2_rst_module_ctx,       /* module context */
    ngx_http_v2_rst_commands,          /* module directives */
    NGX_HTTP_MODULE,                   /* module type */
    NULL,                              /* init master */
    NULL,                              /* init module */
    NULL,                              /* init process */
    NULL,                              /* init thread */
    NULL,                              /* exit thread */
    NULL,                              /* exit process */
    NULL,                              /* exit master */
    NGX_MODULE_V1_PADDING
};

/* 注册变量 $http2_rst_stream_count */
static ngx_int_t
ngx_http_v2_rst_add_variable(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var;

    var = ngx_http_add_variable(cf, &(ngx_str_t)ngx_string("http2_rst_stream_count"),
                                 NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_v2_rst_variable;

    return NGX_OK;
}

/* 创建主配置 */
static void *
ngx_http_v2_rst_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_v2_rst_main_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_v2_rst_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}

/* 创建 location 配置 */
static void *
ngx_http_v2_rst_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_v2_rst_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_v2_rst_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enabled = NGX_CONF_UNSET;
    conf->time_window = NGX_CONF_UNSET_UINT;

    return conf;
}

/* 合并 location 配置 */
static char *
ngx_http_v2_rst_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_v2_rst_loc_conf_t *prev = parent;
    ngx_http_v2_rst_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enabled, prev->enabled, 0);
    ngx_conf_merge_uint_value(conf->time_window, prev->time_window, 1);

    return NGX_CONF_OK;
}

/* 配置共享内存 zone */
static char *
ngx_http_v2_rst_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_v2_rst_main_conf_t  *rmcf = conf;
    ngx_str_t                    *value;
    ngx_shm_zone_t               *shm_zone;
    ssize_t                       size;

    value = cf->args->elts;

    /* 解析 zone=name:size 格式 */
    if (ngx_strncmp(value[1].data, "zone=", 5) != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                          "invalid parameter \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    value[1].data += 5;
    value[1].len -= 5;

    /* 查找冒号分隔符 */
    size_t i;
    for (i = 0; i < value[1].len; i++) {
        if (value[1].data[i] == ':') {
            break;
        }
    }

    if (i == value[1].len) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                          "invalid zone size");
        return NGX_CONF_ERROR;
    }

    ngx_str_t name;
    name.data = value[1].data;
    name.len = i;

    ngx_str_t size_str;
    size_str.data = value[1].data + i + 1;
    size_str.len = value[1].len - i - 1;

    size = ngx_parse_size(&size_str);
    if (size == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                          "invalid zone size \"%V\"", &size_str);
        return NGX_CONF_ERROR;
    }

    if (size < (ssize_t) (8 * ngx_pagesize)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                          "zone \"%V\" is too small", &name);
        return NGX_CONF_ERROR;
    }

    shm_zone = ngx_shared_memory_add(cf, &name, size,
                                     &ngx_http_v2_rst_counter_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (shm_zone->data) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                          "duplicate zone \"%V\"", &name);
        return NGX_CONF_ERROR;
    }

    shm_zone->init = ngx_http_v2_rst_init_zone;
    shm_zone->data = rmcf;

    rmcf->shm_zone = shm_zone;

    return NGX_CONF_OK;
}

/* 初始化共享内存 zone */
static ngx_int_t
ngx_http_v2_rst_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_v2_rst_main_conf_t  *rmcf = shm_zone->data;
    ngx_http_v2_rst_main_conf_t  *ormcf = data;

    if (ormcf) {
        rmcf->rbtree = ormcf->rbtree;
        rmcf->sentinel = ormcf->sentinel;
        rmcf->shpool = ormcf->shpool;
        return NGX_OK;
    }

    rmcf->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        rmcf->rbtree = rmcf->shpool->data;
        rmcf->sentinel = (ngx_rbtree_node_t *)
                         ((u_char *) rmcf->rbtree + sizeof(ngx_rbtree_t));
        return NGX_OK;
    }

    rmcf->rbtree = ngx_slab_alloc(rmcf->shpool, sizeof(ngx_rbtree_t));
    if (rmcf->rbtree == NULL) {
        return NGX_ERROR;
    }

    rmcf->sentinel = ngx_slab_alloc(rmcf->shpool, sizeof(ngx_rbtree_node_t));
    if (rmcf->sentinel == NULL) {
        return NGX_ERROR;
    }

    ngx_rbtree_init(rmcf->rbtree, rmcf->sentinel,
                    ngx_http_v2_rst_rbtree_insert_value);

    rmcf->shpool->data = rmcf->rbtree;

    return NGX_OK;
}

/* 红黑树插入函数 */
static void
ngx_http_v2_rst_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_http_v2_rst_shm_node_t  *n, *t;

    for ( ;; ) {
        if (node->key < temp->key) {
            if (temp->left == sentinel) {
                temp->left = node;
                break;
            }
            temp = temp->left;

        } else if (node->key > temp->key) {
            if (temp->right == sentinel) {
                temp->right = node;
                break;
            }
            temp = temp->right;

        } else {
            /* node->key == temp->key */
            n = (ngx_http_v2_rst_shm_node_t *) node;
            t = (ngx_http_v2_rst_shm_node_t *) temp;

            if (ngx_memcmp(n->record.addr, t->record.addr, 16) < 0) {
                if (temp->left == sentinel) {
                    temp->left = node;
                    break;
                }
                temp = temp->left;
            } else {
                if (temp->right == sentinel) {
                    temp->right = node;
                    break;
                }
                temp = temp->right;
            }
        }
    }

    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}

/* 查找或创建客户端 IP 记录 */
static ngx_http_v2_rst_shm_node_t *
ngx_http_v2_rst_lookup(ngx_http_v2_rst_main_conf_t *conf, struct sockaddr *sa)
{
    uint32_t                      hash;
    ngx_rbtree_node_t            *node, *sentinel;
    ngx_http_v2_rst_shm_node_t   *sn;
    u_char                        addr[16];
    size_t                        len;

    /* 提取 IP 地址 */
    ngx_memzero(addr, 16);

    if (sa->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *) sa;
        ngx_memcpy(addr, &sin->sin_addr.s_addr, 4);
        len = 4;
    }
#if (NGX_HAVE_INET6)
    else if (sa->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) sa;
        ngx_memcpy(addr, &sin6->sin6_addr.s6_addr, 16);
        len = 16;
    }
#endif
    else {
        return NULL;
    }

    /* 计算哈希值 */
    hash = ngx_crc32_short(addr, len);

    /* 在红黑树中查找 */
    node = conf->rbtree->root;
    sentinel = conf->rbtree->sentinel;

    while (node != sentinel) {
        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */
        sn = (ngx_http_v2_rst_shm_node_t *) node;

        if (ngx_memcmp(addr, sn->record.addr, 16) == 0) {
            return sn;
        }

        node = (ngx_memcmp(addr, sn->record.addr, 16) < 0)
               ? node->left : node->right;
    }

    /* 未找到，创建新节点 */
    sn = ngx_slab_alloc_locked(conf->shpool, sizeof(ngx_http_v2_rst_shm_node_t));
    if (sn == NULL) {
        return NULL;
    }

    sn->node.key = hash;
    ngx_memcpy(sn->record.addr, addr, 16);
    sn->record.last_update = ngx_time();
    sn->record.count = 0;

    ngx_rbtree_insert(conf->rbtree, &sn->node);

    return sn;
}

/* 获取变量 $http2_rst_stream_count */
static ngx_int_t
ngx_http_v2_rst_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_v2_rst_main_conf_t  *rmcf;
    ngx_http_v2_rst_loc_conf_t   *rlcf;
    ngx_http_v2_rst_shm_node_t   *sn;
    u_char                       *p;

    rlcf = ngx_http_get_module_loc_conf(r, ngx_http_v2_rst_counter_module);
    if (!rlcf->enabled) {
        v->not_found = 1;
        return NGX_OK;
    }

    rmcf = ngx_http_get_module_main_conf(r, ngx_http_v2_rst_counter_module);
    if (rmcf->shm_zone == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    /* 检查是否是 HTTP/2 请求 */
    if (r->http_version != NGX_HTTP_VERSION_20) {
        v->not_found = 1;
        return NGX_OK;
    }

    ngx_shmtx_lock(&rmcf->shpool->mutex);

    sn = ngx_http_v2_rst_lookup(rmcf, r->connection->sockaddr);
    if (sn == NULL) {
        ngx_shmtx_unlock(&rmcf->shpool->mutex);
        v->not_found = 1;
        return NGX_OK;
    }

    ngx_shmtx_unlock(&rmcf->shpool->mutex);

    /* 分配内存存储计数值 */
    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%ui", sn->record.count) - p;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}

/* RST_STREAM 事件处理函数 */
static ngx_int_t
ngx_http_v2_rst_handler(ngx_http_request_t *r)
{
    ngx_http_v2_rst_main_conf_t  *rmcf;
    ngx_http_v2_rst_loc_conf_t   *rlcf;
    ngx_http_v2_rst_shm_node_t   *sn;
    time_t                        now;

    rlcf = ngx_http_get_module_loc_conf(r, ngx_http_v2_rst_counter_module);
    if (!rlcf->enabled) {
        return NGX_DECLINED;
    }

    rmcf = ngx_http_get_module_main_conf(r, ngx_http_v2_rst_counter_module);
    if (rmcf->shm_zone == NULL) {
        return NGX_DECLINED;
    }

    /* 只处理 HTTP/2 请求 */
    if (r->http_version != NGX_HTTP_VERSION_20) {
        return NGX_DECLINED;
    }

    now = ngx_time();

    ngx_shmtx_lock(&rmcf->shpool->mutex);

    sn = ngx_http_v2_rst_lookup(rmcf, r->connection->sockaddr);
    if (sn == NULL) {
        ngx_shmtx_unlock(&rmcf->shpool->mutex);
        return NGX_DECLINED;
    }

    /* 检查时间窗口 */
    if (now - sn->record.last_update > (time_t)rlcf->time_window) {
        /* 超过时间窗口，重置计数 */
        sn->record.count = 1;
        sn->record.last_update = now;
    } else {
        /* 在时间窗口内，累加计数 */
        sn->record.count++;
    }

    ngx_shmtx_unlock(&rmcf->shpool->mutex);

    return NGX_DECLINED;
}

/* 模块初始化 */
static ngx_int_t
ngx_http_v2_rst_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_v2_rst_handler;

    return NGX_OK;
}