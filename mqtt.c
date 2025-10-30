#include <iot/cJSON.h>
#include <iot/iot.h>
#include "mqtt.h"


static int s_signo;
static void signal_handler(int signo) {
    s_signo = signo;
}

static void mqtt_event_notify(struct mg_connection *c, struct mg_str event_data) {
    struct mqtt_private *priv = (struct mqtt_private *)c->mgr->userdata;
    struct mg_str pub_topic = mg_str("$iot-mqtt-events");
    for (struct mqtt_sub *sub = priv->subs; sub != NULL; sub = sub->next) {
        if (c!=sub->c && mg_match(pub_topic, sub->topic, NULL)) {
            struct mg_mqtt_opts pub_opts;
            memset(&pub_opts, 0, sizeof(pub_opts));
            pub_opts.topic = pub_topic;
            pub_opts.message = event_data;
            pub_opts.qos = MQTT_QOS, pub_opts.retain = false;
            mg_mqtt_pub(sub->c, &pub_opts);
        }
    }
}

static void mqtt_ev_accept_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {

    if (c->fn_data) {
        MG_ERROR(("bad logic error"));
        exit(EXIT_FAILURE);
    }

    c->fn_data = (struct mqtt_session *) calloc(1, sizeof(struct mqtt_session));
    if (!c->fn_data) {
        MG_ERROR(("OOM"));
        exit(EXIT_FAILURE);
    }

    struct mqtt_session *s = (struct mqtt_session*)c->fn_data;
    s->connected = mg_millis();
    s->active = s->connected;

}

static void mqtt_ev_read_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {

    if (!c->fn_data)
        return;

    struct mqtt_session *s = (struct mqtt_session*)c->fn_data;
    s->active = mg_millis();

}

static void mqtt_ev_poll_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {

    if (!c->fn_data)
        return;

    struct mqtt_session *s = (struct mqtt_session*)c->fn_data;

    uint64_t now = mg_millis();
    if ( s->keepalive && now > s->active && now - s->active > (s->keepalive + 12)*1000) {
        MG_INFO(("mqtt connection %llu timeout", c->id));
        c->is_draining = 1;
    }

}

static void mqtt_ev_close_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {

    struct mqtt_private *priv = (struct mqtt_private *)c->mgr->userdata;

    if ( c == priv->mqtt_listener ) {
        MG_ERROR(("mqtt listener closed"));
        priv->mqtt_listener = NULL;
    }

    if ( c == priv->mqtts_listener ) {
        MG_ERROR(("mqtts listener closed"));
        priv->mqtts_listener = NULL;
    }

    // Client disconnects. Remove from the subscription list
    for (struct mqtt_sub *next, *sub = priv->subs; sub != NULL; sub = next) {

        next = sub->next;

        if (c != sub->c)
            continue;

        MG_INFO(("unsub %p [%.*s]", c->fd, (int) sub->topic.len, sub->topic.ptr));
        LIST_DELETE(struct mqtt_sub, &priv->subs, sub);
        if (sub->topic.ptr)
            free((void*)sub->topic.ptr);

        free(sub);
    }

    MG_INFO(("delete %p mqtt_session for connection %lu", c->fd, c->id));

    if (!c->fn_data)
        return;

    struct mqtt_session *s = (struct mqtt_session*)c->fn_data;

    if (s->username.ptr)
        free((void*)s->username.ptr);
    if (s->password.ptr)
        free((void*)s->password.ptr);

    free(c->fn_data);
    c->fn_data = NULL;

    mqtt_event_notify(c, mg_str("disconnected"));

}

static void mqtt_cmd_connect_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {

    int skipped_bytes = 0;
    int data_length_size = 1;
    struct mg_mqtt_message *mm = (struct mg_mqtt_message *) ev_data;

    if (!c->fn_data) {
        mg_error(c, "OOM");
        return;
    }

    while (mm->dgram.ptr[1 + data_length_size] != 0) {
        data_length_size++;
    }

    // Client connects
    if (mm->dgram.len < 9) {
        mg_error(c, "Malformed MQTT frame");
    } else if (mm->dgram.ptr[1 + data_length_size + 6] != 4) { //only mqtt 3.1.1
        mg_error(c, "Unsupported MQTT version %d", mm->dgram.ptr[1 + data_length_size + 6]);
    } else {
        struct mqtt_session *s = (struct mqtt_session*)c->fn_data;
        
        s->keepalive = mg_ntohs(*(uint16_t*)(mm->dgram.ptr +1 + data_length_size + 8)); //keepalive, seconds

        if (mm->dgram.ptr[1 + data_length_size + 7] & 0x80) { //has username
            //keepalive 2 bytes
            skipped_bytes += 2;

            //cid
            skipped_bytes += 2 + mg_ntohs(*(uint16_t*)(mm->dgram.ptr + 1 + data_length_size + 8 + skipped_bytes));

            if (mm->dgram.ptr[1 + data_length_size + 7] & 0x04) {//has will
                skipped_bytes += 2 + mg_ntohs(*(uint16_t*)(mm->dgram.ptr + 1 + data_length_size + 8 + skipped_bytes)); //will topic
                skipped_bytes += 2 + mg_ntohs(*(uint16_t*)(mm->dgram.ptr + 1 + data_length_size + 8 + skipped_bytes)); //will message
            }

            uint16_t username_len = mg_ntohs(*(uint16_t*)(mm->dgram.ptr + 1 + data_length_size + 8 + skipped_bytes));
            const char *username_ptr = mm->dgram.ptr + 1 + data_length_size + 8 + 2 + skipped_bytes;
            s->username = mg_strdup(mg_str_n(username_ptr, username_len));

            if (mm->dgram.ptr[1 + data_length_size + 7] & 0x40) { //has password
                skipped_bytes += 2 + mg_ntohs(*(uint16_t*)(mm->dgram.ptr + 1 + data_length_size + 8 + skipped_bytes)); 
                uint16_t password_len = mg_ntohs(*(uint16_t*)(mm->dgram.ptr + 1 + data_length_size + 8 + skipped_bytes));
                const char *password_ptr = mm->dgram.ptr + 1 + data_length_size + 8 + 2 + skipped_bytes;
                s->password = mg_strdup(mg_str_n(password_ptr, password_len));
            }
            MG_INFO(("%p username: %.*s, password: %.*s", c->fd, s->username.len, s->username.ptr, s->password.len, s->password.ptr));

            mqtt_event_notify(c, mg_str("connected"));
        }
        uint8_t response[] = {0, 0};
        mg_mqtt_send_header(c, MQTT_CMD_CONNACK, 0, sizeof(response));
        mg_send(c, response, sizeof(response));
    }

}

static size_t mqtt_next_topic(struct mg_mqtt_message *msg,
                                 struct mg_str *topic, uint8_t *qos,
                                 size_t pos) {
    unsigned char *buf = (unsigned char *) msg->dgram.ptr + pos;
    size_t new_pos;

    if (pos >= msg->dgram.len)
        return 0;

    topic->len = (size_t) (((unsigned) buf[0]) << 8 | buf[1]);
    topic->ptr = (char *) buf + 2;
    new_pos = pos + 2 + topic->len + (qos == NULL ? 0 : 1);
    
    if ((size_t) new_pos > msg->dgram.len)
        return 0;

    if (qos != NULL)
        *qos = buf[2 + topic->len];
    
    return new_pos;
}

static size_t mqtt_next_sub(struct mg_mqtt_message *msg, struct mg_str *topic,
                        uint8_t *qos, size_t pos) {
    uint8_t tmp;
    return mqtt_next_topic(msg, topic, qos == NULL ? &tmp : qos, pos);
}

static void mqtt_cmd_subscribe_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {

    size_t pos = 4;  // Initial topic offset, where ID ends
    uint8_t qos, resp[256];
    struct mg_str topic;
    int num_topics = 0;
    struct mg_mqtt_message *mm = (struct mg_mqtt_message *) ev_data;
    uint16_t id = mg_htons(mm->id);
    struct mqtt_private *priv = (struct mqtt_private *)c->mgr->userdata;


    while ((pos = mqtt_next_sub(mm, &topic, &qos, pos)) > 0) {
        struct mqtt_sub *sub = calloc(1, sizeof(struct mqtt_sub));
        sub->c = c;
        sub->topic = mg_strdup(topic);
        sub->qos = qos;
        LIST_ADD_HEAD(struct mqtt_sub, &priv->subs, sub);
        if (c->is_tls) {
            MG_INFO(("[MQTTS] sub %p [%.*s]", c->fd, (int) sub->topic.len, sub->topic.ptr));
        } else {
            MG_INFO(("[MQTT] sub %p [%.*s]", c->fd, (int) sub->topic.len, sub->topic.ptr));
        }
        // Change '+' to '*' for topic matching using mg_match
        for (size_t i = 0; i < sub->topic.len; i++) {
            if (sub->topic.ptr[i] == '+') ((char *) sub->topic.ptr)[i] = '*';
        }
        resp[num_topics++] = qos;
    }

    mg_mqtt_send_header(c, MQTT_CMD_SUBACK, 0, num_topics + 2);
    mg_send(c, &id, 2);
    mg_send(c, resp, num_topics);
}

void mqtt_req_handler(struct mg_connection *c, struct mg_str topic, struct mg_str data) {

    cJSON *root = cJSON_ParseWithLength(data.ptr, data.len);
    cJSON *method = cJSON_GetObjectItem(root, FIELD_METHOD);
    cJSON *json_resp = NULL;

    struct mg_str pub_topic = mg_str_n(topic.ptr, topic.len - mg_str(IOT_MQTT_TOPIC_POSTFIX).len);
    const char *error_msg = NULL, *resp = NULL, *out = NULL;

    struct mqtt_private *priv = (struct mqtt_private *)c->mgr->userdata;

    if (!cJSON_IsString(method)) {
        MG_ERROR(("method is not string"));
        error_msg = "{\"code\": -10401}\n";
        goto done;
    }

    struct mg_str mg_method = mg_str(cJSON_GetStringValue(method));
    struct mg_str mg_mqtt_method_clients = mg_str(MQTT_METHOD_CLIENTS);

    if (!mg_strcmp(mg_method, mg_mqtt_method_clients)) { //$mqtt/clients
        json_resp = cJSON_CreateObject();
        cJSON_AddItemToObject(json_resp, "code", cJSON_CreateNumber(0));
        cJSON_AddItemToObject(json_resp, "method", cJSON_CreateString(cJSON_GetStringValue(method)));
        cJSON *data = cJSON_CreateArray();
        uint64_t now = mg_millis();

        for (struct mg_connection *conn = c->mgr->conns; conn != NULL; conn = conn->next) {
            struct mqtt_session *s = (struct mqtt_session*) conn->fn_data;

            if (!s || s->username.len == 0) continue;

            cJSON *obj = cJSON_CreateObject();

            char *username = mg_mprintf("%.*s", s->username.len, s->username.ptr);
            cJSON_AddItemToObject(obj, "u", cJSON_CreateString(username));
            free(username);

            char *password = mg_mprintf("%.*s", s->password.len, s->password.ptr);
            cJSON_AddItemToObject(obj, "p", cJSON_CreateString(password));
            free(password);

            char *ip = mg_mprintf("%M", mg_print_ip, &conn->rem);
            cJSON_AddItemToObject(obj, "a", cJSON_CreateString(ip));
            free(ip);

            cJSON_AddItemToObject(obj, "c", cJSON_CreateNumber(s->connected/1000));
            cJSON_AddItemToObject(obj, "t", cJSON_CreateNumber(s->active/1000));
            cJSON_AddItemToObject(obj, "n", cJSON_CreateNumber(now/1000));
            cJSON_AddItemToObject(obj, "k", cJSON_CreateNumber(s->keepalive));
            cJSON_AddItemToObject(obj, "i", cJSON_CreateNumber(conn->id));

            cJSON_AddItemToArray(data, obj);
        }

        cJSON_AddItemToObject(json_resp, "data", data);
        resp = cJSON_Print(json_resp);

    } else {
        MG_ERROR(("method is not supported"));
        error_msg = "{\"code\": -10401}\n";
        goto done;
    }

done:
    out = resp;
    if (!out) {
        out = error_msg;
    }

    MG_DEBUG(("pub %s ->  %.*s", out, (int) pub_topic.len, pub_topic.ptr));

    for (struct mqtt_sub *sub = priv->subs; sub != NULL; sub = sub->next) {
        if (mg_match(pub_topic, sub->topic, NULL)) {
            struct mg_mqtt_opts pub_opts;
            memset(&pub_opts, 0, sizeof(pub_opts));
            pub_opts.topic = pub_topic;
            pub_opts.message = mg_str(out);
            pub_opts.qos = MQTT_QOS, pub_opts.retain = false;
            mg_mqtt_pub(sub->c, &pub_opts);
        }
    }

    cJSON_Delete(root);
    if (json_resp) {
        cJSON_Delete(json_resp);
    }
    if (resp) {
        cJSON_free((void*)resp);
    }
}

static void mqtt_cmd_publish_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {

    struct mg_mqtt_message *mm = (struct mg_mqtt_message *) ev_data;
    struct mqtt_private *priv = (struct mqtt_private *)c->mgr->userdata;

    MG_DEBUG(("publish %p [%.*s] -> [%.*s]", c->fd, (int) mm->data.len,
        mm->data.ptr, (int) mm->topic.len, mm->topic.ptr));
    if (mg_match(mm->topic, mg_str(IOT_MQTT_TOPIC), NULL)) { //to mqtt server
        MG_INFO(("system msg to mqtt server"));
        mqtt_req_handler(c, mm->topic, mm->data);
    } else {
        struct mg_mqtt_opts pub_opts;
        memset(&pub_opts, 0, sizeof(pub_opts));
        pub_opts.topic = mm->topic;
        pub_opts.message = mm->data;
        pub_opts.qos = MQTT_QOS, pub_opts.retain = false;
        for (struct mqtt_sub *sub = priv->subs; sub != NULL; sub = sub->next) {
            if (mg_match(mm->topic, sub->topic, NULL)) {
                if (sub->c->is_tls && sub->c->send.len > 32 * MG_IO_SIZE) { //outside msg, 64KB msg remain left
                    MG_ERROR(("mqtt connection %llu send buffer full, drop latest msg", sub->c->id));
                    continue;
                }
                mg_mqtt_pub(sub->c, &pub_opts);
            }
        }
    }
}

static void mqtt_cmd_pingreq_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
    mg_mqtt_pong(c);
}

static void mqtt_ev_mqtt_cmd_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
    struct mg_mqtt_message *mm = (struct mg_mqtt_message *) ev_data;
    MG_DEBUG(("cmd %d qos %d", mm->cmd, mm->qos));
    switch (mm->cmd) {
        case MQTT_CMD_CONNECT:
            mqtt_cmd_connect_cb(c, ev, ev_data, fn_data);
            break;
        case MQTT_CMD_SUBSCRIBE:
            mqtt_cmd_subscribe_cb(c, ev, ev_data, fn_data);
            break;
        case MQTT_CMD_PUBLISH:
            mqtt_cmd_publish_cb(c, ev, ev_data, fn_data);
            break;
        case MQTT_CMD_PINGREQ:
            mqtt_cmd_pingreq_cb(c, ev, ev_data, fn_data);
            break;
    }
}

static void mqtt_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
    switch (ev) {
        case MG_EV_ACCEPT:
            mqtt_ev_accept_cb(c, ev, ev_data, fn_data);
            break;
        case MG_EV_READ:
            mqtt_ev_read_cb(c, ev, ev_data, fn_data);
            break;
        case MG_EV_POLL:
            mqtt_ev_poll_cb(c, ev, ev_data, fn_data);
            break;
        case MG_EV_CLOSE:
            mqtt_ev_close_cb(c, ev, ev_data, fn_data);
            break;
        case MG_EV_MQTT_CMD:
            mqtt_ev_mqtt_cmd_cb(c, ev, ev_data, fn_data);
            break;

    }
}

static void mqtts_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
    if (ev == MG_EV_ACCEPT) {
        struct mqtt_private *priv = (struct mqtt_private *)c->mgr->userdata;
        struct mg_tls_opts opts = { 0 };
        opts.ca = priv->cfg.opts->mqtts_ca;         // Enable two-way SSL
        opts.cert = priv->cfg.opts->mqtts_cert;     // Certificate PEM file
        opts.certkey = priv->cfg.opts->mqtts_certkey;
        mg_tls_init(c, &opts);
    }
    mqtt_cb(c, ev, ev_data, fn_data);
}

void timer_mqtt_fn(void *arg) {
    struct mg_mgr *mgr = (struct mg_mgr *)arg;
    struct mqtt_private *priv = (struct mqtt_private *)mgr->userdata;

    if ( !priv->mqtt_listener ) {
        struct mg_connection *c = mg_mqtt_listen(&priv->mgr, priv->cfg.opts->mqtt_listening_address, mqtt_cb, NULL);
        if (!c) {
            MG_ERROR(("mqtt listener create failed"));
        } else {
            MG_INFO(("mqtt listener create %llu", c->id));
            priv->mqtt_listener = c;
        }
    }

    if ( priv->cfg.opts->mqtts_enable && !priv->mqtts_listener ) {
        struct mg_connection *c = mg_mqtt_listen(&priv->mgr, priv->cfg.opts->mqtts_listening_address, mqtts_cb, NULL);
        if (!c) {
            MG_ERROR(("mqtts listener create failed"));
        } else {
            MG_INFO(("mqtts listener create %llu", c->id));
            priv->mqtts_listener = c;
        }
    }
}

int mqtt_init(void **priv, void *opts) {

    struct mqtt_private *p = NULL;
    int timer_opts = MG_TIMER_REPEAT | MG_TIMER_RUN_NOW;

    signal(SIGINT, signal_handler);   // Setup signal handlers - exist event
    signal(SIGTERM, signal_handler);  // manager loop on SIGINT and SIGTERM

    *priv = NULL;
    p = calloc(1, sizeof(struct mqtt_private));
    if (!p)
        return -1;
    
    p->cfg.opts = opts;
    mg_log_set(p->cfg.opts->debug_level);

    mg_mgr_init(&p->mgr);

    p->mgr.userdata = p;

    mg_timer_add(&p->mgr, 1000, timer_opts, timer_mqtt_fn, &p->mgr);  //1s, repeat broadcast if need

    *priv = p;

    return 0;

}

void mqtt_run(void *handle) {
    struct mqtt_private *priv = (struct mqtt_private *)handle;
    while (s_signo == 0) mg_mgr_poll(&priv->mgr, 1000);  // Event loop, 1000ms timeout
}

void mqtt_exit(void *handle) {
    struct mqtt_private *priv = (struct mqtt_private *)handle;
    mg_mgr_free(&priv->mgr);
    free(handle);
}

int mqtt_main(void *user_options) {

    struct mqtt_option *opts = (struct mqtt_option *)user_options;
    void *mqtt_handle;
    int ret;

    ret = mqtt_init(&mqtt_handle, opts);
    if (ret)
        exit(EXIT_FAILURE);

    mqtt_run(mqtt_handle);

    mqtt_exit(mqtt_handle);

    return 0;

}
