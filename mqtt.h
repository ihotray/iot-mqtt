#ifndef __IOT_MQTT_H__
#define __IOT_MQTT_H__

#include <iot/mongoose.h>

struct mqtt_option {
    const char *mqtt_listening_address;
    const char *mqtts_listening_address;
    int mqtts_enable;
    const char *mqtts_ca;
    const char *mqtts_cert;
    const char *mqtts_certkey;
    int debug_level;
};


struct mqtt_config {
    struct mqtt_option *opts;
};

struct mqtt_session {
    uint64_t connected;
    uint64_t active;
    uint16_t keepalive;
    struct mg_str username;
    struct mg_str password;
};


struct mqtt_sub {
    struct mqtt_sub *next;
    struct mg_connection *c;
    struct mg_str topic;
    uint8_t qos;
};

struct mqtt_private {
    struct mqtt_config cfg;
    struct mg_mgr mgr;
    struct mqtt_sub *subs;
};


int mqtt_main(void *user_options);

#endif