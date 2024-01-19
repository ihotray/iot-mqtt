#include <iot/iot.h>
#include "mqtt.h"


#define CA "/www/iot/certs/ca"
#define CERT "/www/iot/certs/server.cert"
#define KEY "/www/iot/certs/server.key"


static void usage(const char *prog) {
    fprintf(stderr,
            "IoT-SDK v.%s\n"
            "Usage: %s OPTIONS\n"
            "  -l ADDR   - listening address for mqtt communitcation, default: '%s'\n"
            "  -L ADDR   - listening address for mqtts communication, default: '%s'\n"
            "  -C CA     - ca content or file path for mqtts communication, default: '%s'\n"
            "  -c CERT   - cert content or file path for mqtts communication, default: '%s'\n"
            "  -k KEY    - cert key content or file path for mqtts communication, default: '%s'\n"
            "  -e 0|1    - mqtts enable, default: 0\n"
            "  -v LEVEL  - debug level, from 0 to 4, default: %d\n",
            MG_VERSION, prog, MQTT_LISTEN_ADDR, MQTTS_LISTEN_ADDR, CA, CERT, KEY, MG_LL_INFO);

    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {

    struct mqtt_option opts = {
        .mqtt_listening_address = MQTT_LISTEN_ADDR,
        .mqtts_listening_address = MQTTS_LISTEN_ADDR,
        .mqtts_enable = 0,
        .mqtts_ca = CA,
        .mqtts_cert = CERT,
        .mqtts_certkey = KEY,
        .debug_level = MG_LL_INFO
    };

    // Parse command-line flags
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0) {
            opts.mqtt_listening_address = argv[++i];
        } else if (strcmp(argv[i], "-L") == 0) {
            opts.mqtts_listening_address = argv[++i];
        }  else if (strcmp(argv[i], "-C") == 0) {
            opts.mqtts_ca = argv[++i];
        }  else if (strcmp(argv[i], "-c") == 0) {
            opts.mqtts_cert = argv[++i];
        }  else if (strcmp(argv[i], "-k") == 0) {
            opts.mqtts_certkey = argv[++i];
        } else if (strcmp(argv[i], "-e") == 0) {
            opts.mqtts_enable = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-v") == 0) {
            opts.debug_level = atoi(argv[++i]);
        } else {
            usage(argv[0]);
        }
    }

    MG_INFO(("IoT-SDK version  : v%s", MG_VERSION));
    MG_INFO(("Listening on     : %s", opts.mqtt_listening_address));
    if (opts.mqtts_enable)
        MG_INFO(("Listening on     : %s", opts.mqtts_listening_address));

    mqtt_main(&opts);
    
    return 0;
}