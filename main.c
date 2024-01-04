#include <iot/iot.h>
#include "mqtt.h"


static const char *s_ca = "-----BEGIN CERTIFICATE-----\n"
"MIIDMTCCAhkCFDAPf8BhiI979coTUPtB87KuLJ4QMA0GCSqGSIb3DQEBCwUAMFQx\n"
"CzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRl\n"
"cm5ldCBXaWRnaXRzIFB0eSBMdGQxDTALBgNVBAMMBFJPT1QwIBcNMjIxMTA3MDI1\n"
"NjM0WhgPMjEyMjEwMTQwMjU2MzRaMFQxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApT\n"
"b21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQxDTAL\n"
"xIYX1VjKp9UZTdHEPQCCFPDlq9wXZczs67Rr5XRM5EpzO2OkpOFEla6M6VyMK17S\n"
"5WddwrUFKq4HmaFSW9TVTfqox42nXnRysq3Y0FeKktiLHy1KMyXYnHloZ3/QD/Vu\n"
"fWUrsPu5ECwLHrbwtXGeBBqlWXREqOc72bzJHVPi874MggMf/BHBbs6iM5TMSx+N\n"
"ZUsJZx6tGmEXKQSI6htRC8PqMVnTO4IvKEmU4yHImUKvhzjuZq530VvmF7ZMJBVg\n"
"Mhf2v1vXXBxCR+xB+r8U2rE/HXzdVcO0oa/zqOnOxzD8n0Rsns1UlcH86Wdaj6x4\n"
"7hY0aTg=\n"
"-----END CERTIFICATE-----\n";

static const char *s_cert = "-----BEGIN CERTIFICATE-----\n"
"MIIDMzCCAhsCFDkAgEpMXOjrLNnbytaj/XjCwgs1MA0GCSqGSIb3DQEBCwUAMFQx\n"
"CzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRl\n"
"cm5ldCBXaWRnaXRzIFB0eSBMdGQxDTALBgNVBAMMBFJPT1QwIBcNMjIxMTIzMDI0\n"
"OTA0WhgPMjEyMjEwMzAwMjQ5MDRaMFYxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApT\n"
"Jo96rkD25KwpYgTlYW8CAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAhZRJeN60Hsjs\n"
"gHJ7iEDOGioJ1DlmAC3dKpkbHnQSIwrKt191xJyh6K3z4Zc1KyGWpH9Ivj7AEacm\n"
"DeRn1TtJf3bA3FbiRNNgEkLJVAR87i93mZ/KOJ6rIocH2Pj4dK2cb5fLDXwX7AhI\n"
"/7GYIeJuxBTvajy8VPlW0Lrkbc9ADJl0h+MiqPe23kRfkAPGYOB8pH+OTjfz7BO1\n"
"KrJ1k9GyO6YdX13gnQ9u5eIZTzjI8Tmt1egs+bNfkw903vgkvq6DmI/LfG4YzUMC\n"
"KvhTgvJVaeoWQe17fK3JMmppfCNzkZlBiiZn4dO0M8B8FtY1fkBDF/P7uMMkE3j7\n"
"I0VutKd95w==\n"
"-----END CERTIFICATE-----\n";

static const char *s_certkey = "-----BEGIN RSA PRIVATE KEY-----\n"
"MIIEowIBAAKCAQEArSM1XBqSPC5LMe0HiFOtPR1MJmXqDg7otJOtPWphUEb5ci6f\n"
"PGJrn6gF6dtc+bi7BdEvB4kZukDc3U14iZnSwVPO2V+tCuHcIilQ7NJjn0qKJfpl\n"
"hfdeH/Iw46UFdU7nBv1vRCle5YTAtFXPJLpHAbP1C16zXCpGfcuB/0mOBYGrtDBN\n"
"3ht1/ezfEskJt072prkMh1kCCRsL6XI8ORZ+htKDa39Uec+RC7cXJemqmrcETLNQ\n"
"cxX2fDo24d3JsTZvpNkzvEf1LBHgAxPGNwbRDOwrSERi2rdz0tLYeulHTUQrCCN2\n"
"NfWvaNgJd2RqpROL1YzPlykCgYBoEG//++vWn7ucJwhwCYwDTLjLMGxIdh61Tux5\n"
"iuN49Tj/Hepd2sOsc3SnYHLGw3LtuX3ziJeHH4YjmyJddgnSC8CzT0r0N1HNHfO4\n"
"pgeXeHorQQe8zID7+WJb/E1T0hKO8xKpjG3JIZM/+/i/VA81KT/usKAoGUDgRj0W\n"
"27KbCQKBgAFglZ/jSgcAxORknm4e75eGfExmY7VKF1yCzUBQ1IYoAAhEJQdmEEsj\n"
"C/YkFnxAyFCFomxQadiWNYy7Z7IyATZ6RlhHqx4wouHGYHXqSk+0iySxiWkJCyYB\n"
"1PZ5VvU83vu8ciHQi1qZF6qtmwgMS/EhXkWyrDU6KBzWjR2YsUjF\n"
"-----END RSA PRIVATE KEY-----\n";


static void usage(const char *prog) {
    fprintf(stderr,
            "IoT-SDK v.%s\n"
            "Usage: %s OPTIONS\n"
            "  -l ADDR   - listening address for mqtt communitcation, default: '%s'\n"
            "  -L ADDR   - listening address for mqtts communication, default: '%s'\n"
            "  -e 0|1    - mqtts enable, default: 1\n"
            "  -v LEVEL  - debug level, from 0 to 4, default: %d\n",
            MG_VERSION, prog, MQTT_LISTEN_ADDR, MQTTS_LISTEN_ADDR, MG_LL_INFO);

    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {

    struct mqtt_option opts = {
		.mqtt_listening_address = MQTT_LISTEN_ADDR,
        .mqtts_listening_address = MQTTS_LISTEN_ADDR,
        .mqtts_enable = 1,
        .mqtts_ca = s_ca,
        .mqtts_cert = s_cert,
        .mqtts_certkey = s_certkey,
        .debug_level = MG_LL_INFO
	};

    // Parse command-line flags
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0) {
            opts.mqtt_listening_address = argv[++i];
        } else if (strcmp(argv[i], "-L") == 0) {
            opts.mqtts_listening_address = argv[++i];
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