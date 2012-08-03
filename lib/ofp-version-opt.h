#ifndef OFP_VERSION_H
#define OFP_VERSION_H 1

#include <openflow/openflow-common.h>
#include "util.h"
#include "ofp-util.h"

#define OFP_VERSION_OPTION_ENUMS                \
    OPT_ALLOWED_OFP_VERSION

#define OFP_VERSION_LONG_OPTIONS                                           \
        {"version",     no_argument, NULL, 'V'},                           \
        {"allowed-ofp-versions", required_argument, NULL, OPT_ALLOWED_OFP_VERSION}

#define OFP_VERSION_OPTION_HANDLERS                                 \
        case 'V':                                                   \
            ovs_print_version(OFP10_VERSION, OFP12_VERSION);        \
            exit(EXIT_SUCCESS);                                     \
                                                                    \
        case OPT_ALLOWED_OFP_VERSION:                               \
            ofp_versions_from_string(optarg);                       \
            break;

uint32_t get_allowed_ofp_versions(void);
void ofp_version_usage(void);
void ofp_versions_from_string(const char *string);

#endif
