#include <config.h>
#include "ofp-util.h"
#include "ofp-version-opt.h"
#include "vlog.h"
#include "dynamic-string.h"

VLOG_DEFINE_THIS_MODULE(ofp_version);

static uint32_t allowed_versions = 0;
static bool allowed_versions_set = false;

uint32_t
get_allowed_ofp_versions(void)
{
    if (!allowed_versions_set) {
        return ofputil_get_allowed_versions_default();
    }
    return allowed_versions;
}

void
ofp_version_usage(void)
{
    struct ds msg = DS_EMPTY_INITIALIZER;

    ofputil_format_version_bitmap_names(&msg,
                                        ofputil_get_allowed_versions_default());
    printf(
        "\nOpen Flow Version options:\n"
        "  -V, --version           display version information\n"
        "  --allowed-ofp-versions  list of allowed Open Flow versions\n"
        "                          (default: %s)\n",
        ds_cstr(&msg));
    ds_destroy(&msg);
}

void
ofp_versions_from_string(const char *string)
{
    allowed_versions = ofputil_versions_from_string(string);
    allowed_versions_set = true;
}
