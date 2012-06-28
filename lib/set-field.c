/*
 * Copyright (c) 2012 Isaku Yamahata <yamahata at private email ne jp>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <string.h>

#include "dynamic-string.h"
#include "meta-flow.h"
#include "odp-util.h"
#include "ofp-actions.h"
#include "openflow/openflow.h"
#include "openvswitch/types.h"
#include "set-field.h"

static bool
set_field_mf_allowed(const struct mf_field *mf)
{
    if (!mf->writable || mf->oxm_header == 0 /* TODO: check meta data */) {
        return false;
    }
    return true;
}

struct ofpact_reg_load*
set_field_put(const struct mf_field *mf, struct ofpbuf *ofpacts)
{
    struct ofpact_reg_load *load = ofpact_put_REG_LOAD(ofpacts);

    load->ofpact.compat = OFPUTIL_OFPAT12_SET_FIELD;
    load->dst.field = mf;
    load->dst.ofs = 0;
    load->dst.n_bits = mf->n_bits;
    return load;
}

void
set_field_parse(const char *s, struct ofpbuf *ofpacts)
{
    char *pos;
    char *copy;
    char *key;
    char *value_s;
    const struct mf_field *mf;
    struct ofpact_reg_load *load;

    pos = copy = xstrdup(s);
    if (!ofputil_parse_key_value(&pos, &key, &value_s)) {
        goto out;
    }
    mf = mf_from_name(key);
    if (!mf) {
        goto out;
    }
    if (!set_field_mf_allowed(mf)){
        goto out;
    }

    load = set_field_put(mf, ofpacts);
    if (mf_parse_value(mf, value_s, &load->value)) {
        goto out;
    }
    if (!mf_is_value_valid(mf, &load->value)) {
        goto out;
    }

out:
    free(copy);

    /* TODO:XXX error */
}

struct format_prefix {
    enum mf_field_id id;
    const char* prefix;
};
struct format_prefix format_prefix[] = {
    {
        .id = MFF_VLAN_VID,
        .prefix = "mod_vlan_vid",
    }, {
        .id = MFF_VLAN_PCP,
        .prefix = "mod_vlan_pcp",
    }, {
        .id = MFF_ETH_SRC,
        .prefix = "mod_dl_src",
    }, {
        .id = MFF_ETH_DST,
        .prefix = "mod_dl_dst",
    }, {
        .id = MFF_IPV4_SRC,
        .prefix = "mod_nw_src",
    }, {
        .id = MFF_IPV4_DST,
        .prefix = "mod_nw_dst",
    }, {
        .id = MFF_IP_DSCP,
        .prefix = "mod_nw_tos",
    },
};


void
set_field_format(const struct ofpact_reg_load *load, struct ds *s)
{
    struct format_prefix *fp;

    for (fp = format_prefix; fp < &format_prefix[ARRAY_SIZE(format_prefix)];
         fp++) {
        const struct mf_field *mf = load->dst.field;
        if (fp->id == mf->id) {
            ds_put_cstr(s, fp->prefix);
            ds_put_cstr(s, ":");
            mf_format(mf, &load->value, NULL, s);
            return;
        }
    }

    NOT_REACHED();
}

/* TODO:XXX udatapath case? */
