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

enum ofperr
set_field_put(struct ofpbuf *out, enum mf_field_id id, const void *valuep)
{
    struct ofpact_set_field *osf;
    osf = ofpact_put_SET_FIELD(out);
    osf->mf = mf_from_id(id);
    memcpy(&osf->value, valuep, osf->mf->n_bytes);

    if (!mf_is_value_valid(osf->mf, &osf->value)) {
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }
    return 0;
}

enum ofperr
set_field_check(const struct ofpact_set_field *osf,
                const struct flow *flow)
{
    if (!mf_are_prereqs_ok(osf->mf, flow)) {
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }
    // TODO:XXX?
    return 0;
}

static bool
set_field_mf_allowed(const struct mf_field *mf)
{
    if (!mf->writable || mf->oxm_header == 0 /* TODO: check meta data */) {
        return false;
    }
    return true;
}

enum ofperr
set_field_from_openflow(const struct ofp12_action_set_field* oasf,
                        struct ofpbuf *ofpacts)
{
    ovs_be32 *p = (ovs_be32*)oasf->field;
    uint32_t oxm_header = ntohl(*p);
    uint8_t oxm_length = NXM_LENGTH(oxm_header);
    struct ofpact_set_field *set_field = ofpact_put_SET_FIELD(ofpacts);
    const struct mf_field *mf;

    if (NXM_HASMASK(oxm_header)) {
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }
    if (oasf->len != ROUND_UP(sizeof(*oasf) + oxm_length,
                              OFP12_ACTION_SET_FIELD_ALIGN)) {
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }
    mf = mf_from_nxm_header(oxm_header);
    if (!set_field_mf_allowed(mf)) {
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }
    memcpy(&set_field->value, oasf + 1, mf->n_bytes);
    if (!mf_is_value_valid(mf, &set_field->value)) {
        return OFPERR_OFPBMC_BAD_VALUE;
    }

    set_field->mf = mf;
    return 0;
}

static void
set_field_put_value(void *valuep,  const struct ofpact_set_field *set_field)
{
    memcpy(valuep, &set_field->value, set_field->mf->n_bytes);
}

void
set_field_to_nxact(const struct ofpact_set_field *set_field,
                   struct ofpbuf *out)
{
    switch (set_field->mf->id) {
    case MFF_MPLS_LABEL:
        ofputil_put_NXAST_SET_MPLS_LABEL(out)->mpls_label =
            set_field->value.be32;
        break;
    case MFF_MPLS_TC:
        ofputil_put_NXAST_SET_MPLS_TC(out)->mpls_tc = set_field->value.be32;
        break;

    case MFF_TUN_ID:
    case MFF_IN_PORT:
    case MFF_REG0 ... MFF_REG_END:
    case MFF_ETH_SRC:
    case MFF_ETH_DST:
    case MFF_ETH_TYPE:
    case MFF_VLAN_TCI:
    case MFF_VLAN_VID:
    case MFF_VLAN_PCP:
    case MFF_VLAN_TPID:
    case MFF_VLAN_QINQ_VID:
    case MFF_VLAN_QINQ_PCP:
    case MFF_MPLS_STACK:
    case MFF_IPV4_SRC:
    case MFF_IPV4_DST:
    case MFF_IPV6_SRC:
    case MFF_IPV6_DST:
    case MFF_IPV6_LABEL:
    case MFF_IP_PROTO:
    case MFF_IP_DSCP:
    case MFF_IP_ECN:
    case MFF_IP_TTL:
    case MFF_IP_FRAG:
    case MFF_ARP_OP:
    case MFF_ARP_SPA:
    case MFF_ARP_TPA:
    case MFF_ARP_SHA:
    case MFF_ARP_THA:
    case MFF_TCP_SRC:
    case MFF_TCP_DST:
    case MFF_UDP_SRC:
    case MFF_UDP_DST:
    case MFF_ICMPV4_TYPE:
    case MFF_ICMPV4_CODE:
    case MFF_ICMPV6_TYPE:
    case MFF_ICMPV6_CODE:
    case MFF_ND_TARGET:
    case MFF_ND_SLL:
    case MFF_ND_TLL:
    case MFF_N_IDS:
    default:
        NOT_REACHED();
        break;
    }
}

bool
set_field_to_openflow10(const struct ofpact_set_field *set_field,
                        struct ofpbuf *out)
{
    switch (set_field->mf->id) {
    case MFF_VLAN_VID:
        set_field_put_value(&ofputil_put_OFPAT10_SET_VLAN_VID(out)->vlan_vid,
                            set_field);
        break;
    case MFF_VLAN_PCP:
        set_field_put_value(&ofputil_put_OFPAT10_SET_VLAN_PCP(out)->vlan_pcp,
                            set_field);
        break;
    case MFF_ETH_SRC:
        set_field_put_value(ofputil_put_OFPAT10_SET_DL_SRC(out)->dl_addr,
                            set_field);
        break;
    case MFF_ETH_DST:
        set_field_put_value(ofputil_put_OFPAT10_SET_DL_DST(out)->dl_addr,
                            set_field);
        break;
    case MFF_IPV4_SRC:
        set_field_put_value(&ofputil_put_OFPAT10_SET_NW_SRC(out)->nw_addr,
                            set_field);
        break;
    case MFF_IPV4_DST:
        set_field_put_value(&ofputil_put_OFPAT10_SET_NW_DST(out)->nw_addr,
                            set_field);
        break;


    case MFF_MPLS_LABEL:
    case MFF_MPLS_TC:
        /* for nx */
        return false;

    case MFF_TUN_ID:
    case MFF_IN_PORT:
    case MFF_REG0 ... MFF_REG_END:
    case MFF_ETH_TYPE:
    case MFF_VLAN_TCI:
    case MFF_VLAN_TPID:
    case MFF_VLAN_QINQ_VID:
    case MFF_VLAN_QINQ_PCP:
    case MFF_MPLS_STACK:
    case MFF_IPV6_SRC:
    case MFF_IPV6_DST:
    case MFF_IPV6_LABEL:
    case MFF_IP_PROTO:
    case MFF_IP_DSCP:
    case MFF_IP_ECN:
    case MFF_IP_TTL:
    case MFF_IP_FRAG:
    case MFF_ARP_OP:
    case MFF_ARP_SPA:
    case MFF_ARP_TPA:
    case MFF_ARP_SHA:
    case MFF_ARP_THA:
    case MFF_TCP_SRC:
    case MFF_TCP_DST:
    case MFF_UDP_SRC:
    case MFF_UDP_DST:
    case MFF_ICMPV4_TYPE:
    case MFF_ICMPV4_CODE:
    case MFF_ICMPV6_TYPE:
    case MFF_ICMPV6_CODE:
    case MFF_ND_TARGET:
    case MFF_ND_SLL:
    case MFF_ND_TLL:
    case MFF_N_IDS:
    default:
        NOT_REACHED();
    }

    return true;
}

bool
set_field_to_openflow11(const struct ofpact_set_field *set_field,
                        struct ofpbuf *out)
{
    switch (set_field->mf->id) {
    case MFF_VLAN_VID:
        set_field_put_value(&ofputil_put_OFPAT11_SET_VLAN_VID(out)->vlan_vid,
                            set_field);
        break;
    case MFF_VLAN_PCP:
        set_field_put_value(&ofputil_put_OFPAT11_SET_VLAN_PCP(out)->vlan_pcp,
                            set_field);
        break;
    case MFF_ETH_SRC:
        set_field_put_value(ofputil_put_OFPAT11_SET_DL_SRC(out)->dl_addr,
                            set_field);
        break;
    case MFF_ETH_DST:
        set_field_put_value(ofputil_put_OFPAT11_SET_DL_DST(out)->dl_addr,
                            set_field);
        break;
    case MFF_IPV4_SRC:
        set_field_put_value(&ofputil_put_OFPAT11_SET_NW_SRC(out)->nw_addr,
                            set_field);
        break;
    case MFF_IPV4_DST:
        set_field_put_value(&ofputil_put_OFPAT11_SET_NW_DST(out)->nw_addr,
                            set_field);
        break;

    case MFF_MPLS_LABEL:
    case MFF_MPLS_TC:
        /* fallback to NX */
        return false;

    case MFF_TUN_ID:
    case MFF_IN_PORT:
    case MFF_REG0 ... MFF_REG_END:
    case MFF_ETH_TYPE:
    case MFF_VLAN_TCI:
    case MFF_VLAN_TPID:
    case MFF_VLAN_QINQ_VID:
    case MFF_VLAN_QINQ_PCP:
    case MFF_MPLS_STACK:
    case MFF_IPV6_SRC:
    case MFF_IPV6_DST:
    case MFF_IPV6_LABEL:
    case MFF_IP_PROTO:
    case MFF_IP_DSCP:
    case MFF_IP_ECN:
    case MFF_IP_TTL:
    case MFF_IP_FRAG:
    case MFF_ARP_OP:
    case MFF_ARP_SPA:
    case MFF_ARP_TPA:
    case MFF_ARP_SHA:
    case MFF_ARP_THA:
    case MFF_TCP_SRC:
    case MFF_TCP_DST:
    case MFF_UDP_SRC:
    case MFF_UDP_DST:
    case MFF_ICMPV4_TYPE:
    case MFF_ICMPV4_CODE:
    case MFF_ICMPV6_TYPE:
    case MFF_ICMPV6_CODE:
    case MFF_ND_TARGET:
    case MFF_ND_SLL:
    case MFF_ND_TLL:
    case MFF_N_IDS:
    default:
        NOT_REACHED();
    }

    return true;
}

void
set_field_parse_with_id(enum mf_field_id id,
                        const char *arg, struct ofpbuf *ofpacts)
{
    const struct mf_field *mf = mf_from_id(id);
    struct ofpact_set_field *set_field = ofpact_put_SET_FIELD(ofpacts);
    const char *ret;
    set_field->mf = mf;

    if (!set_field_mf_allowed(mf)){
        ovs_fatal(0, "%s: field can't be written", mf->name);
    }
    ret = mf_parse_value(mf, arg, &set_field->value);
    if (ret) {
        ovs_fatal(0, "%s", ret);
    }
    if (!mf_is_value_valid(mf, &set_field->value)) {
        ovs_fatal(0, "%s: invalid field value for field %s", arg, mf->name);
    }
}

void
set_field_parse(const char *s, struct ofpbuf *ofpacts)
{
    char *pos;
    char *copy;
    char *key;
    char *value_s;
    const struct mf_field *mf;
    union mf_value value;
    struct ofpact_set_field *set_field;

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
    if (mf_parse_value(mf, value_s, &value)) {
        goto out;
    }
    if (!mf_is_value_valid(mf, &value)) {
        goto out;
    }
    set_field = ofpact_put_SET_FIELD(ofpacts);
    set_field->mf = mf;
    set_field->value = value;

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
    }, {
        .id = MFF_MPLS_LABEL,
        .prefix = "set_mpls_label",
    }, {
        .id = MFF_MPLS_TC,
        .prefix = "set_mpls_tc",
    }, {
        .id = MFF_MPLS_STACK,
        .prefix = "set_mpls_stack",
    },
};


void
set_field_format(const struct ofpact_set_field *set_field, struct ds *s)
{
    struct format_prefix *fp;

    for (fp = format_prefix; fp < &format_prefix[ARRAY_SIZE(format_prefix)];
         fp++) {
        if (fp->id == set_field->mf->id) {
            ds_put_cstr(s, fp->prefix);
            ds_put_cstr(s, ":");
            mf_format(set_field->mf, &set_field->value, NULL, s);
            return;
        }
    }

    NOT_REACHED();
}

void
set_field_execute(const struct ofpact_set_field *set_field,
                  struct flow *flow, struct flow *base_flow,
                  struct ofpbuf *odp_actions)
{
    switch (set_field->mf->id) {
    case MFF_IP_DSCP:
        /* OpenFlow 1.0 only supports IPv4. */
        /* TODO:XXX 1.1+ */
        if (flow->dl_type == htons(ETH_TYPE_IP)) {
            mf_set_flow_value(set_field->mf, &set_field->value, flow);
        }
        break;

    case MFF_MPLS_LABEL:
        mf_set_flow_value(set_field->mf, &set_field->value, flow);
        commit_mpls_lse_action(flow, base_flow, odp_actions);
        break;

    case MFF_MPLS_TC:
        mf_set_flow_value(set_field->mf, &set_field->value, flow);
        commit_mpls_lse_action(flow, base_flow, odp_actions);
        break;

    case MFF_ETH_SRC:
    case MFF_ETH_DST:
    case MFF_MPLS_STACK:
    case MFF_VLAN_VID:
    case MFF_VLAN_PCP:
    case MFF_IPV4_SRC:
    case MFF_IPV4_DST:
        mf_set_flow_value(set_field->mf, &set_field->value, flow);
        break;

    case MFF_ETH_TYPE:
    case MFF_VLAN_TCI:
    case MFF_IP_PROTO:
    case MFF_IP_ECN:
    case MFF_TCP_SRC:
    case MFF_TCP_DST:
    case MFF_UDP_SRC:
    case MFF_UDP_DST:
    case MFF_ARP_OP:
    case MFF_ARP_SPA:
    case MFF_ARP_TPA:
    case MFF_ARP_SHA:
    case MFF_ARP_THA:
    case MFF_IPV6_SRC:
    case MFF_IPV6_DST:
    case MFF_ICMPV4_TYPE:
    case MFF_ICMPV4_CODE:
    case MFF_ICMPV6_TYPE:
    case MFF_ICMPV6_CODE:
    case MFF_ND_TARGET:
    case MFF_ND_SLL:
    case MFF_ND_TLL:
        /* TODO:XXX */
        mf_set_flow_value(set_field->mf, &set_field->value, flow);
        break;

    case MFF_TUN_ID:
    case MFF_IN_PORT:
    case MFF_REG0 ... MFF_REG_END:
    case MFF_VLAN_TPID:
    case MFF_VLAN_QINQ_VID:
    case MFF_VLAN_QINQ_PCP:
    case MFF_IP_TTL:
    case MFF_IP_FRAG:
    case MFF_IPV6_LABEL:
    case MFF_N_IDS:
    default:
        NOT_REACHED();
        break;
    }
}

/* TODO:XXX udatapath case */
