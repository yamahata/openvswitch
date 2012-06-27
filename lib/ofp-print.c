/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012 Nicira, Inc.
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

#include <config.h>
#include "ofp-print.h"

#include <errno.h>
#include <inttypes.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>

#include "bundle.h"
#include "byte-order.h"
#include "compiler.h"
#include "dynamic-string.h"
#include "flow.h"
#include "learn.h"
#include "multipath.h"
#include "meta-flow.h"
#include "netdev.h"
#include "nx-match.h"
#include "ofp-actions.h"
#include "ofp-errors.h"
#include "ofp-util.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "openflow/nicira-ext.h"
#include "packets.h"
#include "pcap.h"
#include "type-props.h"
#include "unaligned.h"
#include "util.h"

static void ofp_print_queue_name(struct ds *string, uint32_t port);
static void ofp_print_error(struct ds *, enum ofperr);


/* Returns a string that represents the contents of the Ethernet frame in the
 * 'len' bytes starting at 'data'.  The caller must free the returned string.*/
char *
ofp_packet_to_string(const void *data, size_t len)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    struct ofpbuf buf;
    struct flow flow;

    ofpbuf_use_const(&buf, data, len);
    flow_extract(&buf, 0, 0, 0, &flow);
    flow_format(&ds, &flow);

    if (buf.l7) {
        if (flow.nw_proto == IPPROTO_TCP) {
            struct tcp_header *th = buf.l4;
            ds_put_format(&ds, " tcp_csum:%"PRIx16,
                          ntohs(th->tcp_csum));
        } else if (flow.nw_proto == IPPROTO_UDP) {
            struct udp_header *uh = buf.l4;
            ds_put_format(&ds, " udp_csum:%"PRIx16,
                          ntohs(uh->udp_csum));
        }
    }

    ds_put_char(&ds, '\n');

    return ds_cstr(&ds);
}

static void
ofp_print_packet_in(struct ds *string, const struct ofp_header *oh,
                    int verbosity)
{
    struct ofputil_packet_in pin;
    int error;
    int i;

    error = ofputil_decode_packet_in(&pin, oh);
    if (error) {
        ofp_print_error(string, error);
        return;
    }

    if (pin.table_id) {
        ds_put_format(string, " table_id=%"PRIu8, pin.table_id);
    }

    if (pin.cookie) {
        ds_put_format(string, " cookie=0x%"PRIx64, ntohll(pin.cookie));
    }

    ds_put_format(string, " total_len=%"PRIu16" in_port=", pin.total_len);
    ofputil_format_port(pin.fmd.in_port, string);

    if (pin.fmd.tun_id_mask) {
        ds_put_format(string, " tun_id=0x%"PRIx64, ntohll(pin.fmd.tun_id));
        if (pin.fmd.tun_id_mask != htonll(UINT64_MAX)) {
            ds_put_format(string, "/0x%"PRIx64, ntohll(pin.fmd.tun_id_mask));
        }
    }

    for (i = 0; i < FLOW_N_REGS; i++) {
        if (pin.fmd.reg_masks[i]) {
            ds_put_format(string, " reg%d=0x%"PRIx32, i, pin.fmd.regs[i]);
            if (pin.fmd.reg_masks[i] != UINT32_MAX) {
                ds_put_format(string, "/0x%"PRIx32, pin.fmd.reg_masks[i]);
            }
        }
    }

    ds_put_format(string, " (via %s)",
                  ofputil_packet_in_reason_to_string(pin.reason));

    ds_put_format(string, " data_len=%zu", pin.packet_len);
    if (pin.buffer_id == UINT32_MAX) {
        ds_put_format(string, " (unbuffered)");
        if (pin.total_len != pin.packet_len) {
            ds_put_format(string, " (***total_len != data_len***)");
        }
    } else {
        ds_put_format(string, " buffer=0x%08"PRIx32, pin.buffer_id);
        if (pin.total_len < pin.packet_len) {
            ds_put_format(string, " (***total_len < data_len***)");
        }
    }
    ds_put_char(string, '\n');

    if (verbosity > 0) {
        char *packet = ofp_packet_to_string(pin.packet, pin.packet_len);
        ds_put_cstr(string, packet);
        free(packet);
    }
}

static void
ofp_print_packet_out(struct ds *string, const struct ofp_header *oh,
                     int verbosity)
{
    struct ofputil_packet_out po;
    struct ofpbuf ofpacts;
    enum ofperr error;

    ofpbuf_init(&ofpacts, 64);
    error = ofputil_decode_packet_out(&po, oh, &ofpacts);
    if (error) {
        ofpbuf_uninit(&ofpacts);
        ofp_print_error(string, error);
        return;
    }

    ds_put_cstr(string, " in_port=");
    ofputil_format_port(po.in_port, string);

    ds_put_char(string, ' ');
    ofpacts_format(po.ofpacts, string);

    if (po.buffer_id == UINT32_MAX) {
        ds_put_format(string, " data_len=%zu", po.packet_len);
        if (verbosity > 0 && po.packet_len > 0) {
            char *packet = ofp_packet_to_string(po.packet, po.packet_len);
            ds_put_char(string, '\n');
            ds_put_cstr(string, packet);
            free(packet);
        }
    } else {
        ds_put_format(string, " buffer=0x%08"PRIx32, po.buffer_id);
    }
    ds_put_char(string, '\n');

    ofpbuf_uninit(&ofpacts);
}

/* qsort comparison function. */
static int
compare_ports(const void *a_, const void *b_)
{
    const struct ofputil_phy_port *a = a_;
    const struct ofputil_phy_port *b = b_;
    uint16_t ap = a->port_no;
    uint16_t bp = b->port_no;

    return ap < bp ? -1 : ap > bp;
}

static void
ofp_print_bit_names(struct ds *string, uint32_t bits,
                    const char *(*bit_to_name)(uint32_t bit))
{
    int n = 0;
    int i;

    if (!bits) {
        ds_put_cstr(string, "0");
        return;
    }

    for (i = 0; i < 32; i++) {
        uint32_t bit = UINT32_C(1) << i;

        if (bits & bit) {
            const char *name = bit_to_name(bit);
            if (name) {
                if (n++) {
                    ds_put_char(string, ' ');
                }
                ds_put_cstr(string, name);
                bits &= ~bit;
            }
        }
    }

    if (bits) {
        if (n) {
            ds_put_char(string, ' ');
        }
        ds_put_format(string, "0x%"PRIx32, bits);
    }
}

static const char *
netdev_feature_to_name(uint32_t bit)
{
    enum netdev_features f = bit;

    switch (f) {
    case NETDEV_F_10MB_HD:    return "10MB-HD";
    case NETDEV_F_10MB_FD:    return "10MB-FD";
    case NETDEV_F_100MB_HD:   return "100MB-HD";
    case NETDEV_F_100MB_FD:   return "100MB-FD";
    case NETDEV_F_1GB_HD:     return "1GB-HD";
    case NETDEV_F_1GB_FD:     return "1GB-FD";
    case NETDEV_F_10GB_FD:    return "10GB-FD";
    case NETDEV_F_40GB_FD:    return "40GB-FD";
    case NETDEV_F_100GB_FD:   return "100GB-FD";
    case NETDEV_F_1TB_FD:     return "1TB-FD";
    case NETDEV_F_OTHER:      return "OTHER";
    case NETDEV_F_COPPER:     return "COPPER";
    case NETDEV_F_FIBER:      return "FIBER";
    case NETDEV_F_AUTONEG:    return "AUTO_NEG";
    case NETDEV_F_PAUSE:      return "AUTO_PAUSE";
    case NETDEV_F_PAUSE_ASYM: return "AUTO_PAUSE_ASYM";
    }

    return NULL;
}

static void
ofp_print_port_features(struct ds *string, enum netdev_features features)
{
    ofp_print_bit_names(string, features, netdev_feature_to_name);
    ds_put_char(string, '\n');
}

static const char *
ofputil_port_config_to_name(uint32_t bit)
{
    enum ofputil_port_config pc = bit;

    switch (pc) {
    case OFPUTIL_PC_PORT_DOWN:    return "PORT_DOWN";
    case OFPUTIL_PC_NO_STP:       return "NO_STP";
    case OFPUTIL_PC_NO_RECV:      return "NO_RECV";
    case OFPUTIL_PC_NO_RECV_STP:  return "NO_RECV_STP";
    case OFPUTIL_PC_NO_FLOOD:     return "NO_FLOOD";
    case OFPUTIL_PC_NO_FWD:       return "NO_FWD";
    case OFPUTIL_PC_NO_PACKET_IN: return "NO_PACKET_IN";
    }

    return NULL;
}

static void
ofp_print_port_config(struct ds *string, enum ofputil_port_config config)
{
    ofp_print_bit_names(string, config, ofputil_port_config_to_name);
    ds_put_char(string, '\n');
}

static const char *
ofputil_port_state_to_name(uint32_t bit)
{
    enum ofputil_port_state ps = bit;

    switch (ps) {
    case OFPUTIL_PS_LINK_DOWN: return "LINK_DOWN";
    case OFPUTIL_PS_BLOCKED:   return "BLOCKED";
    case OFPUTIL_PS_LIVE:      return "LIVE";

    case OFPUTIL_PS_STP_LISTEN:
    case OFPUTIL_PS_STP_LEARN:
    case OFPUTIL_PS_STP_FORWARD:
    case OFPUTIL_PS_STP_BLOCK:
        /* Handled elsewhere. */
        return NULL;
    }

    return NULL;
}

static void
ofp_print_port_state(struct ds *string, enum ofputil_port_state state)
{
    enum ofputil_port_state stp_state;

    /* The STP state is a 2-bit field so it doesn't fit in with the bitmask
     * pattern.  We have to special case it.
     *
     * OVS doesn't support STP, so this field will always be 0 if we are
     * talking to OVS, so we'd always print STP_LISTEN in that case.
     * Therefore, we don't print anything at all if the value is STP_LISTEN, to
     * avoid confusing users. */
    stp_state = state & OFPUTIL_PS_STP_MASK;
    if (stp_state) {
        ds_put_cstr(string,
                    (stp_state == OFPUTIL_PS_STP_LEARN ? "STP_LEARN"
                     : stp_state == OFPUTIL_PS_STP_FORWARD ? "STP_FORWARD"
                     : "STP_BLOCK"));
        state &= ~OFPUTIL_PS_STP_MASK;
        if (state) {
            ofp_print_bit_names(string, state, ofputil_port_state_to_name);
        }
    } else {
        ofp_print_bit_names(string, state, ofputil_port_state_to_name);
    }
    ds_put_char(string, '\n');
}

static void
ofp_print_phy_port(struct ds *string, const struct ofputil_phy_port *port)
{
    char name[sizeof port->name];
    int j;

    memcpy(name, port->name, sizeof name);
    for (j = 0; j < sizeof name - 1; j++) {
        if (!isprint((unsigned char) name[j])) {
            break;
        }
    }
    name[j] = '\0';

    ds_put_char(string, ' ');
    ofputil_format_port(port->port_no, string);
    ds_put_format(string, "(%s): addr:"ETH_ADDR_FMT"\n",
                  name, ETH_ADDR_ARGS(port->hw_addr));

    ds_put_cstr(string, "     config:     ");
    ofp_print_port_config(string, port->config);

    ds_put_cstr(string, "     state:      ");
    ofp_print_port_state(string, port->state);

    if (port->curr) {
        ds_put_format(string, "     current:    ");
        ofp_print_port_features(string, port->curr);
    }
    if (port->advertised) {
        ds_put_format(string, "     advertised: ");
        ofp_print_port_features(string, port->advertised);
    }
    if (port->supported) {
        ds_put_format(string, "     supported:  ");
        ofp_print_port_features(string, port->supported);
    }
    if (port->peer) {
        ds_put_format(string, "     peer:       ");
        ofp_print_port_features(string, port->peer);
    }
    ds_put_format(string, "     speed: %"PRIu32" Mbps now, "
                  "%"PRIu32" Mbps max\n",
                  port->curr_speed / UINT32_C(1000),
                  port->max_speed / UINT32_C(1000));
}

/* Given a buffer 'b' that contains an array of OpenFlow ports of type
 * 'ofp_version', writes a detailed description of each port into
 * 'string'. */
static void
ofp_print_phy_ports(struct ds *string, uint8_t ofp_version,
                    struct ofpbuf *b)
{
    size_t n_ports;
    struct ofputil_phy_port *ports;
    enum ofperr error;
    size_t i;

    n_ports = ofputil_count_phy_ports(ofp_version, b);

    ports = xmalloc(n_ports * sizeof *ports);
    for (i = 0; i < n_ports; i++) {
        error = ofputil_pull_phy_port(ofp_version, b, &ports[i]);
        if (error) {
            ofp_print_error(string, error);
            goto exit;
        }
    }
    qsort(ports, n_ports, sizeof *ports, compare_ports);
    for (i = 0; i < n_ports; i++) {
        ofp_print_phy_port(string, &ports[i]);
    }

exit:
    free(ports);
}

static const char *
ofputil_capabilities_to_name(uint32_t bit)
{
    enum ofputil_capabilities capabilities = bit;

    switch (capabilities) {
    case OFPUTIL_C_FLOW_STATS:   return "FLOW_STATS";
    case OFPUTIL_C_TABLE_STATS:  return "TABLE_STATS";
    case OFPUTIL_C_PORT_STATS:   return "PORT_STATS";
    case OFPUTIL_C_IP_REASM:     return "IP_REASM";
    case OFPUTIL_C_QUEUE_STATS:  return "QUEUE_STATS";
    case OFPUTIL_C_ARP_MATCH_IP: return "ARP_MATCH_IP";
    case OFPUTIL_C_STP:          return "STP";
    case OFPUTIL_C_GROUP_STATS:  return "GROUP_STATS";
    case OFPUTIL_C_PORT_BLOCKED: return "PORT_BLOCKED";
    }

    return NULL;
}

static const char *
ofputil_action_bitmap_to_name(uint32_t bit)
{
    enum ofputil_action_bitmap action = bit;

    switch (action) {
    case OFPUTIL_A_OUTPUT:         return "OUTPUT";
    case OFPUTIL_A_SET_VLAN_VID:   return "SET_VLAN_VID";
    case OFPUTIL_A_SET_VLAN_PCP:   return "SET_VLAN_PCP";
    case OFPUTIL_A_STRIP_VLAN:     return "STRIP_VLAN";
    case OFPUTIL_A_SET_DL_SRC:     return "SET_DL_SRC";
    case OFPUTIL_A_SET_DL_DST:     return "SET_DL_DST";
    case OFPUTIL_A_SET_NW_SRC:     return "SET_NW_SRC";
    case OFPUTIL_A_SET_NW_DST:     return "SET_NW_DST";
    case OFPUTIL_A_SET_NW_ECN:     return "SET_NW_ECN";
    case OFPUTIL_A_SET_NW_TOS:     return "SET_NW_TOS";
    case OFPUTIL_A_SET_TP_SRC:     return "SET_TP_SRC";
    case OFPUTIL_A_SET_TP_DST:     return "SET_TP_DST";
    case OFPUTIL_A_ENQUEUE:        return "ENQUEUE";
    case OFPUTIL_A_COPY_TTL_OUT:   return "COPY_TTL_OUT";
    case OFPUTIL_A_COPY_TTL_IN:    return "COPY_TTL_IN";
    case OFPUTIL_A_SET_MPLS_LABEL: return "SET_MPLS_LABEL";
    case OFPUTIL_A_SET_MPLS_TC:    return "SET_MPLS_TC";
    case OFPUTIL_A_SET_MPLS_TTL:   return "SET_MPLS_TTL";
    case OFPUTIL_A_DEC_MPLS_TTL:   return "DEC_MPLS_TTL";
    case OFPUTIL_A_PUSH_VLAN:      return "PUSH_VLAN";
    case OFPUTIL_A_POP_VLAN:       return "POP_VLAN";
    case OFPUTIL_A_PUSH_MPLS:      return "PUSH_MPLS";
    case OFPUTIL_A_POP_MPLS:       return "POP_MPLS";
    case OFPUTIL_A_SET_QUEUE:      return "SET_QUEUE";
    case OFPUTIL_A_GROUP:          return "GROUP";
    case OFPUTIL_A_SET_NW_TTL:     return "SET_NW_TTL";
    case OFPUTIL_A_DEC_NW_TTL:     return "DEC_NW_TTL";
    }

    return NULL;
}

static void
ofp_print_switch_features(struct ds *string,
                          const struct ofp_switch_features *osf)
{
    struct ofputil_switch_features features;
    enum ofperr error;
    struct ofpbuf b;

    error = ofputil_decode_switch_features(osf, &features, &b);
    if (error) {
        ofp_print_error(string, error);
        return;
    }

    ds_put_format(string, " dpid:%016"PRIx64"\n", features.datapath_id);
    ds_put_format(string, "n_tables:%"PRIu8", n_buffers:%"PRIu32"\n",
                  features.n_tables, features.n_buffers);

    ds_put_cstr(string, "capabilities: ");
    ofp_print_bit_names(string, features.capabilities,
                        ofputil_capabilities_to_name);
    ds_put_char(string, '\n');

    ds_put_cstr(string, "actions: ");
    ofp_print_bit_names(string, features.actions,
                        ofputil_action_bitmap_to_name);
    ds_put_char(string, '\n');

    ofp_print_phy_ports(string, osf->header.version, &b);
}

static void
ofp_print_switch_config(struct ds *string, const struct ofp_switch_config *osc)
{
    enum ofp_config_flags flags;

    flags = ntohs(osc->flags);

    ds_put_format(string, " frags=%s", ofputil_frag_handling_to_string(flags));
    flags &= ~OFPC_FRAG_MASK;

    if (flags & OFPC_INVALID_TTL_TO_CONTROLLER) {
        ds_put_format(string, " invalid_ttl_to_controller");
        flags &= ~OFPC_INVALID_TTL_TO_CONTROLLER;
    }

    if (flags) {
        ds_put_format(string, " ***unknown flags 0x%04"PRIx16"***", flags);
    }

    ds_put_format(string, " miss_send_len=%"PRIu16"\n", ntohs(osc->miss_send_len));
}

static void print_wild(struct ds *string, const char *leader, int is_wild,
            int verbosity, const char *format, ...)
            __attribute__((format(printf, 5, 6)));

static void print_wild(struct ds *string, const char *leader, int is_wild,
                       int verbosity, const char *format, ...)
{
    if (is_wild && verbosity < 2) {
        return;
    }
    ds_put_cstr(string, leader);
    if (!is_wild) {
        va_list args;

        va_start(args, format);
        ds_put_format_valist(string, format, args);
        va_end(args);
    } else {
        ds_put_char(string, '*');
    }
    ds_put_char(string, ',');
}

static void
print_ip_netmask(struct ds *string, const char *leader, ovs_be32 ip,
                 uint32_t wild_bits, int verbosity)
{
    if (wild_bits >= 32 && verbosity < 2) {
        return;
    }
    ds_put_cstr(string, leader);
    if (wild_bits < 32) {
        ds_put_format(string, IP_FMT, IP_ARGS(&ip));
        if (wild_bits) {
            ds_put_format(string, "/%d", 32 - wild_bits);
        }
    } else {
        ds_put_char(string, '*');
    }
    ds_put_char(string, ',');
}

void
ofp10_match_print(struct ds *f, const struct ofp10_match *om, int verbosity)
{
    char *s = ofp10_match_to_string(om, verbosity);
    ds_put_cstr(f, s);
    free(s);
}

char *
ofp10_match_to_string(const struct ofp10_match *om, int verbosity)
{
    struct ds f = DS_EMPTY_INITIALIZER;
    uint32_t w = ntohl(om->wildcards);
    bool skip_type = false;
    bool skip_proto = false;

    if (!(w & OFPFW10_DL_TYPE)) {
        skip_type = true;
        if (om->dl_type == htons(ETH_TYPE_IP)) {
            if (!(w & OFPFW10_NW_PROTO)) {
                skip_proto = true;
                if (om->nw_proto == IPPROTO_ICMP) {
                    ds_put_cstr(&f, "icmp,");
                } else if (om->nw_proto == IPPROTO_TCP) {
                    ds_put_cstr(&f, "tcp,");
                } else if (om->nw_proto == IPPROTO_UDP) {
                    ds_put_cstr(&f, "udp,");
                } else {
                    ds_put_cstr(&f, "ip,");
                    skip_proto = false;
                }
            } else {
                ds_put_cstr(&f, "ip,");
            }
        } else if (om->dl_type == htons(ETH_TYPE_ARP)) {
            ds_put_cstr(&f, "arp,");
        } else {
            skip_type = false;
        }
    }
    print_wild(&f, "in_port=", w & OFPFW10_IN_PORT, verbosity,
               "%d", ntohs(om->in_port));
    print_wild(&f, "dl_vlan=", w & OFPFW10_DL_VLAN, verbosity,
               "%d", ntohs(om->dl_vlan));
    print_wild(&f, "dl_vlan_pcp=", w & OFPFW10_DL_VLAN_PCP, verbosity,
               "%d", om->dl_vlan_pcp);
    print_wild(&f, "dl_src=", w & OFPFW10_DL_SRC, verbosity,
               ETH_ADDR_FMT, ETH_ADDR_ARGS(om->dl_src));
    print_wild(&f, "dl_dst=", w & OFPFW10_DL_DST, verbosity,
               ETH_ADDR_FMT, ETH_ADDR_ARGS(om->dl_dst));
    if (!skip_type) {
        print_wild(&f, "dl_type=", w & OFPFW10_DL_TYPE, verbosity,
                   "0x%04x", ntohs(om->dl_type));
    }
    print_ip_netmask(&f, "nw_src=", om->nw_src,
                     (w & OFPFW10_NW_SRC_MASK) >> OFPFW10_NW_SRC_SHIFT,
                     verbosity);
    print_ip_netmask(&f, "nw_dst=", om->nw_dst,
                     (w & OFPFW10_NW_DST_MASK) >> OFPFW10_NW_DST_SHIFT,
                     verbosity);
    if (!skip_proto) {
        if (om->dl_type == htons(ETH_TYPE_ARP)) {
            print_wild(&f, "arp_op=", w & OFPFW10_NW_PROTO, verbosity,
                       "%u", om->nw_proto);
        } else {
            print_wild(&f, "nw_proto=", w & OFPFW10_NW_PROTO, verbosity,
                       "%u", om->nw_proto);
        }
    }
    print_wild(&f, "nw_tos=", w & OFPFW10_NW_TOS, verbosity,
               "%u", om->nw_tos);
    if (om->nw_proto == IPPROTO_ICMP) {
        print_wild(&f, "icmp_type=", w & OFPFW10_ICMP_TYPE, verbosity,
                   "%d", ntohs(om->tp_src));
        print_wild(&f, "icmp_code=", w & OFPFW10_ICMP_CODE, verbosity,
                   "%d", ntohs(om->tp_dst));
    } else {
        print_wild(&f, "tp_src=", w & OFPFW10_TP_SRC, verbosity,
                   "%d", ntohs(om->tp_src));
        print_wild(&f, "tp_dst=", w & OFPFW10_TP_DST, verbosity,
                   "%d", ntohs(om->tp_dst));
    }
    if (ds_last(&f) == ',') {
        f.length--;
    }
    return ds_cstr(&f);
}

static void
ofp_print_flow_mod(struct ds *s, const struct ofp_header *oh)
{
    struct ofputil_flow_mod fm;
    struct ofpbuf ofpacts;
    enum ofperr error;
    enum ofputil_protocol protocol;

    switch(oh->version) {
    case OFP10_VERSION:
          protocol = OFPUTIL_P_OF10_TID;
          break;
    default:
          protocol = ofputil_protocol_from_ofp_version(oh->version);
          break;
    }

    ofpbuf_init(&ofpacts, 64);
    error = ofputil_decode_flow_mod(&fm, oh, protocol, &ofpacts);
    if (error) {
        ofpbuf_uninit(&ofpacts);
        ofp_print_error(s, error);
        return;
    }

    ds_put_char(s, ' ');
    switch (fm.command) {
    case OFPFC_ADD:
        ds_put_cstr(s, "ADD");
        break;
    case OFPFC_MODIFY:
        ds_put_cstr(s, "MOD");
        break;
    case OFPFC_MODIFY_STRICT:
        ds_put_cstr(s, "MOD_STRICT");
        break;
    case OFPFC_DELETE:
        ds_put_cstr(s, "DEL");
        break;
    case OFPFC_DELETE_STRICT:
        ds_put_cstr(s, "DEL_STRICT");
        break;
    default:
        ds_put_format(s, "cmd:%d", fm.command);
    }
    if (fm.table_id != 0) {
        ds_put_format(s, " table:%d", fm.table_id);
    }

    ds_put_char(s, ' ');
    cls_rule_format(&fm.cr, s);

    if (ds_last(s) != ' ') {
        ds_put_char(s, ' ');
    }
    if (fm.new_cookie != htonll(0)) {
        ds_put_format(s, "cookie:0x%"PRIx64" ", ntohll(fm.new_cookie));
    }
    if (fm.cookie_mask != htonll(0)) {
        ds_put_format(s, "cookie:0x%"PRIx64"/0x%"PRIx64" ",
                ntohll(fm.cookie), ntohll(fm.cookie_mask));
    }
    if (fm.idle_timeout != OFP_FLOW_PERMANENT) {
        ds_put_format(s, "idle:%"PRIu16" ", fm.idle_timeout);
    }
    if (fm.hard_timeout != OFP_FLOW_PERMANENT) {
        ds_put_format(s, "hard:%"PRIu16" ", fm.hard_timeout);
    }
    if (fm.buffer_id != UINT32_MAX) {
        ds_put_format(s, "buf:0x%"PRIx32" ", fm.buffer_id);
    }
    if (fm.flags != 0) {
        uint16_t flags = fm.flags;

        if (flags & OFPFF_SEND_FLOW_REM) {
            ds_put_cstr(s, "send_flow_rem ");
        }
        if (flags & OFPFF_CHECK_OVERLAP) {
            ds_put_cstr(s, "check_overlap ");
        }
        if (flags & OFPFF10_EMERG) {
            ds_put_cstr(s, "emerg ");
        }

        flags &= ~(OFPFF_SEND_FLOW_REM | OFPFF_CHECK_OVERLAP | OFPFF10_EMERG);
        if (flags) {
            ds_put_format(s, "flags:0x%"PRIx16" ", flags);
        }
    }

    ofpacts_format(fm.ofpacts, s);
    ofpbuf_uninit(&ofpacts);
}

static void
ofp_print_duration(struct ds *string, unsigned int sec, unsigned int nsec)
{
    ds_put_format(string, "%u", sec);
    if (nsec > 0) {
        ds_put_format(string, ".%09u", nsec);
        while (string->string[string->length - 1] == '0') {
            string->length--;
        }
    }
    ds_put_char(string, 's');
}

static const char *
ofp_flow_removed_reason_to_string(enum ofp_flow_removed_reason reason)
{
    static char s[32];

    switch (reason) {
    case OFPRR_IDLE_TIMEOUT:
        return "idle";
    case OFPRR_HARD_TIMEOUT:
        return "hard";
    case OFPRR_DELETE:
        return "delete";
    case OFPRR_GROUP_DELETE:
        return "group_delete";
    default:
        sprintf(s, "%d", (int) reason);
        return s;
    }
}

static void
ofp_print_flow_removed(struct ds *string, const struct ofp_header *oh)
{
    struct ofputil_flow_removed fr;
    enum ofperr error;

    error = ofputil_decode_flow_removed(&fr, oh);
    if (error) {
        ofp_print_error(string, error);
        return;
    }

    ds_put_char(string, ' ');
    cls_rule_format(&fr.rule, string);

    ds_put_format(string, " reason=%s",
                  ofp_flow_removed_reason_to_string(fr.reason));

    if (fr.cookie != htonll(0)) {
        ds_put_format(string, " cookie:0x%"PRIx64, ntohll(fr.cookie));
    }
    ds_put_cstr(string, " duration");
    ofp_print_duration(string, fr.duration_sec, fr.duration_nsec);
    ds_put_format(string, " idle%"PRIu16" pkts%"PRIu64" bytes%"PRIu64"\n",
         fr.idle_timeout, fr.packet_count, fr.byte_count);
}

static void
ofp_print_port_mod(struct ds *string, const struct ofp_header *oh)
{
    struct ofputil_port_mod pm;
    enum ofperr error;

    error = ofputil_decode_port_mod(oh, &pm);
    if (error) {
        ofp_print_error(string, error);
        return;
    }

    ds_put_format(string, "port: %"PRIu16": addr:"ETH_ADDR_FMT"\n",
                  pm.port_no, ETH_ADDR_ARGS(pm.hw_addr));

    ds_put_format(string, "     config: ");
    ofp_print_port_config(string, pm.config);

    ds_put_format(string, "     mask:   ");
    ofp_print_port_config(string, pm.mask);

    ds_put_format(string, "     advertise: ");
    if (pm.advertise) {
        ofp_print_port_features(string, pm.advertise);
    } else {
        ds_put_format(string, "UNCHANGED\n");
    }
}

static void
ofp_print_error(struct ds *string, enum ofperr error)
{
    if (string->length) {
        ds_put_char(string, ' ');
    }
    ds_put_format(string, "***decode error: %s***\n", ofperr_get_name(error));
}

static void
ofp_print_error_msg(struct ds *string, const struct ofp_error_msg *oem)
{
    size_t len = ntohs(oem->header.length);
    size_t payload_ofs, payload_len;
    const void *payload;
    enum ofperr error;
    char *s;

    error = ofperr_decode_msg(&oem->header, &payload_ofs);
    if (!error) {
        ds_put_cstr(string, "***decode error***");
        ds_put_hex_dump(string, oem->data, len - sizeof *oem, 0, true);
        return;
    }

    ds_put_format(string, " %s\n", ofperr_get_name(error));

    payload = (const uint8_t *) oem + payload_ofs;
    payload_len = len - payload_ofs;
    if (error == OFPERR_OFPHFC_INCOMPATIBLE || error == OFPERR_OFPHFC_EPERM) {
        ds_put_printable(string, payload, payload_len);
    } else {
        s = ofp_to_string(payload, payload_len, 1);
        ds_put_cstr(string, s);
        free(s);
    }
}

static void
ofp_print_port_status(struct ds *string, const struct ofp_port_status *ops)
{
    struct ofputil_port_status ps;
    enum ofperr error;

    error = ofputil_decode_port_status(ops, &ps);
    if (error) {
        ofp_print_error(string, error);
        return;
    }

    if (ps.reason == OFPPR_ADD) {
        ds_put_format(string, " ADD:");
    } else if (ps.reason == OFPPR_DELETE) {
        ds_put_format(string, " DEL:");
    } else if (ps.reason == OFPPR_MODIFY) {
        ds_put_format(string, " MOD:");
    }

    ofp_print_phy_port(string, &ps.desc);
}

static void
ofp_print_ofpst_desc_reply(struct ds *string, const struct ofp_header *oh)
{
    const struct ofp_desc_stats *ods = ofputil_stats_msg_body(oh);

    ds_put_char(string, '\n');
    ds_put_format(string, "Manufacturer: %.*s\n",
            (int) sizeof ods->mfr_desc, ods->mfr_desc);
    ds_put_format(string, "Hardware: %.*s\n",
            (int) sizeof ods->hw_desc, ods->hw_desc);
    ds_put_format(string, "Software: %.*s\n",
            (int) sizeof ods->sw_desc, ods->sw_desc);
    ds_put_format(string, "Serial Num: %.*s\n",
            (int) sizeof ods->serial_num, ods->serial_num);
    ds_put_format(string, "DP Description: %.*s\n",
            (int) sizeof ods->dp_desc, ods->dp_desc);
}

static void
ofp_print_flow_stats_request(struct ds *string, const struct ofp_header *oh)
{
    struct ofputil_flow_stats_request fsr;
    enum ofperr error;

    error = ofputil_decode_flow_stats_request(&fsr, oh);
    if (error) {
        ofp_print_error(string, error);
        return;
    }

    if (fsr.table_id != 0xff) {
        ds_put_format(string, " table=%"PRIu8, fsr.table_id);
    }

    if (fsr.out_port != OFPP_NONE) {
        ds_put_cstr(string, " out_port=");
        ofputil_format_port(fsr.out_port, string);
    }

    /* A flow stats request doesn't include a priority, but cls_rule_format()
     * will print one unless it is OFP_DEFAULT_PRIORITY. */
    fsr.match.priority = OFP_DEFAULT_PRIORITY;

    ds_put_char(string, ' ');
    cls_rule_format(&fsr.match, string);
}

static void
ofp_print_flow_stats_reply(struct ds *string, const struct ofp_header *oh)
{
    struct ofpbuf ofpacts;
    struct ofpbuf b;

    ofpbuf_use_const(&b, oh, ntohs(oh->length));
    ofpbuf_init(&ofpacts, 64);
    for (;;) {
        struct ofputil_flow_stats fs;
        int retval;

        retval = ofputil_decode_flow_stats_reply(&fs, &b, true, &ofpacts);
        if (retval) {
            if (retval != EOF) {
                ds_put_cstr(string, " ***parse error***");
            }
            break;
        }

        ds_put_char(string, '\n');

        ds_put_format(string, " cookie=0x%"PRIx64", duration=",
                      ntohll(fs.cookie));
        ofp_print_duration(string, fs.duration_sec, fs.duration_nsec);
        ds_put_format(string, ", table=%"PRIu8", ", fs.table_id);
        ds_put_format(string, "n_packets=%"PRIu64", ", fs.packet_count);
        ds_put_format(string, "n_bytes=%"PRIu64", ", fs.byte_count);
        if (fs.idle_timeout != OFP_FLOW_PERMANENT) {
            ds_put_format(string, "idle_timeout=%"PRIu16", ", fs.idle_timeout);
        }
        if (fs.hard_timeout != OFP_FLOW_PERMANENT) {
            ds_put_format(string, "hard_timeout=%"PRIu16", ", fs.hard_timeout);
        }
        if (fs.idle_age >= 0) {
            ds_put_format(string, "idle_age=%d, ", fs.idle_age);
        }
        if (fs.hard_age >= 0 && fs.hard_age != fs.duration_sec) {
            ds_put_format(string, "hard_age=%d, ", fs.hard_age);
        }

        cls_rule_format(&fs.rule, string);
        if (string->string[string->length - 1] != ' ') {
            ds_put_char(string, ' ');
        }
        ofpacts_format(fs.ofpacts, string);
    }
    ofpbuf_uninit(&ofpacts);
}

static void
ofp_print_ofpst_aggregate_reply__(struct ds *string,
                                  const struct ofp11_aggregate_stats_reply *asr)
{
    ds_put_format(string, " packet_count=%"PRIu64, ntohll(asr->packet_count));
    ds_put_format(string, " byte_count=%"PRIu64, ntohll(asr->byte_count));
    ds_put_format(string, " flow_count=%"PRIu32, ntohl(asr->flow_count));
}

static void
ofp_print_ofpst_aggregate_reply(struct ds *string, const struct ofp_header *oh)
{
    struct ofp11_aggregate_stats_reply asr;

    switch (oh->version) {
    case OFP12_VERSION:
    case OFP11_VERSION: {
        const struct ofp11_aggregate_stats_reply *asr11;

        asr11 = ofputil_stats_msg_body(oh);
        asr = *asr11;
        break;
    }

    case OFP10_VERSION: {
        const struct ofp10_aggregate_stats_reply *asr10;

        asr10 = ofputil_stats_msg_body(oh);
        asr.packet_count = get_32aligned_be64(&asr10->packet_count);
        asr.byte_count = get_32aligned_be64(&asr10->byte_count);
        asr.flow_count = asr10->flow_count;
        break;
    }

    default:
        NOT_REACHED();
    }

    ofp_print_ofpst_aggregate_reply__(string, &asr);
}

static void
ofp_print_nxst_aggregate_reply(struct ds *string, const struct ofp_header *oh)
{
    const struct ofp11_aggregate_stats_reply *asr = ofputil_stats_msg_body(oh);

    ofp_print_ofpst_aggregate_reply__(string, asr);
}

static void ofp_print_port_stat(struct ds *string, const char *leader,
                                ovs_be64 stat, int more)
{
    ds_put_cstr(string, leader);
    if (stat != UINT64_MAX) {
        ds_put_format(string, "%"PRIu64, ntohll(stat));
    } else {
        ds_put_char(string, '?');
    }
    if (more) {
        ds_put_cstr(string, ", ");
    } else {
        ds_put_cstr(string, "\n");
    }
}

static void
ofp_print_ofpst_port_request(struct ds *string, const struct ofp_header *oh)
{
    switch (oh->version) {
    case OFP12_VERSION:
    case OFP11_VERSION: {
        const struct ofp11_port_stats_request *psr = ofputil_stats_msg_body(oh);
        ds_put_format(string, " port_no=%"PRIu32, ntohl(psr->port_no));
        break;
    }

    case OFP10_VERSION: {
        const struct ofp10_port_stats_request *psr = ofputil_stats_msg_body(oh);
        ds_put_format(string, " port_no=%"PRIu16, ntohs(psr->port_no));
        break;
    }

    default:
        NOT_REACHED();
    }
}

static void
ofp_print_ofpst_port_reply(struct ds *string, const struct ofp_header *oh,
                           int verbosity)
{
    struct ofpbuf b;
    size_t n;
    struct ofp11_port_stats ps;

    ofpbuf_use_const(&b, oh, ntohs(oh->length));
    ofputil_pull_stats_msg(&b);

    /* struct ofp10_port_stats and struct ofp11_port_stats are the
     * same size.
     */
    n = b.size / sizeof ps;
    ds_put_format(string, " %zu ports\n", n);
    if (verbosity < 1) {
        return;
    }

    for (;;) {

        switch (oh->version) {
        case OFP12_VERSION:
        case OFP11_VERSION: {
            struct ofp11_port_stats *ps11 = ofpbuf_try_pull(&b, sizeof *ps11);
            if (!ps11) {
                return;
            }
            ds_put_format(string, "  port %2"PRIu32": ", ntohl(ps11->port_no));
            ps = *ps11;
            break;
        }

        case OFP10_VERSION: {
            struct ofp10_port_stats *ps10 = ofpbuf_try_pull(&b, sizeof *ps10);
            if (!ps10) {
                return;
            }

            ds_put_format(string, "  port %2"PRIu16": ", ntohs(ps.port_no));
            ps.rx_packets = get_32aligned_be64(&ps10->rx_packets);
            ps.rx_bytes = get_32aligned_be64(&ps10->rx_bytes);
            ps.rx_dropped = get_32aligned_be64(&ps10->rx_dropped);
            ps.rx_errors = get_32aligned_be64(&ps10->rx_errors);
            ps.rx_frame_err = get_32aligned_be64(&ps10->rx_frame_err);
            ps.rx_over_err = get_32aligned_be64(&ps10->rx_over_err);
            ps.rx_crc_err = get_32aligned_be64(&ps10->rx_crc_err);
            ps.tx_packets = get_32aligned_be64(&ps10->tx_packets);
            ps.tx_bytes = get_32aligned_be64(&ps10->tx_bytes);
            ps.tx_dropped = get_32aligned_be64(&ps10->tx_dropped);
            ps.tx_errors = get_32aligned_be64(&ps10->tx_errors);
            ps.collisions = get_32aligned_be64(&ps10->collisions);
            break;
        }

        default:
            NOT_REACHED();
        }

        ds_put_cstr(string, "rx ");
        ofp_print_port_stat(string, "pkts=", ps.rx_packets, 1);
        ofp_print_port_stat(string, "bytes=", ps.rx_bytes, 1);
        ofp_print_port_stat(string, "drop=", ps.rx_dropped, 1);
        ofp_print_port_stat(string, "errs=", ps.rx_errors, 1);
        ofp_print_port_stat(string, "frame=", ps.rx_frame_err, 1);
        ofp_print_port_stat(string, "over=", ps.rx_over_err, 1);
        ofp_print_port_stat(string, "crc=", ps.rx_crc_err, 0);

        ds_put_cstr(string, "           tx ");
        ofp_print_port_stat(string, "pkts=", ps.tx_packets, 1);
        ofp_print_port_stat(string, "bytes=", ps.tx_bytes, 1);
        ofp_print_port_stat(string, "drop=", ps.tx_dropped, 1);
        ofp_print_port_stat(string, "errs=", ps.tx_errors, 1);
        ofp_print_port_stat(string, "coll=", ps.collisions, 0);
    }
}

static void
ofp_print_one_ofpst_table_reply(struct ds *string, uint8_t ofp_version,
                                const char *name, struct ofp12_table_stats *ts)
{
    char name_[OFP_MAX_TABLE_NAME_LEN + 1];

    ovs_strlcpy(name_, name, sizeof name);

    ds_put_format(string, "  %d: %-8s: ", ts->table_id, name_);
    ds_put_format(string, "wild=0x%05"PRIx32", ", ntohl(ts->wildcards));
    ds_put_format(string, "max=%6"PRIu32", ", ntohl(ts->max_entries));
    ds_put_format(string, "active=%"PRIu32"\n", ntohl(ts->active_count));
    ds_put_cstr(string, "               ");
    ds_put_format(string, "lookup=%"PRIu64", ", ntohll(ts->lookup_count));
    ds_put_format(string, "matched=%"PRIu64"\n", ntohll(ts->matched_count));

    if (ofp_version < OFP11_VERSION) {
        return;
    }

    ds_put_cstr(string, "               ");
    ds_put_format(string, "match=%08"PRIx32", ", ntohl(ts->match));
    ds_put_format(string, "instructions=%08"PRIx32", ",
                  ntohl(ts->instructions));
    ds_put_format(string, "config=%08"PRIx32"\n", ntohl(ts->config));
    ds_put_cstr(string, "               ");
    ds_put_format(string, "write_actions=%08"PRIx32", ",
                  ntohl(ts->write_actions));
    ds_put_format(string, "apply_actions=%08"PRIx32"\n",
                  ntohl(ts->apply_actions));

    if (ofp_version < OFP12_VERSION) {
        return;
    }

    ds_put_cstr(string, "               ");
    ds_put_format(string, "write_setfields=%016"PRIx64"\n",
                  ntohll(ts->write_setfields));
    ds_put_cstr(string, "               ");
    ds_put_format(string, "apply_setfields=%016"PRIx64"\n",
                  ntohll(ts->apply_setfields));
    ds_put_cstr(string, "               ");
    ds_put_format(string, "metadata_match=%016"PRIx64"\n",
                  ntohll(ts->metadata_match));
    ds_put_cstr(string, "               ");
    ds_put_format(string, "metadata_write=%016"PRIx64"\n",
                  ntohll(ts->metadata_write));
}

static void
ofp_print_ofpst_table_reply12(struct ds *string, const struct ofp_header *oh,
                              int verbosity)
{
    struct ofp12_table_stats *ts;
    struct ofpbuf b;
    size_t n;

    ofpbuf_use_const(&b, oh, ntohs(oh->length));
    ofputil_pull_stats_msg(&b);

    n = b.size / sizeof *ts;
    ds_put_format(string, " %zu tables\n", n);
    if (verbosity < 1) {
        return;
    }

    for (;;) {
        ts = ofpbuf_try_pull(&b, sizeof *ts);
        if (!ts) {
            return;
        }

        ofp_print_one_ofpst_table_reply(string, OFP12_VERSION, ts->name, ts);
     }
}

static void
ofp_print_ofpst_table_reply11(struct ds *string, const struct ofp_header *oh,
                              int verbosity)
{
    struct ofp11_table_stats *ts;
    struct ofpbuf b;
    size_t n;

    ofpbuf_use_const(&b, oh, ntohs(oh->length));
    ofputil_pull_stats_msg(&b);

    n = b.size / sizeof *ts;
    ds_put_format(string, " %zu tables\n", n);
    if (verbosity < 1) {
        return;
    }

    for (;;) {
        struct ofp12_table_stats ts12;

        ts = ofpbuf_try_pull(&b, sizeof *ts);
        if (!ts) {
            return;
        }

        ts12.table_id = ts->table_id;
        ts12.wildcards = ts->wildcards;
        ts12.max_entries = ts->max_entries;
        ts12.active_count = ts->active_count;
        ts12.lookup_count = ts->lookup_count;
        ts12.matched_count = ts->matched_count;
        ts12.match = ts->match;
        ts12.instructions = ts->instructions;
        ts12.config = ts->config;
        ts12.write_actions = ts->write_actions;
        ts12.apply_actions = ts->apply_actions;
        ofp_print_one_ofpst_table_reply(string, OFP11_VERSION, ts->name, &ts12);
     }
}

static void
ofp_print_ofpst_table_reply10(struct ds *string, const struct ofp_header *oh,
                              int verbosity)
{
    struct ofp10_table_stats *ts;
    struct ofpbuf b;
    size_t n;

    ofpbuf_use_const(&b, oh, ntohs(oh->length));
    ofputil_pull_stats_msg(&b);

    n = b.size / sizeof *ts;
    ds_put_format(string, " %zu tables\n", n);
    if (verbosity < 1) {
        return;
    }

    for (;;) {
        struct ofp12_table_stats ts12;

        ts = ofpbuf_try_pull(&b, sizeof *ts);
        if (!ts) {
            return;
        }

        ts12.table_id = ts->table_id;
        ts12.wildcards = ts->wildcards;
        ts12.max_entries = ts->max_entries;
        ts12.active_count = ts->active_count;
        ts12.lookup_count = get_32aligned_be64(&ts->lookup_count);
        ts12.matched_count = get_32aligned_be64(&ts->matched_count);
        ofp_print_one_ofpst_table_reply(string, OFP10_VERSION, ts->name, &ts12);
     }
}

static void
ofp_print_ofpst_table_reply(struct ds *string, const struct ofp_header *oh,
                            int verbosity)
{
    switch (oh->version) {
    case OFP12_VERSION:
        ofp_print_ofpst_table_reply12(string, oh, verbosity);
        break;

    case OFP11_VERSION:
        ofp_print_ofpst_table_reply11(string, oh, verbosity);
        break;

    case OFP10_VERSION:
        ofp_print_ofpst_table_reply10(string, oh, verbosity);
        break;

    default:
        NOT_REACHED();
    }
}

static void
ofp_print_queue_name(struct ds *string, uint32_t queue_id)
{
    if (queue_id == OFPQ_ALL) {
        ds_put_cstr(string, "ALL");
    } else {
        ds_put_format(string, "%"PRIu32, queue_id);
    }
}

static void
ofp_print_ofpst_queue_request(struct ds *string, const struct ofp_header *oh)
{
    uint16_t port_no;
    uint32_t queue_id;

    switch (oh->version) {
    case OFP11_VERSION:
    case OFP12_VERSION: {
        const struct ofp11_queue_stats_request *qsr;

        qsr = ofputil_stats_msg_body(oh);
        if (ofputil_port_from_ofp11(qsr->port_no, &port_no)) {
            ds_put_cstr(string, "*** parse error: invalid port ***\n");
            return;
        }
        port_no = ntohs(qsr->port_no);
        queue_id = ntohl(qsr->queue_id);
        break;
    }

    case OFP10_VERSION: {
        const struct ofp10_queue_stats_request *qsr;

        qsr = ofputil_stats_msg_body(oh);
        port_no = ntohs(qsr->port_no);
        queue_id = ntohl(qsr->queue_id);
        break;
    }

    default:
       NOT_REACHED();
    }

    ds_put_cstr(string, "port=");
    ofputil_format_port(port_no, string);

    ds_put_cstr(string, " queue=");
    ofp_print_queue_name(string, queue_id);
}

static void
ofp_print_ofpst_queue_reply(struct ds *string, const struct ofp_header *oh,
                            int verbosity)
{
    struct ofpbuf b;
    size_t n;
    struct ofp11_queue_stats qs;

    ofpbuf_use_const(&b, oh, ntohs(oh->length));
    ofputil_pull_stats_msg(&b);

    /* This calculation is correct because
     * struct ofp10_queue_stats and struct ofp11_queue_stats
     * are the same size.
     */
    n = b.size / sizeof qs;
    ds_put_format(string, " %zu queues\n", n);
    if (verbosity < 1) {
        return;
    }

    for (;;) {
        uint16_t port_no;

        switch (oh->version) {
        case OFP11_VERSION:
        case OFP12_VERSION: {
            const struct ofp11_queue_stats *qs11;

            qs11 = ofpbuf_try_pull(&b, sizeof *qs11);
            if (!qs11) {
                return;
            }
            if (ofputil_port_from_ofp11(qs11->port_no, &port_no)) {
                ds_put_cstr(string, "*** parse error: invalid port ***\n");
                return;
            }
            qs = *qs11;
            break;
        }

        case OFP10_VERSION: {
            const struct ofp10_queue_stats *qs10;

            qs10 = ofpbuf_try_pull(&b, sizeof *qs10);
            if (!qs10) {
                return;
            }
            port_no = ntohs(qs10->port_no);
            qs.queue_id = qs10->queue_id;
            qs.tx_bytes = get_32aligned_be64(&qs10->tx_bytes);
            qs.tx_packets = get_32aligned_be64(&qs10->tx_packets);
            qs.tx_errors = get_32aligned_be64(&qs10->tx_errors);
            break;
        }

        default:
            NOT_REACHED();
        }

        ds_put_cstr(string, "  port ");
        ofputil_format_port(port_no, string);
        ds_put_cstr(string, " queue ");
        ofp_print_queue_name(string, ntohl(qs.queue_id));
        ds_put_cstr(string, ": ");

        ofp_print_port_stat(string, "bytes=", qs.tx_bytes, 1);
        ofp_print_port_stat(string, "pkts=", qs.tx_packets, 1);
        ofp_print_port_stat(string, "errors=", qs.tx_errors, 0);
    }
}

static void
ofp_print_ofpst_port_desc_reply(struct ds *string,
                                const struct ofp_header *oh)
{
    struct ofpbuf b;

    ofpbuf_use_const(&b, oh, ntohs(oh->length));
    ofputil_pull_stats_msg(&b);
    ds_put_char(string, '\n');
    ofp_print_phy_ports(string, oh->version, &b);
}

static void
ofp_print_stats_request(struct ds *string, const struct ofp_header *oh)
{
    uint16_t flags = ofputil_decode_stats_msg_flags(oh);

    if (flags) {
        ds_put_format(string, " ***unknown flags 0x%04"PRIx16"***", flags);
    }
}

static void
ofp_print_stats_reply(struct ds *string, const struct ofp_header *oh)
{
    uint16_t flags = ofputil_decode_stats_msg_flags(oh);

    if (flags) {
        ds_put_cstr(string, " flags=");
        if (flags & OFPSF_REPLY_MORE) {
            ds_put_cstr(string, "[more]");
            flags &= ~OFPSF_REPLY_MORE;
        }
        if (flags) {
            ds_put_format(string, "[***unknown flags 0x%04"PRIx16"***]",
                          flags);
        }
    }
}

static void
ofp_print_echo(struct ds *string, const struct ofp_header *oh, int verbosity)
{
    size_t len = ntohs(oh->length);

    ds_put_format(string, " %zu bytes of payload\n", len - sizeof *oh);
    if (verbosity > 1) {
        ds_put_hex_dump(string, oh + 1, len - sizeof *oh, 0, true);
    }
}

static void
ofp_print_nxt_role_message(struct ds *string,
                           const struct nx_role_request *nrr)
{
    unsigned int role = ntohl(nrr->role);

    ds_put_cstr(string, " role=");
    if (role == NX_ROLE_OTHER) {
        ds_put_cstr(string, "other");
    } else if (role == NX_ROLE_MASTER) {
        ds_put_cstr(string, "master");
    } else if (role == NX_ROLE_SLAVE) {
        ds_put_cstr(string, "slave");
    } else {
        ds_put_format(string, "%u", role);
    }
}

static void
ofp_print_nxt_flow_mod_table_id(struct ds *string,
                                const struct nx_flow_mod_table_id *nfmti)
{
    ds_put_format(string, " %s", nfmti->set ? "enable" : "disable");
}

static void
ofp_print_nxt_set_flow_format(struct ds *string,
                              const struct nx_set_flow_format *nsff)
{
    uint32_t format = ntohl(nsff->format);

    ds_put_cstr(string, " format=");
    if (ofputil_nx_flow_format_is_valid(format)) {
        ds_put_cstr(string, ofputil_nx_flow_format_to_string(format));
    } else {
        ds_put_format(string, "%"PRIu32, format);
    }
}

static void
ofp_print_nxt_set_packet_in_format(struct ds *string,
                                   const struct nx_set_packet_in_format *nspf)
{
    uint32_t format = ntohl(nspf->format);

    ds_put_cstr(string, " format=");
    if (ofputil_packet_in_format_is_valid(format)) {
        ds_put_cstr(string, ofputil_packet_in_format_to_string(format));
    } else {
        ds_put_format(string, "%"PRIu32, format);
    }
}

static const char *
ofp_port_reason_to_string(enum ofp_port_reason reason)
{
    static char s[32];

    switch (reason) {
    case OFPPR_ADD:
        return "add";

    case OFPPR_DELETE:
        return "delete";

    case OFPPR_MODIFY:
        return "modify";

    default:
        sprintf(s, "%d", (int) reason);
        return s;
    }
}

static void
ofp_print_nxt_set_async_config(struct ds *string,
                               const struct nx_async_config *nac)
{
    int i;

    for (i = 0; i < 2; i++) {
        int j;

        ds_put_format(string, "\n %s:\n", i == 0 ? "master" : "slave");

        ds_put_cstr(string, "       PACKET_IN:");
        for (j = 0; j < 32; j++) {
            if (nac->packet_in_mask[i] & htonl(1u << j)) {
                ds_put_format(string, " %s",
                              ofputil_packet_in_reason_to_string(j));
            }
        }
        if (!nac->packet_in_mask[i]) {
            ds_put_cstr(string, " (off)");
        }
        ds_put_char(string, '\n');

        ds_put_cstr(string, "     PORT_STATUS:");
        for (j = 0; j < 32; j++) {
            if (nac->port_status_mask[i] & htonl(1u << j)) {
                ds_put_format(string, " %s", ofp_port_reason_to_string(j));
            }
        }
        if (!nac->port_status_mask[i]) {
            ds_put_cstr(string, " (off)");
        }
        ds_put_char(string, '\n');

        ds_put_cstr(string, "    FLOW_REMOVED:");
        for (j = 0; j < 32; j++) {
            if (nac->flow_removed_mask[i] & htonl(1u << j)) {
                ds_put_format(string, " %s",
                              ofp_flow_removed_reason_to_string(j));
            }
        }
        if (!nac->flow_removed_mask[i]) {
            ds_put_cstr(string, " (off)");
        }
        ds_put_char(string, '\n');
    }
}

static void
ofp_print_nxt_set_controller_id(struct ds *string,
                                const struct nx_controller_id *nci)
{
    ds_put_format(string, " id=%"PRIu16, ntohs(nci->controller_id));
}

static void
ofp_to_string__(const struct ofp_header *oh,
                const struct ofputil_msg_type *type, struct ds *string,
                int verbosity)
{
    enum ofputil_msg_code code;
    const void *msg = oh;

    ds_put_cstr(string, ofputil_msg_type_name(type));
    switch (oh->version) {
    case OFP10_VERSION:
        break;
    case OFP11_VERSION:
        ds_put_cstr(string, " (OF1.1)");
        break;
    case OFP12_VERSION:
        ds_put_cstr(string, " (OF1.2)");
        break;
    default:
        ds_put_format(string, " (OF 0x%02"PRIx8")", oh->version);
        break;
    }
    ds_put_format(string, " (xid=0x%"PRIx32"):", ntohl(oh->xid));

    code = ofputil_msg_type_code(type);
    switch (code) {
    case OFPUTIL_MSG_INVALID:
        break;

    case OFPUTIL_OFPT_HELLO:
        ds_put_char(string, '\n');
        ds_put_hex_dump(string, oh + 1, ntohs(oh->length) - sizeof *oh,
                        0, true);
        break;

    case OFPUTIL_OFPT_ERROR:
        ofp_print_error_msg(string, msg);
        break;

    case OFPUTIL_OFPT_ECHO_REQUEST:
    case OFPUTIL_OFPT_ECHO_REPLY:
        ofp_print_echo(string, oh, verbosity);
        break;

    case OFPUTIL_OFPT_FEATURES_REQUEST:
        break;

    case OFPUTIL_OFPT_FEATURES_REPLY:
        ofp_print_switch_features(string, msg);
        break;

    case OFPUTIL_OFPT_GET_CONFIG_REQUEST:
        break;

    case OFPUTIL_OFPT_GET_CONFIG_REPLY:
    case OFPUTIL_OFPT_SET_CONFIG:
        ofp_print_switch_config(string, msg);
        break;

    case OFPUTIL_OFPT_PACKET_IN:
    case OFPUTIL_NXT_PACKET_IN:
        ofp_print_packet_in(string, msg, verbosity);
        break;

    case OFPUTIL_OFPT_FLOW_REMOVED:
    case OFPUTIL_NXT_FLOW_REMOVED:
        ofp_print_flow_removed(string, msg);
        break;

    case OFPUTIL_OFPT_PORT_STATUS:
        ofp_print_port_status(string, msg);
        break;

    case OFPUTIL_OFPT_PACKET_OUT:
        ofp_print_packet_out(string, msg, verbosity);
        break;

    case OFPUTIL_OFPT10_FLOW_MOD:
    case OFPUTIL_OFPT11_FLOW_MOD:
    case OFPUTIL_NXT_FLOW_MOD:
        ofp_print_flow_mod(string, msg);
        break;

    case OFPUTIL_OFPT_PORT_MOD:
        ofp_print_port_mod(string, msg);
        break;

    case OFPUTIL_OFPT_BARRIER_REQUEST:
    case OFPUTIL_OFPT_BARRIER_REPLY:
        break;

    case OFPUTIL_OFPT_QUEUE_GET_CONFIG_REQUEST:
    case OFPUTIL_OFPT_QUEUE_GET_CONFIG_REPLY:
        /* XXX */
        break;

    case OFPUTIL_OFPST_DESC_REQUEST:
    case OFPUTIL_OFPST_PORT_DESC_REQUEST:
        ofp_print_stats_request(string, oh);
        break;

    case OFPUTIL_OFPST10_FLOW_REQUEST:
    case OFPUTIL_OFPST11_FLOW_REQUEST:
    case OFPUTIL_NXST_FLOW_REQUEST:
    case OFPUTIL_OFPST10_AGGREGATE_REQUEST:
    case OFPUTIL_OFPST11_AGGREGATE_REQUEST:
    case OFPUTIL_NXST_AGGREGATE_REQUEST:
        ofp_print_stats_request(string, oh);
        ofp_print_flow_stats_request(string, oh);
        break;

    case OFPUTIL_OFPST_TABLE_REQUEST:
        ofp_print_stats_request(string, oh);
        break;

    case OFPUTIL_OFPST_PORT_REQUEST:
        ofp_print_stats_request(string, oh);
        ofp_print_ofpst_port_request(string, msg);
        break;

    case OFPUTIL_OFPST_QUEUE_REQUEST:
        ofp_print_stats_request(string, oh);
        ofp_print_ofpst_queue_request(string, msg);
        break;

    case OFPUTIL_OFPST_DESC_REPLY:
        ofp_print_stats_reply(string, oh);
        ofp_print_ofpst_desc_reply(string, msg);
        break;

    case OFPUTIL_OFPST10_FLOW_REPLY:
    case OFPUTIL_OFPST11_FLOW_REPLY:
    case OFPUTIL_NXST_FLOW_REPLY:
        ofp_print_stats_reply(string, oh);
        ofp_print_flow_stats_reply(string, oh);
        break;

    case OFPUTIL_OFPST_QUEUE_REPLY:
        ofp_print_stats_reply(string, oh);
        ofp_print_ofpst_queue_reply(string, oh, verbosity);
        break;

    case OFPUTIL_OFPST_PORT_REPLY:
        ofp_print_stats_reply(string, oh);
        ofp_print_ofpst_port_reply(string, oh, verbosity);
        break;

    case OFPUTIL_OFPST_TABLE_REPLY:
        ofp_print_stats_reply(string, oh);
        ofp_print_ofpst_table_reply(string, oh, verbosity);
        break;

    case OFPUTIL_OFPST10_AGGREGATE_REPLY:
    case OFPUTIL_OFPST11_AGGREGATE_REPLY:
        ofp_print_stats_reply(string, oh);
        ofp_print_ofpst_aggregate_reply(string, msg);
        break;

    case OFPUTIL_OFPST_PORT_DESC_REPLY:
        ofp_print_stats_reply(string, oh);
        ofp_print_ofpst_port_desc_reply(string, oh);
        break;

    case OFPUTIL_NXT_ROLE_REQUEST:
    case OFPUTIL_NXT_ROLE_REPLY:
        ofp_print_nxt_role_message(string, msg);
        break;

    case OFPUTIL_NXT_FLOW_MOD_TABLE_ID:
        ofp_print_nxt_flow_mod_table_id(string, msg);
        break;

    case OFPUTIL_NXT_SET_FLOW_FORMAT:
        ofp_print_nxt_set_flow_format(string, msg);
        break;

    case OFPUTIL_NXT_SET_PACKET_IN_FORMAT:
        ofp_print_nxt_set_packet_in_format(string, msg);
        break;

    case OFPUTIL_NXT_FLOW_AGE:
        break;

    case OFPUTIL_NXT_SET_CONTROLLER_ID:
        ofp_print_nxt_set_controller_id(string, msg);
        break;

    case OFPUTIL_NXT_SET_ASYNC_CONFIG:
        ofp_print_nxt_set_async_config(string, msg);
        break;

    case OFPUTIL_NXST_AGGREGATE_REPLY:
        ofp_print_stats_reply(string, oh);
        ofp_print_nxst_aggregate_reply(string, msg);
        break;
    }
}

/* Composes and returns a string representing the OpenFlow packet of 'len'
 * bytes at 'oh' at the given 'verbosity' level.  0 is a minimal amount of
 * verbosity and higher numbers increase verbosity.  The caller is responsible
 * for freeing the string. */
char *
ofp_to_string(const void *oh_, size_t len, int verbosity)
{
    struct ds string = DS_EMPTY_INITIALIZER;
    const struct ofp_header *oh = oh_;

    if (!len) {
        ds_put_cstr(&string, "OpenFlow message is empty\n");
    } else if (len < sizeof(struct ofp_header)) {
        ds_put_format(&string, "OpenFlow packet too short (only %zu bytes):\n",
                      len);
    } else if (ntohs(oh->length) > len) {
        ds_put_format(&string,
                      "(***truncated to %zu bytes from %"PRIu16"***)\n",
                      len, ntohs(oh->length));
    } else if (ntohs(oh->length) < len) {
        ds_put_format(&string,
                      "(***only uses %"PRIu16" bytes out of %zu***)\n",
                      ntohs(oh->length), len);
    } else {
        const struct ofputil_msg_type *type;
        enum ofperr error;

        error = ofputil_decode_msg_type(oh, &type);
        if (!error) {
            ofp_to_string__(oh, type, &string, verbosity);
            if (verbosity >= 5) {
                if (ds_last(&string) != '\n') {
                    ds_put_char(&string, '\n');
                }
                ds_put_hex_dump(&string, oh, len, 0, true);
            }
            if (ds_last(&string) != '\n') {
                ds_put_char(&string, '\n');
            }
            return ds_steal_cstr(&string);
        }

        ofp_print_error(&string, error);
    }
    ds_put_hex_dump(&string, oh, len, 0, true);
    return ds_steal_cstr(&string);
}

static void
print_and_free(FILE *stream, char *string)
{
    fputs(string, stream);
    free(string);
}

/* Pretty-print the OpenFlow packet of 'len' bytes at 'oh' to 'stream' at the
 * given 'verbosity' level.  0 is a minimal amount of verbosity and higher
 * numbers increase verbosity. */
void
ofp_print(FILE *stream, const void *oh, size_t len, int verbosity)
{
    print_and_free(stream, ofp_to_string(oh, len, verbosity));
}

/* Dumps the contents of the Ethernet frame in the 'len' bytes starting at
 * 'data' to 'stream'. */
void
ofp_print_packet(FILE *stream, const void *data, size_t len)
{
    print_and_free(stream, ofp_packet_to_string(data, len));
}
