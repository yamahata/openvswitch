/*
 * Copyright (c) 2009, 2010, 2011 Nicira Networks.
 * Copyright (c) 2010 Jean Tourrilhes - HP-Labs.
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
#include "ofproto.h"
#include <errno.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdlib.h>
#include "autopath.h"
#include "bitmap.h"
#include "bond.h"
#include "byte-order.h"
#include "cfm.h"
#include "classifier.h"
#include "connmgr.h"
#include "coverage.h"
#include "dynamic-string.h"
#include "fail-open.h"
#include "hash.h"
#include "hmap.h"
#include "hmapx.h"
#include "in-band.h"
#include "lacp.h"
#include "mac-learning.h"
#include "multipath.h"
#include "netdev.h"
#include "netflow.h"
#include "netlink.h"
#include "nx-match.h"
#include "odp-util.h"
#include "ofp-print.h"
#include "ofp-util.h"
#include "ofproto-sflow.h"
#include "ofpbuf.h"
#include "openflow/nicira-ext.h"
#include "openflow/openflow.h"
#include "openvswitch/datapath-protocol.h"
#include "packets.h"
#include "pinsched.h"
#include "pktbuf.h"
#include "poll-loop.h"
#include "private.h"
#include "rconn.h"
#include "shash.h"
#include "sset.h"
#include "stream-ssl.h"
#include "tag.h"
#include "timer.h"
#include "timeval.h"
#include "unaligned.h"
#include "unixctl.h"
#include "vconn.h"
#include "vlan-bitmap.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(ofproto);

COVERAGE_DEFINE(odp_overflow);
COVERAGE_DEFINE(ofproto_agg_request);
COVERAGE_DEFINE(ofproto_costly_flags);
COVERAGE_DEFINE(ofproto_ctlr_action);
COVERAGE_DEFINE(ofproto_error);
COVERAGE_DEFINE(ofproto_expiration);
COVERAGE_DEFINE(ofproto_expired);
COVERAGE_DEFINE(ofproto_flows_req);
COVERAGE_DEFINE(ofproto_flush);
COVERAGE_DEFINE(ofproto_invalidated);
COVERAGE_DEFINE(ofproto_no_packet_in);
COVERAGE_DEFINE(ofproto_ofp2odp);
COVERAGE_DEFINE(ofproto_packet_in);
COVERAGE_DEFINE(ofproto_packet_out);
COVERAGE_DEFINE(ofproto_queue_req);
COVERAGE_DEFINE(ofproto_recv_openflow);
COVERAGE_DEFINE(ofproto_reinit_ports);
COVERAGE_DEFINE(ofproto_unexpected_rule);
COVERAGE_DEFINE(ofproto_uninstallable);
COVERAGE_DEFINE(ofproto_update_port);

static void ofport_destroy__(struct ofport *);
static void ofport_destroy(struct ofport *);

static int rule_create(struct ofproto *, const struct cls_rule *,
                       const union ofp_action *, size_t n_actions,
                       uint16_t idle_timeout, uint16_t hard_timeout,
                       ovs_be64 flow_cookie, bool send_flow_removed,
                       struct rule **rulep);

static uint64_t pick_datapath_id(const struct ofproto *);
static uint64_t pick_fallback_dpid(void);

static void ofproto_destroy__(struct ofproto *);
static void ofproto_flush_flows__(struct ofproto *);

static void ofproto_rule_destroy__(struct rule *);
static void ofproto_rule_send_removed(struct rule *, uint8_t reason);
static void ofproto_rule_remove(struct rule *);

static void handle_openflow(struct ofconn *, struct ofpbuf *);

static void update_port(struct ofproto *, const char *devname);
static int init_ports(struct ofproto *);
static void reinit_ports(struct ofproto *);

static void ofproto_unixctl_init(void);

/* All registered ofproto classes, in probe order. */
static const struct ofproto_class **ofproto_classes;
static size_t n_ofproto_classes;
static size_t allocated_ofproto_classes;

/* Map from dpif name to struct ofproto, for use by unixctl commands. */
static struct hmap all_ofprotos = HMAP_INITIALIZER(&all_ofprotos);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

static void
ofproto_initialize(void)
{
    static bool inited;

    if (!inited) {
        inited = true;
        ofproto_class_register(&ofproto_dpif_class);
    }
}

/* 'type' should be a normalized datapath type, as returned by
 * ofproto_normalize_type().  Returns the corresponding ofproto_class
 * structure, or a null pointer if there is none registered for 'type'. */
static const struct ofproto_class *
ofproto_class_find__(const char *type)
{
    size_t i;

    ofproto_initialize();
    for (i = 0; i < n_ofproto_classes; i++) {
        const struct ofproto_class *class = ofproto_classes[i];
        struct sset types;
        bool found;

        sset_init(&types);
        class->enumerate_types(&types);
        found = sset_contains(&types, type);
        sset_destroy(&types);

        if (found) {
            return class;
        }
    }
    VLOG_WARN("unknown datapath type %s", type);
    return NULL;
}

/* Registers a new ofproto class.  After successful registration, new ofprotos
 * of that type can be created using ofproto_create(). */
int
ofproto_class_register(const struct ofproto_class *new_class)
{
    size_t i;

    for (i = 0; i < n_ofproto_classes; i++) {
        if (ofproto_classes[i] == new_class) {
            return EEXIST;
        }
    }

    if (n_ofproto_classes >= allocated_ofproto_classes) {
        ofproto_classes = x2nrealloc(ofproto_classes,
                                     &allocated_ofproto_classes,
                                     sizeof *ofproto_classes);
    }
    ofproto_classes[n_ofproto_classes++] = new_class;
    return 0;
}

/* Unregisters a datapath provider.  'type' must have been previously
 * registered and not currently be in use by any ofprotos.  After
 * unregistration new datapaths of that type cannot be opened using
 * ofproto_create(). */
int
ofproto_class_unregister(const struct ofproto_class *class)
{
    size_t i;

    for (i = 0; i < n_ofproto_classes; i++) {
        if (ofproto_classes[i] == class) {
            for (i++; i < n_ofproto_classes; i++) {
                ofproto_classes[i - 1] = ofproto_classes[i];
            }
            n_ofproto_classes--;
            return 0;
        }
    }
    VLOG_WARN("attempted to unregister an ofproto class that is not "
              "registered");
    return EAFNOSUPPORT;
}

/* Clears 'types' and enumerates all registered ofproto types into it.  The
 * caller must first initialize the sset. */
void
ofproto_enumerate_types(struct sset *types)
{
    size_t i;

    ofproto_initialize();
    for (i = 0; i < n_ofproto_classes; i++) {
        ofproto_classes[i]->enumerate_types(types);
    }
}

/* Returns the fully spelled out name for the given ofproto 'type'.
 *
 * Normalized type string can be compared with strcmp().  Unnormalized type
 * string might be the same even if they have different spellings. */
const char *
ofproto_normalize_type(const char *type)
{
    return type && type[0] ? type : "system";
}

/* Clears 'names' and enumerates the names of all known created ofprotos with
 * the given 'type'.  The caller must first initialize the sset.  Returns 0 if
 * successful, otherwise a positive errno value.
 *
 * Some kinds of datapaths might not be practically enumerable.  This is not
 * considered an error. */
int
ofproto_enumerate_names(const char *type, struct sset *names)
{
    const struct ofproto_class *class = ofproto_class_find__(type);
    return class ? class->enumerate_names(type, names) : EAFNOSUPPORT;
 }

int
ofproto_create(const char *datapath_name, const char *datapath_type,
               struct ofproto **ofprotop)
{
    const struct ofproto_class *class;
    struct ofproto *ofproto;
    int error;

    *ofprotop = NULL;

    ofproto_initialize();
    ofproto_unixctl_init();

    datapath_type = ofproto_normalize_type(datapath_type);
    class = ofproto_class_find__(datapath_type);
    if (!class) {
        VLOG_WARN("could not create datapath %s of unknown type %s",
                  datapath_name, datapath_type);
        return EAFNOSUPPORT;
    }

    ofproto = class->alloc();
    if (!ofproto) {
        VLOG_ERR("failed to allocate datapath %s of type %s",
                 datapath_name, datapath_type);
        return ENOMEM;
    }

    /* Initialize. */
    memset(ofproto, 0, sizeof *ofproto);
    ofproto->ofproto_class = class;
    ofproto->name = xstrdup(datapath_name);
    ofproto->type = xstrdup(datapath_type);
    hmap_insert(&all_ofprotos, &ofproto->hmap_node,
                hash_string(ofproto->name, 0));
    ofproto->datapath_id = 0;
    ofproto->fallback_dpid = pick_fallback_dpid();
    ofproto->mfr_desc = xstrdup(DEFAULT_MFR_DESC);
    ofproto->hw_desc = xstrdup(DEFAULT_HW_DESC);
    ofproto->sw_desc = xstrdup(DEFAULT_SW_DESC);
    ofproto->serial_desc = xstrdup(DEFAULT_SERIAL_DESC);
    ofproto->dp_desc = xstrdup(DEFAULT_DP_DESC);
    ofproto->netdev_monitor = netdev_monitor_create();
    hmap_init(&ofproto->ports);
    shash_init(&ofproto->port_by_name);
    classifier_init(&ofproto->cls);
    ofproto->connmgr = connmgr_create(ofproto, datapath_name, datapath_name);

    error = ofproto->ofproto_class->construct(ofproto);
    if (error) {
        VLOG_ERR("failed to open datapath %s: %s",
                 datapath_name, strerror(error));
        ofproto_destroy__(ofproto);
        return error;
    }

    ofproto->datapath_id = pick_datapath_id(ofproto);
    VLOG_INFO("using datapath ID %016"PRIx64, ofproto->datapath_id);
    init_ports(ofproto);

    *ofprotop = ofproto;
    return 0;
}

void
ofproto_set_datapath_id(struct ofproto *p, uint64_t datapath_id)
{
    uint64_t old_dpid = p->datapath_id;
    p->datapath_id = datapath_id ? datapath_id : pick_datapath_id(p);
    if (p->datapath_id != old_dpid) {
        VLOG_INFO("datapath ID changed to %016"PRIx64, p->datapath_id);

        /* Force all active connections to reconnect, since there is no way to
         * notify a controller that the datapath ID has changed. */
        ofproto_reconnect_controllers(p);
    }
}

void
ofproto_set_controllers(struct ofproto *p,
                        const struct ofproto_controller *controllers,
                        size_t n_controllers)
{
    connmgr_set_controllers(p->connmgr, controllers, n_controllers);
}

void
ofproto_set_fail_mode(struct ofproto *p, enum ofproto_fail_mode fail_mode)
{
    connmgr_set_fail_mode(p->connmgr, fail_mode);
}

/* Drops the connections between 'ofproto' and all of its controllers, forcing
 * them to reconnect. */
void
ofproto_reconnect_controllers(struct ofproto *ofproto)
{
    connmgr_reconnect(ofproto->connmgr);
}

/* Sets the 'n' TCP port addresses in 'extras' as ones to which 'ofproto''s
 * in-band control should guarantee access, in the same way that in-band
 * control guarantees access to OpenFlow controllers. */
void
ofproto_set_extra_in_band_remotes(struct ofproto *ofproto,
                                  const struct sockaddr_in *extras, size_t n)
{
    connmgr_set_extra_in_band_remotes(ofproto->connmgr, extras, n);
}

/* Sets the OpenFlow queue used by flows set up by in-band control on
 * 'ofproto' to 'queue_id'.  If 'queue_id' is negative, then in-band control
 * flows will use the default queue. */
void
ofproto_set_in_band_queue(struct ofproto *ofproto, int queue_id)
{
    connmgr_set_in_band_queue(ofproto->connmgr, queue_id);
}

void
ofproto_set_desc(struct ofproto *p,
                 const char *mfr_desc, const char *hw_desc,
                 const char *sw_desc, const char *serial_desc,
                 const char *dp_desc)
{
    struct ofp_desc_stats *ods;

    if (mfr_desc) {
        if (strlen(mfr_desc) >= sizeof ods->mfr_desc) {
            VLOG_WARN("truncating mfr_desc, must be less than %zu characters",
                    sizeof ods->mfr_desc);
        }
        free(p->mfr_desc);
        p->mfr_desc = xstrdup(mfr_desc);
    }
    if (hw_desc) {
        if (strlen(hw_desc) >= sizeof ods->hw_desc) {
            VLOG_WARN("truncating hw_desc, must be less than %zu characters",
                    sizeof ods->hw_desc);
        }
        free(p->hw_desc);
        p->hw_desc = xstrdup(hw_desc);
    }
    if (sw_desc) {
        if (strlen(sw_desc) >= sizeof ods->sw_desc) {
            VLOG_WARN("truncating sw_desc, must be less than %zu characters",
                    sizeof ods->sw_desc);
        }
        free(p->sw_desc);
        p->sw_desc = xstrdup(sw_desc);
    }
    if (serial_desc) {
        if (strlen(serial_desc) >= sizeof ods->serial_num) {
            VLOG_WARN("truncating serial_desc, must be less than %zu "
                    "characters",
                    sizeof ods->serial_num);
        }
        free(p->serial_desc);
        p->serial_desc = xstrdup(serial_desc);
    }
    if (dp_desc) {
        if (strlen(dp_desc) >= sizeof ods->dp_desc) {
            VLOG_WARN("truncating dp_desc, must be less than %zu characters",
                    sizeof ods->dp_desc);
        }
        free(p->dp_desc);
        p->dp_desc = xstrdup(dp_desc);
    }
}

int
ofproto_set_snoops(struct ofproto *ofproto, const struct sset *snoops)
{
    return connmgr_set_snoops(ofproto->connmgr, snoops);
}

int
ofproto_set_netflow(struct ofproto *ofproto,
                    const struct netflow_options *nf_options)
{
    if (nf_options && sset_is_empty(&nf_options->collectors)) {
        nf_options = NULL;
    }

    if (ofproto->ofproto_class->set_netflow) {
        return ofproto->ofproto_class->set_netflow(ofproto, nf_options);
    } else {
        return nf_options ? EOPNOTSUPP : 0;
    }
}

int
ofproto_set_sflow(struct ofproto *ofproto,
                  const struct ofproto_sflow_options *oso)
{
    if (oso && sset_is_empty(&oso->targets)) {
        oso = NULL;
    }

    if (ofproto->ofproto_class->set_sflow) {
        return ofproto->ofproto_class->set_sflow(ofproto, oso);
    } else {
        return oso ? EOPNOTSUPP : 0;
    }
}

/* Connectivity Fault Management configuration. */

/* Clears the CFM configuration from 'ofp_port' on 'ofproto'. */
void
ofproto_port_clear_cfm(struct ofproto *ofproto, uint16_t ofp_port)
{
    struct ofport *ofport = ofproto_get_port(ofproto, ofp_port);
    if (ofport && ofproto->ofproto_class->set_cfm) {
        ofproto->ofproto_class->set_cfm(ofport, NULL, NULL, 0);
    }
}

/* Configures connectivity fault management on 'ofp_port' in 'ofproto'.  Takes
 * basic configuration from the configuration members in 'cfm', and the set of
 * remote maintenance points from the 'n_remote_mps' elements in 'remote_mps'.
 * Ignores the statistics members of 'cfm'.
 *
 * This function has no effect if 'ofproto' does not have a port 'ofp_port'. */
void
ofproto_port_set_cfm(struct ofproto *ofproto, uint16_t ofp_port,
                     const struct cfm *cfm,
                     const uint16_t *remote_mps, size_t n_remote_mps)
{
    struct ofport *ofport;
    int error;

    ofport = ofproto_get_port(ofproto, ofp_port);
    if (!ofport) {
        VLOG_WARN("%s: cannot configure CFM on nonexistent port %"PRIu16,
                  ofproto->name, ofp_port);
        return;
    }

    error = (ofproto->ofproto_class->set_cfm
             ? ofproto->ofproto_class->set_cfm(ofport, cfm,
                                               remote_mps, n_remote_mps)
             : EOPNOTSUPP);
    if (error) {
        VLOG_WARN("%s: CFM configuration on port %"PRIu16" (%s) failed (%s)",
                  ofproto->name, ofp_port, netdev_get_name(ofport->netdev),
                  strerror(error));
    }
}

/* Returns the connectivity fault management object associated with 'ofp_port'
 * within 'ofproto', or a null pointer if 'ofproto' does not have a port
 * 'ofp_port' or if that port does not have CFM configured.  The caller must
 * not modify or destroy the returned object. */
const struct cfm *
ofproto_port_get_cfm(struct ofproto *ofproto, uint16_t ofp_port)
{
    struct ofport *ofport;
    const struct cfm *cfm;

    ofport = ofproto_get_port(ofproto, ofp_port);
    return (ofport
            && ofproto->ofproto_class->get_cfm
            && !ofproto->ofproto_class->get_cfm(ofport, &cfm)) ? cfm : NULL;
}

/* Checks the status of LACP negotiation for 'ofp_port' within ofproto.
 * Returns 1 if LACP partner information for 'ofp_port' is up-to-date,
 * 0 if LACP partner information is not current (generally indicating a
 * connectivity problem), or -1 if LACP is not enabled on 'ofp_port'. */
int
ofproto_port_is_lacp_current(struct ofproto *ofproto, uint16_t ofp_port)
{
    struct ofport *ofport = ofproto_get_port(ofproto, ofp_port);
    return (ofport && ofproto->ofproto_class->port_is_lacp_current
            ? ofproto->ofproto_class->port_is_lacp_current(ofport)
            : -1);
}

/* Bundles. */

/* Registers a "bundle" associated with client data pointer 'aux' in 'ofproto'.
 * A bundle is the same concept as a Port in OVSDB, that is, it consists of one
 * or more "slave" devices (Interfaces, in OVSDB) along with a VLAN
 * configuration plus, if there is more than one slave, a bonding
 * configuration.
 *
 * If 'aux' is already registered then this function updates its configuration
 * to 's'.  Otherwise, this function registers a new bundle.
 *
 * Bundles affect only the treatment of packets output to the OFPP_NORMAL
 * port.  */
int
ofproto_bundle_register(struct ofproto *ofproto, void *aux,
                        const struct ofproto_bundle_settings *s)
{
    return (ofproto->ofproto_class->bundle_set
            ? ofproto->ofproto_class->bundle_set(ofproto, aux, s)
            : EOPNOTSUPP);
}

/* Unregisters the bundle registered on 'ofproto' with auxiliary data 'aux'.
 * If no such bundle has been registered, this has no effect. */
int
ofproto_bundle_unregister(struct ofproto *ofproto, void *aux)
{
    return ofproto_bundle_register(ofproto, aux, NULL);
}


/* Registers a mirror associated with client data pointer 'aux' in 'ofproto'.
 * If 'aux' is already registered then this function updates its configuration
 * to 's'.  Otherwise, this function registers a new mirror.
 *
 * Mirrors affect only the treatment of packets output to the OFPP_NORMAL
 * port.  */
int
ofproto_mirror_register(struct ofproto *ofproto, void *aux,
                        const struct ofproto_mirror_settings *s)
{
    return (ofproto->ofproto_class->mirror_set
            ? ofproto->ofproto_class->mirror_set(ofproto, aux, s)
            : EOPNOTSUPP);
}

/* Unregisters the mirror registered on 'ofproto' with auxiliary data 'aux'.
 * If no mirror has been registered, this has no effect. */
int
ofproto_mirror_unregister(struct ofproto *ofproto, void *aux)
{
    return ofproto_mirror_register(ofproto, aux, NULL);
}

/* Configures the VLANs whose bits are set to 1 in 'flood_vlans' as VLANs on
 * which all packets are flooded, instead of using MAC learning.  If
 * 'flood_vlans' is NULL, then MAC learning applies to all VLANs.
 *
 * Flood VLANs affect only the treatment of packets output to the OFPP_NORMAL
 * port. */
int
ofproto_set_flood_vlans(struct ofproto *ofproto, unsigned long *flood_vlans)
{
    return (ofproto->ofproto_class->set_flood_vlans
            ? ofproto->ofproto_class->set_flood_vlans(ofproto, flood_vlans)
            : EOPNOTSUPP);
}

/* Returns true if 'aux' is a registered bundle that is currently in use as the
 * output for a mirror. */
bool
ofproto_is_mirror_output_bundle(struct ofproto *ofproto, void *aux)
{
    return (ofproto->ofproto_class->is_mirror_output_bundle
            ? ofproto->ofproto_class->is_mirror_output_bundle(ofproto, aux)
            : false);
}

bool
ofproto_has_snoops(const struct ofproto *ofproto)
{
    return connmgr_has_snoops(ofproto->connmgr);
}

void
ofproto_get_snoops(const struct ofproto *ofproto, struct sset *snoops)
{
    connmgr_get_snoops(ofproto->connmgr, snoops);
}

static void
ofproto_destroy__(struct ofproto *ofproto)
{
    connmgr_destroy(ofproto->connmgr);

    hmap_remove(&all_ofprotos, &ofproto->hmap_node);
    free(ofproto->name);
    free(ofproto->mfr_desc);
    free(ofproto->hw_desc);
    free(ofproto->sw_desc);
    free(ofproto->serial_desc);
    free(ofproto->dp_desc);
    netdev_monitor_destroy(ofproto->netdev_monitor);
    hmap_destroy(&ofproto->ports);
    shash_destroy(&ofproto->port_by_name);
    classifier_destroy(&ofproto->cls);

    ofproto->ofproto_class->dealloc(ofproto);
}

void
ofproto_destroy(struct ofproto *p)
{
    struct ofport *ofport, *next_ofport;

    if (!p) {
        return;
    }

    ofproto_flush_flows__(p);
    HMAP_FOR_EACH_SAFE (ofport, next_ofport, hmap_node, &p->ports) {
        hmap_remove(&p->ports, &ofport->hmap_node);
        ofport_destroy(ofport);
    }

    p->ofproto_class->destruct(p);
    ofproto_destroy__(p);
}

int
ofproto_delete(const char *name, const char *type)
{
    const struct ofproto_class *class = ofproto_class_find__(type);
    return (!class ? EAFNOSUPPORT
            : !class->del ? EACCES
            : class->del(type, name));
}

static void
process_port_change(struct ofproto *ofproto, int error, char *devname)
{
    if (error == ENOBUFS) {
        reinit_ports(ofproto);
    } else if (!error) {
        update_port(ofproto, devname);
        free(devname);
    }
}

int
ofproto_run(struct ofproto *p)
{
    char *devname;
    int error;

    error = p->ofproto_class->run(p);
    if (error == ENODEV) {
        /* Someone destroyed the datapath behind our back.  The caller
         * better destroy us and give up, because we're just going to
         * spin from here on out. */
        static struct vlog_rate_limit rl2 = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_ERR_RL(&rl2, "%s: datapath was destroyed externally",
                    p->name);
        return ENODEV;
    }

    while ((error = p->ofproto_class->port_poll(p, &devname)) != EAGAIN) {
        process_port_change(p, error, devname);
    }
    while ((error = netdev_monitor_poll(p->netdev_monitor,
                                        &devname)) != EAGAIN) {
        process_port_change(p, error, devname);
    }

    connmgr_run(p->connmgr, handle_openflow);

    return 0;
}

void
ofproto_wait(struct ofproto *p)
{
    p->ofproto_class->wait(p);
    p->ofproto_class->port_poll_wait(p);
    netdev_monitor_poll_wait(p->netdev_monitor);
    connmgr_wait(p->connmgr);
}

bool
ofproto_is_alive(const struct ofproto *p)
{
    return connmgr_has_controllers(p->connmgr);
}

void
ofproto_get_ofproto_controller_info(const struct ofproto *ofproto,
                                    struct shash *info)
{
    connmgr_get_controller_info(ofproto->connmgr, info);
}

void
ofproto_free_ofproto_controller_info(struct shash *info)
{
    struct shash_node *node;

    SHASH_FOR_EACH (node, info) {
        struct ofproto_controller_info *cinfo = node->data;
        while (cinfo->pairs.n) {
            free((char *) cinfo->pairs.values[--cinfo->pairs.n]);
        }
        free(cinfo);
    }
    shash_destroy(info);
}

/* Makes a deep copy of 'old' into 'port'. */
void
ofproto_port_clone(struct ofproto_port *port, const struct ofproto_port *old)
{
    port->name = xstrdup(old->name);
    port->type = xstrdup(old->type);
    port->ofp_port = old->ofp_port;
}

/* Frees memory allocated to members of 'ofproto_port'.
 *
 * Do not call this function on a ofproto_port obtained from
 * ofproto_port_dump_next(): that function retains ownership of the data in the
 * ofproto_port. */
void
ofproto_port_destroy(struct ofproto_port *ofproto_port)
{
    free(ofproto_port->name);
    free(ofproto_port->type);
}

/* Initializes 'dump' to begin dumping the ports in an ofproto.
 *
 * This function provides no status indication.  An error status for the entire
 * dump operation is provided when it is completed by calling
 * ofproto_port_dump_done().
 */
void
ofproto_port_dump_start(struct ofproto_port_dump *dump,
                        const struct ofproto *ofproto)
{
    dump->ofproto = ofproto;
    dump->error = ofproto->ofproto_class->port_dump_start(ofproto,
                                                          &dump->state);
}

/* Attempts to retrieve another port from 'dump', which must have been created
 * with ofproto_port_dump_start().  On success, stores a new ofproto_port into
 * 'port' and returns true.  On failure, returns false.
 *
 * Failure might indicate an actual error or merely that the last port has been
 * dumped.  An error status for the entire dump operation is provided when it
 * is completed by calling ofproto_port_dump_done().
 *
 * The ofproto owns the data stored in 'port'.  It will remain valid until at
 * least the next time 'dump' is passed to ofproto_port_dump_next() or
 * ofproto_port_dump_done(). */
bool
ofproto_port_dump_next(struct ofproto_port_dump *dump,
                       struct ofproto_port *port)
{
    const struct ofproto *ofproto = dump->ofproto;

    if (dump->error) {
        return false;
    }

    dump->error = ofproto->ofproto_class->port_dump_next(ofproto, dump->state,
                                                         port);
    if (dump->error) {
        ofproto->ofproto_class->port_dump_done(ofproto, dump->state);
        return false;
    }
    return true;
}

/* Completes port table dump operation 'dump', which must have been created
 * with ofproto_port_dump_start().  Returns 0 if the dump operation was
 * error-free, otherwise a positive errno value describing the problem. */
int
ofproto_port_dump_done(struct ofproto_port_dump *dump)
{
    const struct ofproto *ofproto = dump->ofproto;
    if (!dump->error) {
        dump->error = ofproto->ofproto_class->port_dump_done(ofproto,
                                                             dump->state);
    }
    return dump->error == EOF ? 0 : dump->error;
}

/* Attempts to add 'netdev' as a port on 'ofproto'.  If successful, returns 0
 * and sets '*ofp_portp' to the new port's OpenFlow port number (if 'ofp_portp'
 * is non-null).  On failure, returns a positive errno value and sets
 * '*ofp_portp' to OFPP_NONE (if 'ofp_portp' is non-null). */
int
ofproto_port_add(struct ofproto *ofproto, struct netdev *netdev,
                 uint16_t *ofp_portp)
{
    uint16_t ofp_port;
    int error;

    error = ofproto->ofproto_class->port_add(ofproto, netdev, &ofp_port);
    if (!error) {
        update_port(ofproto, netdev_get_name(netdev));
    }
    if (ofp_portp) {
        *ofp_portp = error ? OFPP_NONE : ofp_port;
    }
    return error;
}

/* Looks up a port named 'devname' in 'ofproto'.  On success, returns 0 and
 * initializes '*port' appropriately; on failure, returns a positive errno
 * value.
 *
 * The caller owns the data in 'ofproto_port' and must free it with
 * ofproto_port_destroy() when it is no longer needed. */
int
ofproto_port_query_by_name(const struct ofproto *ofproto, const char *devname,
                           struct ofproto_port *port)
{
    int error;

    error = ofproto->ofproto_class->port_query_by_name(ofproto, devname, port);
    if (error) {
        memset(port, 0, sizeof *port);
    }
    return error;
}

/* Deletes port number 'ofp_port' from the datapath for 'ofproto'.
 * Returns 0 if successful, otherwise a positive errno. */
int
ofproto_port_del(struct ofproto *ofproto, uint16_t ofp_port)
{
    struct ofport *ofport = ofproto_get_port(ofproto, ofp_port);
    const char *name = ofport ? netdev_get_name(ofport->netdev) : "<unknown>";
    int error;

    error = ofproto->ofproto_class->port_del(ofproto, ofp_port);
    if (!error && ofport) {
        /* 'name' is the netdev's name and update_port() is going to close the
         * netdev.  Just in case update_port() refers to 'name' after it
         * destroys 'ofport', make a copy of it around the update_port()
         * call. */
        char *devname = xstrdup(name);
        update_port(ofproto, devname);
        free(devname);
    }
    return error;
}

/* Adds a flow to the OpenFlow flow table in 'p' that matches 'cls_rule' and
 * performs the 'n_actions' actions in 'actions'.  The new flow will not
 * timeout.
 *
 * If cls_rule->priority is in the range of priorities supported by OpenFlow
 * (0...65535, inclusive) then the flow will be visible to OpenFlow
 * controllers; otherwise, it will be hidden.
 *
 * The caller retains ownership of 'cls_rule' and 'actions'. */
void
ofproto_add_flow(struct ofproto *p, const struct cls_rule *cls_rule,
                 const union ofp_action *actions, size_t n_actions)
{
    struct rule *rule;
    rule_create(p, cls_rule, actions, n_actions, 0, 0, 0, false, &rule);
}

void
ofproto_delete_flow(struct ofproto *ofproto, const struct cls_rule *target)
{
    struct rule *rule;

    rule = rule_from_cls_rule(classifier_find_rule_exactly(&ofproto->cls,
                                                           target));
    if (rule) {
        ofproto_rule_remove(rule);
    }
}

static void
ofproto_flush_flows__(struct ofproto *ofproto)
{
    struct rule *rule, *next_rule;
    struct cls_cursor cursor;

    COVERAGE_INC(ofproto_flush);

    if (ofproto->ofproto_class->flush) {
        ofproto->ofproto_class->flush(ofproto);
    }

    cls_cursor_init(&cursor, &ofproto->cls, NULL);
    CLS_CURSOR_FOR_EACH_SAFE (rule, next_rule, cr, &cursor) {
        ofproto_rule_remove(rule);
    }
}

void
ofproto_flush_flows(struct ofproto *ofproto)
{
    ofproto_flush_flows__(ofproto);
    connmgr_flushed(ofproto->connmgr);
}

static void
reinit_ports(struct ofproto *p)
{
    struct ofproto_port_dump dump;
    struct sset devnames;
    struct ofport *ofport;
    struct ofproto_port ofproto_port;
    const char *devname;

    COVERAGE_INC(ofproto_reinit_ports);

    sset_init(&devnames);
    HMAP_FOR_EACH (ofport, hmap_node, &p->ports) {
        sset_add(&devnames, netdev_get_name(ofport->netdev));
    }
    OFPROTO_PORT_FOR_EACH (&ofproto_port, &dump, p) {
        sset_add(&devnames, ofproto_port.name);
    }

    SSET_FOR_EACH (devname, &devnames) {
        update_port(p, devname);
    }
    sset_destroy(&devnames);
}

/* Opens and returns a netdev for 'ofproto_port', or a null pointer if the
 * netdev cannot be opened.  On success, also fills in 'opp'.  */
static struct netdev *
ofport_open(const struct ofproto_port *ofproto_port, struct ofp_phy_port *opp)
{
    uint32_t curr, advertised, supported, peer;
    struct netdev_options netdev_options;
    enum netdev_flags flags;
    struct netdev *netdev;
    int error;

    memset(&netdev_options, 0, sizeof netdev_options);
    netdev_options.name = ofproto_port->name;
    netdev_options.type = ofproto_port->type;
    netdev_options.ethertype = NETDEV_ETH_TYPE_NONE;

    error = netdev_open(&netdev_options, &netdev);
    if (error) {
        VLOG_WARN_RL(&rl, "ignoring port %s (%"PRIu16") because netdev %s "
                     "cannot be opened (%s)",
                     ofproto_port->name, ofproto_port->ofp_port,
                     ofproto_port->name, strerror(error));
        return NULL;
    }

    netdev_get_flags(netdev, &flags);
    netdev_get_features(netdev, &curr, &advertised, &supported, &peer);

    opp->port_no = htons(ofproto_port->ofp_port);
    netdev_get_etheraddr(netdev, opp->hw_addr);
    ovs_strzcpy(opp->name, ofproto_port->name, sizeof opp->name);
    opp->config = flags & NETDEV_UP ? 0 : htonl(OFPPC_PORT_DOWN);
    opp->state = netdev_get_carrier(netdev) ? 0 : htonl(OFPPS_LINK_DOWN);
    opp->curr = htonl(curr);
    opp->advertised = htonl(advertised);
    opp->supported = htonl(supported);
    opp->peer = htonl(peer);

    return netdev;
}

/* Returns true if most fields of 'a' and 'b' are equal.  Differences in name,
 * port number, and 'config' bits other than OFPPC_PORT_DOWN are
 * disregarded. */
static bool
ofport_equal(const struct ofp_phy_port *a, const struct ofp_phy_port *b)
{
    BUILD_ASSERT_DECL(sizeof *a == 48); /* Detect ofp_phy_port changes. */
    return (!memcmp(a->hw_addr, b->hw_addr, sizeof a->hw_addr)
            && a->state == b->state
            && !((a->config ^ b->config) & htonl(OFPPC_PORT_DOWN))
            && a->curr == b->curr
            && a->advertised == b->advertised
            && a->supported == b->supported
            && a->peer == b->peer);
}

/* Adds an ofport to 'p' initialized based on the given 'netdev' and 'opp'.
 * The caller must ensure that 'p' does not have a conflicting ofport (that is,
 * one with the same name or port number). */
static void
ofport_install(struct ofproto *p,
               struct netdev *netdev, const struct ofp_phy_port *opp)
{
    const char *netdev_name = netdev_get_name(netdev);
    struct ofport *ofport;
    int error;

    /* Create ofport. */
    ofport = p->ofproto_class->port_alloc();
    if (!ofport) {
        error = ENOMEM;
        goto error;
    }
    ofport->ofproto = p;
    ofport->netdev = netdev;
    ofport->opp = *opp;
    ofport->ofp_port = ntohs(opp->port_no);

    /* Add port to 'p'. */
    netdev_monitor_add(p->netdev_monitor, ofport->netdev);
    hmap_insert(&p->ports, &ofport->hmap_node, hash_int(ofport->ofp_port, 0));
    shash_add(&p->port_by_name, netdev_name, ofport);

    /* Let the ofproto_class initialize its private data. */
    error = p->ofproto_class->port_construct(ofport);
    if (error) {
        goto error;
    }
    connmgr_send_port_status(p->connmgr, opp, OFPPR_ADD);
    return;

error:
    VLOG_WARN_RL(&rl, "%s: could not add port %s (%s)",
                 p->name, netdev_name, strerror(error));
    if (ofport) {
        ofport_destroy__(ofport);
    } else {
        netdev_close(netdev);
    }
}

/* Removes 'ofport' from 'p' and destroys it. */
static void
ofport_remove(struct ofport *ofport)
{
    connmgr_send_port_status(ofport->ofproto->connmgr, &ofport->opp,
                             OFPPR_DELETE);
    ofport_destroy(ofport);
}

/* If 'ofproto' contains an ofport named 'name', removes it from 'ofproto' and
 * destroys it. */
static void
ofport_remove_with_name(struct ofproto *ofproto, const char *name)
{
    struct ofport *port = shash_find_data(&ofproto->port_by_name, name);
    if (port) {
        ofport_remove(port);
    }
}

/* Updates 'port' within 'ofproto' with the new 'netdev' and 'opp'.
 *
 * Does not handle a name or port number change.  The caller must implement
 * such a change as a delete followed by an add.  */
static void
ofport_modified(struct ofport *port, struct ofp_phy_port *opp)
{
    memcpy(port->opp.hw_addr, opp->hw_addr, ETH_ADDR_LEN);
    port->opp.config = ((port->opp.config & ~htonl(OFPPC_PORT_DOWN))
                        | (opp->config & htonl(OFPPC_PORT_DOWN)));
    port->opp.state = opp->state;
    port->opp.curr = opp->curr;
    port->opp.advertised = opp->advertised;
    port->opp.supported = opp->supported;
    port->opp.peer = opp->peer;

    connmgr_send_port_status(port->ofproto->connmgr, &port->opp, OFPPR_MODIFY);
}

void
ofproto_port_unregister(struct ofproto *ofproto, uint16_t ofp_port)
{
    struct ofport *port = ofproto_get_port(ofproto, ofp_port);
    if (port) {
        if (port->ofproto->ofproto_class->set_cfm) {
            port->ofproto->ofproto_class->set_cfm(port, NULL, NULL, 0);
        }
        if (port->ofproto->ofproto_class->bundle_remove) {
            port->ofproto->ofproto_class->bundle_remove(port);
        }
    }
}

static void
ofport_destroy__(struct ofport *port)
{
    struct ofproto *ofproto = port->ofproto;
    const char *name = netdev_get_name(port->netdev);

    netdev_monitor_remove(ofproto->netdev_monitor, port->netdev);
    hmap_remove(&ofproto->ports, &port->hmap_node);
    shash_delete(&ofproto->port_by_name,
                 shash_find(&ofproto->port_by_name, name));

    netdev_close(port->netdev);
    ofproto->ofproto_class->port_dealloc(port);
}

static void
ofport_destroy(struct ofport *port)
{
    if (port) {
        port->ofproto->ofproto_class->port_destruct(port);
        ofport_destroy__(port);
     }
}

struct ofport *
ofproto_get_port(const struct ofproto *ofproto, uint16_t ofp_port)
{
    struct ofport *port;

    HMAP_FOR_EACH_IN_BUCKET (port, hmap_node,
                             hash_int(ofp_port, 0), &ofproto->ports) {
        if (port->ofp_port == ofp_port) {
            return port;
        }
    }
    return NULL;
}

static void
update_port(struct ofproto *ofproto, const char *name)
{
    struct ofproto_port ofproto_port;
    struct ofp_phy_port opp;
    struct netdev *netdev;
    struct ofport *port;

    COVERAGE_INC(ofproto_update_port);

    /* Fetch 'name''s location and properties from the datapath. */
    netdev = (!ofproto_port_query_by_name(ofproto, name, &ofproto_port)
              ? ofport_open(&ofproto_port, &opp)
              : NULL);
    if (netdev) {
        port = ofproto_get_port(ofproto, ofproto_port.ofp_port);
        if (port && !strcmp(netdev_get_name(port->netdev), name)) {
            /* 'name' hasn't changed location.  Any properties changed? */
            if (!ofport_equal(&port->opp, &opp)) {
                ofport_modified(port, &opp);
            }

            /* Install the newly opened netdev in case it has changed. */
            netdev_monitor_remove(ofproto->netdev_monitor, port->netdev);
            netdev_monitor_add(ofproto->netdev_monitor, netdev);

            netdev_close(port->netdev);
            port->netdev = netdev;

            if (port->ofproto->ofproto_class->port_modified) {
                port->ofproto->ofproto_class->port_modified(port);
            }
        } else {
            /* If 'port' is nonnull then its name differs from 'name' and thus
             * we should delete it.  If we think there's a port named 'name'
             * then its port number must be wrong now so delete it too. */
            if (port) {
                ofport_remove(port);
            }
            ofport_remove_with_name(ofproto, name);
            ofport_install(ofproto, netdev, &opp);
        }
    } else {
        /* Any port named 'name' is gone now. */
        ofport_remove_with_name(ofproto, name);
    }
    ofproto_port_destroy(&ofproto_port);
}

static int
init_ports(struct ofproto *p)
{
    struct ofproto_port_dump dump;
    struct ofproto_port ofproto_port;

    OFPROTO_PORT_FOR_EACH (&ofproto_port, &dump, p) {
        uint16_t ofp_port = ofproto_port.ofp_port;
        if (ofproto_get_port(p, ofp_port)) {
            VLOG_WARN_RL(&rl, "ignoring duplicate port %"PRIu16" in datapath",
                         ofp_port);
        } else if (shash_find(&p->port_by_name, ofproto_port.name)) {
            VLOG_WARN_RL(&rl, "ignoring duplicate device %s in datapath",
                         ofproto_port.name);
        } else {
            struct ofp_phy_port opp;
            struct netdev *netdev;

            netdev = ofport_open(&ofproto_port, &opp);
            if (netdev) {
                ofport_install(p, netdev, &opp);
            }
        }
    }

    return 0;
}

/* Creates a new rule initialized as specified, inserts it into 'ofproto''s
 * flow table, and stores the new rule into '*rulep'.  Returns 0 on success,
 * otherwise a positive errno value or OpenFlow error code. */
static int
rule_create(struct ofproto *ofproto, const struct cls_rule *cls_rule,
            const union ofp_action *actions, size_t n_actions,
            uint16_t idle_timeout, uint16_t hard_timeout,
            ovs_be64 flow_cookie, bool send_flow_removed,
            struct rule **rulep)
{
    struct rule *rule;
    int error;

    rule = ofproto->ofproto_class->rule_alloc();
    if (!rule) {
        error = ENOMEM;
        goto error;
    }

    rule->ofproto = ofproto;
    rule->created = time_msec();
    rule->flow_cookie = flow_cookie;
    rule->cr = *cls_rule;
    rule->idle_timeout = idle_timeout;
    rule->hard_timeout = hard_timeout;
    rule->send_flow_removed = send_flow_removed;
    if (n_actions > 0) {
        rule->n_actions = n_actions;
        rule->actions = xmemdup(actions, n_actions * sizeof *actions);
    }

    error = ofproto->ofproto_class->rule_construct(rule);
    if (error) {
        ofproto_rule_destroy__(rule);
        goto error;
    }

    *rulep = rule;
    return 0;

error:
    VLOG_WARN_RL(&rl, "%s: failed to create rule (%s)",
                 ofproto->name, strerror(error));
    *rulep = NULL;
    return error;
}

static void
ofproto_rule_destroy__(struct rule *rule)
{
    free(rule->actions);
    rule->ofproto->ofproto_class->rule_dealloc(rule);
}

/* Destroys 'rule' and iterates through all of its facets and revalidates them,
 * destroying any that no longer has a rule (which is probably all of them).
 *
 * The caller must have already removed 'rule' from the classifier. */
void
ofproto_rule_destroy(struct rule *rule)
{
    rule->ofproto->ofproto_class->rule_destruct(rule);
    ofproto_rule_destroy__(rule);
}

/* Returns true if 'rule' has an OpenFlow OFPAT_OUTPUT or OFPAT_ENQUEUE action
 * that outputs to 'out_port' (output to OFPP_FLOOD and OFPP_ALL doesn't
 * count). */
static bool
rule_has_out_port(const struct rule *rule, ovs_be16 out_port)
{
    const union ofp_action *oa;
    struct actions_iterator i;

    if (out_port == htons(OFPP_NONE)) {
        return true;
    }
    for (oa = actions_first(&i, rule->actions, rule->n_actions); oa;
         oa = actions_next(&i)) {
        if (action_outputs_to_port(oa, out_port)) {
            return true;
        }
    }
    return false;
}

struct rule *
ofproto_rule_lookup(struct ofproto *ofproto, const struct flow *flow)
{
    return rule_from_cls_rule(classifier_lookup(&ofproto->cls, flow));
}

/* Executes the actions indicated by 'rule' on 'packet' and credits 'rule''s
 * statistics (or the statistics for one of its facets) appropriately.
 * 'packet' must have at least sizeof(struct ofp_packet_in) bytes of headroom.
 *
 * 'packet' doesn't necessarily have to match 'rule'.  'rule' will be credited
 * with statistics for 'packet' either way.
 *
 * Takes ownership of 'packet'. */
static void
rule_execute(struct rule *rule, uint16_t in_port, struct ofpbuf *packet)
{
    struct flow flow;

    assert(ofpbuf_headroom(packet) >= sizeof(struct ofp_packet_in));

    flow_extract(packet, 0, in_port, &flow);
    rule->ofproto->ofproto_class->rule_execute(rule, &flow, packet);
}

/* Remove 'rule' from 'ofproto' and free up the associated memory:
 *
 *   - Removes 'rule' from the classifier.
 *
 *   - If 'rule' has facets, revalidates them (and possibly uninstalls and
 *     destroys them), via rule_destroy().
 */
void
ofproto_rule_remove(struct rule *rule)
{
    rule->ofproto->ofproto_class->rule_remove(rule);
    ofproto_rule_destroy(rule);
}

/* Returns true if 'rule' should be hidden from the controller.
 *
 * Rules with priority higher than UINT16_MAX are set up by ofproto itself
 * (e.g. by in-band control) and are intentionally hidden from the
 * controller. */
static bool
rule_is_hidden(const struct rule *rule)
{
    return rule->cr.priority > UINT16_MAX;
}

static void
send_error_oh(const struct ofconn *ofconn, const struct ofp_header *oh,
              int error)
{
    struct ofpbuf *buf = ofputil_encode_error_msg(error, oh);
    if (buf) {
        COVERAGE_INC(ofproto_error);
        ofconn_send_reply(ofconn, buf);
    }
}

static int
handle_echo_request(struct ofconn *ofconn, const struct ofp_header *oh)
{
    ofconn_send_reply(ofconn, make_echo_reply(oh));
    return 0;
}

static int
handle_features_request(struct ofconn *ofconn, const struct ofp_header *oh)
{
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    struct ofp_switch_features *osf;
    struct ofpbuf *buf;
    struct ofport *port;

    osf = make_openflow_xid(sizeof *osf, OFPT_FEATURES_REPLY, oh->xid, &buf);
    osf->datapath_id = htonll(ofproto->datapath_id);
    osf->n_buffers = htonl(pktbuf_capacity());
    osf->n_tables = 2;
    osf->capabilities = htonl(OFPC_FLOW_STATS | OFPC_TABLE_STATS |
                              OFPC_PORT_STATS | OFPC_ARP_MATCH_IP);
    osf->actions = htonl((1u << OFPAT_OUTPUT) |
                         (1u << OFPAT_SET_VLAN_VID) |
                         (1u << OFPAT_SET_VLAN_PCP) |
                         (1u << OFPAT_STRIP_VLAN) |
                         (1u << OFPAT_SET_DL_SRC) |
                         (1u << OFPAT_SET_DL_DST) |
                         (1u << OFPAT_SET_NW_SRC) |
                         (1u << OFPAT_SET_NW_DST) |
                         (1u << OFPAT_SET_NW_TOS) |
                         (1u << OFPAT_SET_TP_SRC) |
                         (1u << OFPAT_SET_TP_DST) |
                         (1u << OFPAT_ENQUEUE));

    HMAP_FOR_EACH (port, hmap_node, &ofproto->ports) {
        ofpbuf_put(buf, &port->opp, sizeof port->opp);
    }

    ofconn_send_reply(ofconn, buf);
    return 0;
}

static int
handle_get_config_request(struct ofconn *ofconn, const struct ofp_header *oh)
{
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    struct ofpbuf *buf;
    struct ofp_switch_config *osc;
    uint16_t flags;
    bool drop_frags;

    /* Figure out flags. */
    drop_frags = ofproto->ofproto_class->get_drop_frags(ofproto);
    flags = drop_frags ? OFPC_FRAG_DROP : OFPC_FRAG_NORMAL;

    /* Send reply. */
    osc = make_openflow_xid(sizeof *osc, OFPT_GET_CONFIG_REPLY, oh->xid, &buf);
    osc->flags = htons(flags);
    osc->miss_send_len = htons(ofconn_get_miss_send_len(ofconn));
    ofconn_send_reply(ofconn, buf);

    return 0;
}

static int
handle_set_config(struct ofconn *ofconn, const struct ofp_switch_config *osc)
{
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    uint16_t flags = ntohs(osc->flags);

    if (ofconn_get_type(ofconn) == OFCONN_PRIMARY
        && ofconn_get_role(ofconn) != NX_ROLE_SLAVE) {
        switch (flags & OFPC_FRAG_MASK) {
        case OFPC_FRAG_NORMAL:
            ofproto->ofproto_class->set_drop_frags(ofproto, false);
            break;
        case OFPC_FRAG_DROP:
            ofproto->ofproto_class->set_drop_frags(ofproto, true);
            break;
        default:
            VLOG_WARN_RL(&rl, "requested bad fragment mode (flags=%"PRIx16")",
                         osc->flags);
            break;
        }
    }

    ofconn_set_miss_send_len(ofconn, ntohs(osc->miss_send_len));

    return 0;
}

/* Checks whether 'ofconn' is a slave controller.  If so, returns an OpenFlow
 * error message code (composed with ofp_mkerr()) for the caller to propagate
 * upward.  Otherwise, returns 0.
 *
 * The log message mentions 'msg_type'. */
static int
reject_slave_controller(struct ofconn *ofconn, const const char *msg_type)
{
    if (ofconn_get_type(ofconn) == OFCONN_PRIMARY
        && ofconn_get_role(ofconn) == NX_ROLE_SLAVE) {
        static struct vlog_rate_limit perm_rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&perm_rl, "rejecting %s message from slave controller",
                     msg_type);

        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_EPERM);
    } else {
        return 0;
    }
}

static int
handle_packet_out(struct ofconn *ofconn, const struct ofp_header *oh)
{
    struct ofproto *p = ofconn_get_ofproto(ofconn);
    struct ofp_packet_out *opo;
    struct ofpbuf payload, *buffer;
    union ofp_action *ofp_actions;
    struct ofpbuf request;
    struct flow flow;
    size_t n_ofp_actions;
    uint16_t in_port;
    int error;

    COVERAGE_INC(ofproto_packet_out);

    error = reject_slave_controller(ofconn, "OFPT_PACKET_OUT");
    if (error) {
        return error;
    }

    /* Get ofp_packet_out. */
    ofpbuf_use_const(&request, oh, ntohs(oh->length));
    opo = ofpbuf_pull(&request, offsetof(struct ofp_packet_out, actions));

    /* Get actions. */
    error = ofputil_pull_actions(&request, ntohs(opo->actions_len),
                                 &ofp_actions, &n_ofp_actions);
    if (error) {
        return error;
    }

    /* Get payload. */
    if (opo->buffer_id != htonl(UINT32_MAX)) {
        error = ofconn_pktbuf_retrieve(ofconn, ntohl(opo->buffer_id),
                                       &buffer, &in_port);
        if (error || !buffer) {
            return error;
        }
        payload = *buffer;
    } else {
        payload = request;
        buffer = NULL;
    }

    /* Send out packet. */
    flow_extract(&payload, 0, ntohs(opo->in_port), &flow);
    error = p->ofproto_class->packet_out(p, &payload, &flow,
                                         ofp_actions, n_ofp_actions);
    ofpbuf_delete(buffer);

    return error;
}

static void
update_port_config(struct ofport *port, ovs_be32 config, ovs_be32 mask)
{
    ovs_be32 old_config = port->opp.config;

    mask &= config ^ port->opp.config;
    if (mask & htonl(OFPPC_PORT_DOWN)) {
        if (config & htonl(OFPPC_PORT_DOWN)) {
            netdev_turn_flags_off(port->netdev, NETDEV_UP, true);
        } else {
            netdev_turn_flags_on(port->netdev, NETDEV_UP, true);
        }
    }

    port->opp.config ^= mask & (htonl(OFPPC_NO_RECV | OFPPC_NO_RECV_STP |
                                      OFPPC_NO_FLOOD | OFPPC_NO_FWD |
                                      OFPPC_NO_PACKET_IN));
    if (port->opp.config != old_config) {
        port->ofproto->ofproto_class->port_reconfigured(port, old_config);
    }
}

static int
handle_port_mod(struct ofconn *ofconn, const struct ofp_header *oh)
{
    struct ofproto *p = ofconn_get_ofproto(ofconn);
    const struct ofp_port_mod *opm = (const struct ofp_port_mod *) oh;
    struct ofport *port;
    int error;

    error = reject_slave_controller(ofconn, "OFPT_PORT_MOD");
    if (error) {
        return error;
    }

    port = ofproto_get_port(p, ntohs(opm->port_no));
    if (!port) {
        return ofp_mkerr(OFPET_PORT_MOD_FAILED, OFPPMFC_BAD_PORT);
    } else if (memcmp(port->opp.hw_addr, opm->hw_addr, OFP_ETH_ALEN)) {
        return ofp_mkerr(OFPET_PORT_MOD_FAILED, OFPPMFC_BAD_HW_ADDR);
    } else {
        update_port_config(port, opm->config, opm->mask);
        if (opm->advertise) {
            netdev_set_advertisements(port->netdev, ntohl(opm->advertise));
        }
    }
    return 0;
}

static struct ofpbuf *
make_ofp_stats_reply(ovs_be32 xid, ovs_be16 type, size_t body_len)
{
    struct ofp_stats_reply *osr;
    struct ofpbuf *msg;

    msg = ofpbuf_new(MIN(sizeof *osr + body_len, UINT16_MAX));
    osr = put_openflow_xid(sizeof *osr, OFPT_STATS_REPLY, xid, msg);
    osr->type = type;
    osr->flags = htons(0);
    return msg;
}

static struct ofpbuf *
start_ofp_stats_reply(const struct ofp_header *request, size_t body_len)
{
    const struct ofp_stats_request *osr
        = (const struct ofp_stats_request *) request;
    return make_ofp_stats_reply(osr->header.xid, osr->type, body_len);
}

static void *
append_ofp_stats_reply(size_t nbytes, struct ofconn *ofconn,
                       struct ofpbuf **msgp)
{
    struct ofpbuf *msg = *msgp;
    assert(nbytes <= UINT16_MAX - sizeof(struct ofp_stats_reply));
    if (nbytes + msg->size > UINT16_MAX) {
        struct ofp_stats_reply *reply = msg->data;
        reply->flags = htons(OFPSF_REPLY_MORE);
        *msgp = make_ofp_stats_reply(reply->header.xid, reply->type, nbytes);
        ofconn_send_reply(ofconn, msg);
    }
    return ofpbuf_put_uninit(*msgp, nbytes);
}

static struct ofpbuf *
make_nxstats_reply(ovs_be32 xid, ovs_be32 subtype, size_t body_len)
{
    struct nicira_stats_msg *nsm;
    struct ofpbuf *msg;

    msg = ofpbuf_new(MIN(sizeof *nsm + body_len, UINT16_MAX));
    nsm = put_openflow_xid(sizeof *nsm, OFPT_STATS_REPLY, xid, msg);
    nsm->type = htons(OFPST_VENDOR);
    nsm->flags = htons(0);
    nsm->vendor = htonl(NX_VENDOR_ID);
    nsm->subtype = subtype;
    return msg;
}

static struct ofpbuf *
start_nxstats_reply(const struct nicira_stats_msg *request, size_t body_len)
{
    return make_nxstats_reply(request->header.xid, request->subtype, body_len);
}

static void
append_nxstats_reply(size_t nbytes, struct ofconn *ofconn,
                     struct ofpbuf **msgp)
{
    struct ofpbuf *msg = *msgp;
    assert(nbytes <= UINT16_MAX - sizeof(struct nicira_stats_msg));
    if (nbytes + msg->size > UINT16_MAX) {
        struct nicira_stats_msg *reply = msg->data;
        reply->flags = htons(OFPSF_REPLY_MORE);
        *msgp = make_nxstats_reply(reply->header.xid, reply->subtype, nbytes);
        ofconn_send_reply(ofconn, msg);
    }
    ofpbuf_prealloc_tailroom(*msgp, nbytes);
}

static int
handle_desc_stats_request(struct ofconn *ofconn,
                          const struct ofp_header *request)
{
    struct ofproto *p = ofconn_get_ofproto(ofconn);
    struct ofp_desc_stats *ods;
    struct ofpbuf *msg;

    msg = start_ofp_stats_reply(request, sizeof *ods);
    ods = append_ofp_stats_reply(sizeof *ods, ofconn, &msg);
    memset(ods, 0, sizeof *ods);
    ovs_strlcpy(ods->mfr_desc, p->mfr_desc, sizeof ods->mfr_desc);
    ovs_strlcpy(ods->hw_desc, p->hw_desc, sizeof ods->hw_desc);
    ovs_strlcpy(ods->sw_desc, p->sw_desc, sizeof ods->sw_desc);
    ovs_strlcpy(ods->serial_num, p->serial_desc, sizeof ods->serial_num);
    ovs_strlcpy(ods->dp_desc, p->dp_desc, sizeof ods->dp_desc);
    ofconn_send_reply(ofconn, msg);

    return 0;
}

static int
handle_table_stats_request(struct ofconn *ofconn,
                           const struct ofp_header *request)
{
    struct ofproto *p = ofconn_get_ofproto(ofconn);
    struct ofp_table_stats *ots;
    struct ofpbuf *msg;

    msg = start_ofp_stats_reply(request, sizeof *ots * 2);

    /* Classifier table. */
    ots = append_ofp_stats_reply(sizeof *ots, ofconn, &msg);
    memset(ots, 0, sizeof *ots);
    strcpy(ots->name, "classifier");
    ots->wildcards = (ofconn_get_flow_format(ofconn) == NXFF_OPENFLOW10
                      ? htonl(OFPFW_ALL) : htonl(OVSFW_ALL));
    ots->max_entries = htonl(1024 * 1024); /* An arbitrary big number. */
    ots->active_count = htonl(classifier_count(&p->cls));
    put_32aligned_be64(&ots->lookup_count, htonll(0));  /* XXX */
    put_32aligned_be64(&ots->matched_count, htonll(0)); /* XXX */

    ofconn_send_reply(ofconn, msg);
    return 0;
}

static void
append_port_stat(struct ofport *port, struct ofconn *ofconn,
                 struct ofpbuf **msgp)
{
    struct netdev_stats stats;
    struct ofp_port_stats *ops;

    /* Intentionally ignore return value, since errors will set
     * 'stats' to all-1s, which is correct for OpenFlow, and
     * netdev_get_stats() will log errors. */
    netdev_get_stats(port->netdev, &stats);

    ops = append_ofp_stats_reply(sizeof *ops, ofconn, msgp);
    ops->port_no = port->opp.port_no;
    memset(ops->pad, 0, sizeof ops->pad);
    put_32aligned_be64(&ops->rx_packets, htonll(stats.rx_packets));
    put_32aligned_be64(&ops->tx_packets, htonll(stats.tx_packets));
    put_32aligned_be64(&ops->rx_bytes, htonll(stats.rx_bytes));
    put_32aligned_be64(&ops->tx_bytes, htonll(stats.tx_bytes));
    put_32aligned_be64(&ops->rx_dropped, htonll(stats.rx_dropped));
    put_32aligned_be64(&ops->tx_dropped, htonll(stats.tx_dropped));
    put_32aligned_be64(&ops->rx_errors, htonll(stats.rx_errors));
    put_32aligned_be64(&ops->tx_errors, htonll(stats.tx_errors));
    put_32aligned_be64(&ops->rx_frame_err, htonll(stats.rx_frame_errors));
    put_32aligned_be64(&ops->rx_over_err, htonll(stats.rx_over_errors));
    put_32aligned_be64(&ops->rx_crc_err, htonll(stats.rx_crc_errors));
    put_32aligned_be64(&ops->collisions, htonll(stats.collisions));
}

static int
handle_port_stats_request(struct ofconn *ofconn, const struct ofp_header *oh)
{
    struct ofproto *p = ofconn_get_ofproto(ofconn);
    const struct ofp_port_stats_request *psr = ofputil_stats_body(oh);
    struct ofp_port_stats *ops;
    struct ofpbuf *msg;
    struct ofport *port;

    msg = start_ofp_stats_reply(oh, sizeof *ops * 16);
    if (psr->port_no != htons(OFPP_NONE)) {
        port = ofproto_get_port(p, ntohs(psr->port_no));
        if (port) {
            append_port_stat(port, ofconn, &msg);
        }
    } else {
        HMAP_FOR_EACH (port, hmap_node, &p->ports) {
            append_port_stat(port, ofconn, &msg);
        }
    }

    ofconn_send_reply(ofconn, msg);
    return 0;
}

static void
calc_flow_duration__(long long int start, uint32_t *sec, uint32_t *nsec)
{
    long long int msecs = time_msec() - start;
    *sec = msecs / 1000;
    *nsec = (msecs % 1000) * (1000 * 1000);
}

static void
calc_flow_duration(long long int start, ovs_be32 *sec_be, ovs_be32 *nsec_be)
{
    uint32_t sec, nsec;

    calc_flow_duration__(start, &sec, &nsec);
    *sec_be = htonl(sec);
    *nsec_be = htonl(nsec);
}

static void
put_ofp_flow_stats(struct ofconn *ofconn, struct rule *rule,
                   ovs_be16 out_port, struct ofpbuf **replyp)
{
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    struct ofp_flow_stats *ofs;
    uint64_t packet_count, byte_count;
    ovs_be64 cookie;
    size_t act_len, len;

    if (rule_is_hidden(rule) || !rule_has_out_port(rule, out_port)) {
        return;
    }

    act_len = sizeof *rule->actions * rule->n_actions;
    len = offsetof(struct ofp_flow_stats, actions) + act_len;

    ofproto->ofproto_class->rule_get_stats(rule, &packet_count, &byte_count);

    ofs = append_ofp_stats_reply(len, ofconn, replyp);
    ofs->length = htons(len);
    ofs->table_id = 0;
    ofs->pad = 0;
    ofputil_cls_rule_to_match(&rule->cr, ofconn_get_flow_format(ofconn),
                              &ofs->match, rule->flow_cookie, &cookie);
    put_32aligned_be64(&ofs->cookie, cookie);
    calc_flow_duration(rule->created, &ofs->duration_sec, &ofs->duration_nsec);
    ofs->priority = htons(rule->cr.priority);
    ofs->idle_timeout = htons(rule->idle_timeout);
    ofs->hard_timeout = htons(rule->hard_timeout);
    memset(ofs->pad2, 0, sizeof ofs->pad2);
    put_32aligned_be64(&ofs->packet_count, htonll(packet_count));
    put_32aligned_be64(&ofs->byte_count, htonll(byte_count));
    if (rule->n_actions > 0) {
        memcpy(ofs->actions, rule->actions, act_len);
    }
}

static bool
is_valid_table(uint8_t table_id)
{
    if (table_id == 0 || table_id == 0xff) {
        return true;
    } else {
        /* It would probably be better to reply with an error but there doesn't
         * seem to be any appropriate value, so that might just be
         * confusing. */
        VLOG_WARN_RL(&rl, "controller asked for invalid table %"PRIu8,
                     table_id);
        return false;
    }
}

static int
handle_flow_stats_request(struct ofconn *ofconn, const struct ofp_header *oh)
{
    const struct ofp_flow_stats_request *fsr = ofputil_stats_body(oh);
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    struct ofpbuf *reply;

    COVERAGE_INC(ofproto_flows_req);
    reply = start_ofp_stats_reply(oh, 1024);
    if (is_valid_table(fsr->table_id)) {
        struct cls_cursor cursor;
        struct cls_rule target;
        struct rule *rule;

        ofputil_cls_rule_from_match(&fsr->match, 0, NXFF_OPENFLOW10, 0,
                                    &target);
        cls_cursor_init(&cursor, &ofproto->cls, &target);
        CLS_CURSOR_FOR_EACH (rule, cr, &cursor) {
            put_ofp_flow_stats(ofconn, rule, fsr->out_port, &reply);
        }
    }
    ofconn_send_reply(ofconn, reply);

    return 0;
}

static void
put_nx_flow_stats(struct ofconn *ofconn, struct rule *rule,
                  ovs_be16 out_port, struct ofpbuf **replyp)
{
    struct nx_flow_stats *nfs;
    uint64_t packet_count, byte_count;
    size_t act_len, start_len;
    struct ofpbuf *reply;

    if (rule_is_hidden(rule) || !rule_has_out_port(rule, out_port)) {
        return;
    }

    rule->ofproto->ofproto_class->rule_get_stats(rule,
                                                 &packet_count, &byte_count);

    act_len = sizeof *rule->actions * rule->n_actions;

    append_nxstats_reply(sizeof *nfs + NXM_MAX_LEN + act_len, ofconn, replyp);
    start_len = (*replyp)->size;
    reply = *replyp;

    nfs = ofpbuf_put_uninit(reply, sizeof *nfs);
    nfs->table_id = 0;
    nfs->pad = 0;
    calc_flow_duration(rule->created, &nfs->duration_sec, &nfs->duration_nsec);
    nfs->cookie = rule->flow_cookie;
    nfs->priority = htons(rule->cr.priority);
    nfs->idle_timeout = htons(rule->idle_timeout);
    nfs->hard_timeout = htons(rule->hard_timeout);
    nfs->match_len = htons(nx_put_match(reply, &rule->cr));
    memset(nfs->pad2, 0, sizeof nfs->pad2);
    nfs->packet_count = htonll(packet_count);
    nfs->byte_count = htonll(byte_count);
    if (rule->n_actions > 0) {
        ofpbuf_put(reply, rule->actions, act_len);
    }
    nfs->length = htons(reply->size - start_len);
}

static int
handle_nxst_flow(struct ofconn *ofconn, const struct ofp_header *oh)
{
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    struct nx_flow_stats_request *nfsr;
    struct cls_rule target;
    struct ofpbuf *reply;
    struct ofpbuf b;
    int error;

    ofpbuf_use_const(&b, oh, ntohs(oh->length));

    /* Dissect the message. */
    nfsr = ofpbuf_pull(&b, sizeof *nfsr);
    error = nx_pull_match(&b, ntohs(nfsr->match_len), 0, &target);
    if (error) {
        return error;
    }
    if (b.size) {
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    COVERAGE_INC(ofproto_flows_req);
    reply = start_nxstats_reply(&nfsr->nsm, 1024);
    if (is_valid_table(nfsr->table_id)) {
        struct cls_cursor cursor;
        struct rule *rule;

        cls_cursor_init(&cursor, &ofproto->cls, &target);
        CLS_CURSOR_FOR_EACH (rule, cr, &cursor) {
            put_nx_flow_stats(ofconn, rule, nfsr->out_port, &reply);
        }
    }
    ofconn_send_reply(ofconn, reply);

    return 0;
}

static void
flow_stats_ds(struct rule *rule, struct ds *results)
{
    uint64_t packet_count, byte_count;
    size_t act_len = sizeof *rule->actions * rule->n_actions;

    rule->ofproto->ofproto_class->rule_get_stats(rule,
                                                 &packet_count, &byte_count);

    ds_put_format(results, "duration=%llds, ",
                  (time_msec() - rule->created) / 1000);
    //ds_put_format(results, "idle=%.3fs, ", (time_msec() - rule->used) / 1000.0);
    ds_put_format(results, "priority=%u, ", rule->cr.priority);
    ds_put_format(results, "n_packets=%"PRIu64", ", packet_count);
    ds_put_format(results, "n_bytes=%"PRIu64", ", byte_count);
    cls_rule_format(&rule->cr, results);
    ds_put_char(results, ',');
    if (act_len > 0) {
        ofp_print_actions(results, &rule->actions->header, act_len);
    } else {
        ds_put_cstr(results, "drop");
    }
    ds_put_cstr(results, "\n");
}

/* Adds a pretty-printed description of all flows to 'results', including
 * hidden flows (e.g., set up by in-band control). */
void
ofproto_get_all_flows(struct ofproto *p, struct ds *results)
{
    struct cls_cursor cursor;
    struct rule *rule;

    cls_cursor_init(&cursor, &p->cls, NULL);
    CLS_CURSOR_FOR_EACH (rule, cr, &cursor) {
        flow_stats_ds(rule, results);
    }
}

/* Obtains the NetFlow engine type and engine ID for 'ofproto' into
 * '*engine_type' and '*engine_id', respectively. */
void
ofproto_get_netflow_ids(const struct ofproto *ofproto,
                        uint8_t *engine_type, uint8_t *engine_id)
{
    ofproto->ofproto_class->get_netflow_ids(ofproto, engine_type, engine_id);
}

static void
query_aggregate_stats(struct ofproto *ofproto, struct cls_rule *target,
                      ovs_be16 out_port, uint8_t table_id,
                      struct ofp_aggregate_stats_reply *oasr)
{
    uint64_t total_packets = 0;
    uint64_t total_bytes = 0;
    int n_flows = 0;

    COVERAGE_INC(ofproto_agg_request);

    if (is_valid_table(table_id)) {
        struct cls_cursor cursor;
        struct rule *rule;

        cls_cursor_init(&cursor, &ofproto->cls, target);
        CLS_CURSOR_FOR_EACH (rule, cr, &cursor) {
            if (!rule_is_hidden(rule) && rule_has_out_port(rule, out_port)) {
                uint64_t packet_count;
                uint64_t byte_count;

                ofproto->ofproto_class->rule_get_stats(rule, &packet_count,
                                                       &byte_count);

                total_packets += packet_count;
                total_bytes += byte_count;
                n_flows++;
            }
        }
    }

    oasr->flow_count = htonl(n_flows);
    put_32aligned_be64(&oasr->packet_count, htonll(total_packets));
    put_32aligned_be64(&oasr->byte_count, htonll(total_bytes));
    memset(oasr->pad, 0, sizeof oasr->pad);
}

static int
handle_aggregate_stats_request(struct ofconn *ofconn,
                               const struct ofp_header *oh)
{
    const struct ofp_aggregate_stats_request *request = ofputil_stats_body(oh);
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    struct ofp_aggregate_stats_reply *reply;
    struct cls_rule target;
    struct ofpbuf *msg;

    ofputil_cls_rule_from_match(&request->match, 0, NXFF_OPENFLOW10, 0,
                                &target);

    msg = start_ofp_stats_reply(oh, sizeof *reply);
    reply = append_ofp_stats_reply(sizeof *reply, ofconn, &msg);
    query_aggregate_stats(ofproto, &target, request->out_port,
                          request->table_id, reply);
    ofconn_send_reply(ofconn, msg);
    return 0;
}

static int
handle_nxst_aggregate(struct ofconn *ofconn, const struct ofp_header *oh)
{
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    struct nx_aggregate_stats_request *request;
    struct ofp_aggregate_stats_reply *reply;
    struct cls_rule target;
    struct ofpbuf b;
    struct ofpbuf *buf;
    int error;

    ofpbuf_use_const(&b, oh, ntohs(oh->length));

    /* Dissect the message. */
    request = ofpbuf_pull(&b, sizeof *request);
    error = nx_pull_match(&b, ntohs(request->match_len), 0, &target);
    if (error) {
        return error;
    }
    if (b.size) {
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    /* Reply. */
    COVERAGE_INC(ofproto_flows_req);
    buf = start_nxstats_reply(&request->nsm, sizeof *reply);
    reply = ofpbuf_put_uninit(buf, sizeof *reply);
    query_aggregate_stats(ofproto, &target, request->out_port,
                          request->table_id, reply);
    ofconn_send_reply(ofconn, buf);

    return 0;
}

struct queue_stats_cbdata {
    struct ofconn *ofconn;
    struct ofport *ofport;
    struct ofpbuf *msg;
};

static void
put_queue_stats(struct queue_stats_cbdata *cbdata, uint32_t queue_id,
                const struct netdev_queue_stats *stats)
{
    struct ofp_queue_stats *reply;

    reply = append_ofp_stats_reply(sizeof *reply, cbdata->ofconn, &cbdata->msg);
    reply->port_no = cbdata->ofport->opp.port_no;
    memset(reply->pad, 0, sizeof reply->pad);
    reply->queue_id = htonl(queue_id);
    put_32aligned_be64(&reply->tx_bytes, htonll(stats->tx_bytes));
    put_32aligned_be64(&reply->tx_packets, htonll(stats->tx_packets));
    put_32aligned_be64(&reply->tx_errors, htonll(stats->tx_errors));
}

static void
handle_queue_stats_dump_cb(uint32_t queue_id,
                           struct netdev_queue_stats *stats,
                           void *cbdata_)
{
    struct queue_stats_cbdata *cbdata = cbdata_;

    put_queue_stats(cbdata, queue_id, stats);
}

static void
handle_queue_stats_for_port(struct ofport *port, uint32_t queue_id,
                            struct queue_stats_cbdata *cbdata)
{
    cbdata->ofport = port;
    if (queue_id == OFPQ_ALL) {
        netdev_dump_queue_stats(port->netdev,
                                handle_queue_stats_dump_cb, cbdata);
    } else {
        struct netdev_queue_stats stats;

        if (!netdev_get_queue_stats(port->netdev, queue_id, &stats)) {
            put_queue_stats(cbdata, queue_id, &stats);
        }
    }
}

static int
handle_queue_stats_request(struct ofconn *ofconn, const struct ofp_header *oh)
{
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    const struct ofp_queue_stats_request *qsr;
    struct queue_stats_cbdata cbdata;
    struct ofport *port;
    unsigned int port_no;
    uint32_t queue_id;

    qsr = ofputil_stats_body(oh);
    if (!qsr) {
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    COVERAGE_INC(ofproto_queue_req);

    cbdata.ofconn = ofconn;
    cbdata.msg = start_ofp_stats_reply(oh, 128);

    port_no = ntohs(qsr->port_no);
    queue_id = ntohl(qsr->queue_id);
    if (port_no == OFPP_ALL) {
        HMAP_FOR_EACH (port, hmap_node, &ofproto->ports) {
            handle_queue_stats_for_port(port, queue_id, &cbdata);
        }
    } else if (port_no < OFPP_MAX) {
        port = ofproto_get_port(ofproto, port_no);
        if (port) {
            handle_queue_stats_for_port(port, queue_id, &cbdata);
        }
    } else {
        ofpbuf_delete(cbdata.msg);
        return ofp_mkerr(OFPET_QUEUE_OP_FAILED, OFPQOFC_BAD_PORT);
    }
    ofconn_send_reply(ofconn, cbdata.msg);

    return 0;
}

/* Implements OFPFC_ADD and the cases for OFPFC_MODIFY and OFPFC_MODIFY_STRICT
 * in which no matching flow already exists in the flow table.
 *
 * Adds the flow specified by 'ofm', which is followed by 'n_actions'
 * ofp_actions, to the ofproto's flow table.  Returns 0 on success or an
 * OpenFlow error code as encoded by ofp_mkerr() on failure.
 *
 * 'ofconn' is used to retrieve the packet buffer specified in ofm->buffer_id,
 * if any. */
static int
add_flow(struct ofconn *ofconn, struct flow_mod *fm)
{
    struct ofproto *p = ofconn_get_ofproto(ofconn);
    struct ofpbuf *packet;
    struct rule *rule;
    uint16_t in_port;
    int buf_err;
    int error;

    if (fm->flags & OFPFF_CHECK_OVERLAP
        && classifier_rule_overlaps(&p->cls, &fm->cr)) {
        return ofp_mkerr(OFPET_FLOW_MOD_FAILED, OFPFMFC_OVERLAP);
    }

    buf_err = ofconn_pktbuf_retrieve(ofconn, fm->buffer_id, &packet, &in_port);
    error = rule_create(p, &fm->cr, fm->actions, fm->n_actions,
                        fm->idle_timeout, fm->hard_timeout, fm->cookie,
                        fm->flags & OFPFF_SEND_FLOW_REM, &rule);
    if (error) {
        ofpbuf_delete(packet);
        return error;
    }

    if (packet) {
        rule_execute(rule, in_port, packet);
    }
    return buf_err;
}

static struct rule *
find_flow_strict(struct ofproto *p, const struct flow_mod *fm)
{
    return rule_from_cls_rule(classifier_find_rule_exactly(&p->cls, &fm->cr));
}

static int
send_buffered_packet(struct ofconn *ofconn,
                     struct rule *rule, uint32_t buffer_id)
{
    struct ofpbuf *packet;
    uint16_t in_port;
    int error;

    if (buffer_id == UINT32_MAX) {
        return 0;
    }

    error = ofconn_pktbuf_retrieve(ofconn, buffer_id, &packet, &in_port);
    if (error) {
        return error;
    }

    rule_execute(rule, in_port, packet);

    return 0;
}

/* OFPFC_MODIFY and OFPFC_MODIFY_STRICT. */

struct modify_flows_cbdata {
    struct ofproto *ofproto;
    const struct flow_mod *fm;
    struct rule *match;
};

static int modify_flow(const struct flow_mod *, struct rule *);

/* Implements OFPFC_MODIFY.  Returns 0 on success or an OpenFlow error code as
 * encoded by ofp_mkerr() on failure.
 *
 * 'ofconn' is used to retrieve the packet buffer specified in ofm->buffer_id,
 * if any. */
static int
modify_flows_loose(struct ofconn *ofconn, struct flow_mod *fm)
{
    struct ofproto *p = ofconn_get_ofproto(ofconn);
    struct rule *match = NULL;
    struct cls_cursor cursor;
    struct rule *rule;
    int error;

    error = 0;
    cls_cursor_init(&cursor, &p->cls, &fm->cr);
    CLS_CURSOR_FOR_EACH (rule, cr, &cursor) {
        if (!rule_is_hidden(rule)) {
            int retval = modify_flow(fm, rule);
            if (!retval) {
                match = rule;
            } else {
                error = retval;
            }
        }
    }

    if (error) {
        return error;
    } else if (match) {
        /* This credits the packet to whichever flow happened to match last.
         * That's weird.  Maybe we should do a lookup for the flow that
         * actually matches the packet?  Who knows. */
        send_buffered_packet(ofconn, match, fm->buffer_id);
        return 0;
    } else {
        return add_flow(ofconn, fm);
    }
}

/* Implements OFPFC_MODIFY_STRICT.  Returns 0 on success or an OpenFlow error
 * code as encoded by ofp_mkerr() on failure.
 *
 * 'ofconn' is used to retrieve the packet buffer specified in ofm->buffer_id,
 * if any. */
static int
modify_flow_strict(struct ofconn *ofconn, struct flow_mod *fm)
{
    struct ofproto *p = ofconn_get_ofproto(ofconn);
    struct rule *rule = find_flow_strict(p, fm);
    if (rule && !rule_is_hidden(rule)) {
        int error = modify_flow(fm, rule);
        if (!error) {
            error = send_buffered_packet(ofconn, rule, fm->buffer_id);
        }
        return error;
    } else {
        return add_flow(ofconn, fm);
    }
}

/* Implements core of OFPFC_MODIFY and OFPFC_MODIFY_STRICT where 'rule' has
 * been identified as a flow to be modified, by changing the rule's actions to
 * match those in 'ofm' (which is followed by 'n_actions' ofp_action[]
 * structures). */
static int
modify_flow(const struct flow_mod *fm, struct rule *rule)
{
    size_t actions_len = fm->n_actions * sizeof *rule->actions;
    int error;

    if (fm->n_actions == rule->n_actions
        && (!fm->n_actions
            || !memcmp(fm->actions, rule->actions, actions_len))) {
        error = 0;
    } else {
        error = rule->ofproto->ofproto_class->rule_modify_actions(
            rule, fm->actions, fm->n_actions);
        if (!error) {
            free(rule->actions);
            rule->actions = (fm->n_actions
                             ? xmemdup(fm->actions, actions_len)
                             : NULL);
            rule->n_actions = fm->n_actions;
        }
    }

    if (!error) {
        rule->flow_cookie = fm->cookie;
    }

    return error;
}

/* OFPFC_DELETE implementation. */

static void delete_flow(struct rule *, ovs_be16 out_port);

/* Implements OFPFC_DELETE. */
static void
delete_flows_loose(struct ofproto *p, const struct flow_mod *fm)
{
    struct rule *rule, *next_rule;
    struct cls_cursor cursor;

    cls_cursor_init(&cursor, &p->cls, &fm->cr);
    CLS_CURSOR_FOR_EACH_SAFE (rule, next_rule, cr, &cursor) {
        delete_flow(rule, htons(fm->out_port));
    }
}

/* Implements OFPFC_DELETE_STRICT. */
static void
delete_flow_strict(struct ofproto *p, struct flow_mod *fm)
{
    struct rule *rule = find_flow_strict(p, fm);
    if (rule) {
        delete_flow(rule, htons(fm->out_port));
    }
}

/* Implements core of OFPFC_DELETE and OFPFC_DELETE_STRICT where 'rule' has
 * been identified as a flow to delete from 'p''s flow table, by deleting the
 * flow and sending out a OFPT_FLOW_REMOVED message to any interested
 * controller.
 *
 * Will not delete 'rule' if it is hidden.  Will delete 'rule' only if
 * 'out_port' is htons(OFPP_NONE) or if 'rule' actually outputs to the
 * specified 'out_port'. */
static void
delete_flow(struct rule *rule, ovs_be16 out_port)
{
    if (rule_is_hidden(rule)) {
        return;
    }

    if (out_port != htons(OFPP_NONE) && !rule_has_out_port(rule, out_port)) {
        return;
    }

    ofproto_rule_send_removed(rule, OFPRR_DELETE);
    ofproto_rule_remove(rule);
}

static void
ofproto_rule_send_removed(struct rule *rule, uint8_t reason)
{
    struct ofputil_flow_removed fr;

    if (rule_is_hidden(rule) || !rule->send_flow_removed) {
        return;
    }

    fr.rule = rule->cr;
    fr.cookie = rule->flow_cookie;
    fr.reason = reason;
    calc_flow_duration__(rule->created, &fr.duration_sec, &fr.duration_nsec);
    fr.idle_timeout = rule->idle_timeout;
    rule->ofproto->ofproto_class->rule_get_stats(rule, &fr.packet_count,
                                                 &fr.byte_count);

    connmgr_send_flow_removed(rule->ofproto->connmgr, &fr);
}

/* Sends an OpenFlow "flow removed" message with the given 'reason' (either
 * OFPRR_HARD_TIMEOUT or OFPRR_IDLE_TIMEOUT), and then removes 'rule' from its
 * ofproto.
 *
 * ofproto implementation ->run() functions should use this function to expire
 * OpenFlow flows. */
void
ofproto_rule_expire(struct rule *rule, uint8_t reason)
{
    assert(reason == OFPRR_HARD_TIMEOUT || reason == OFPRR_IDLE_TIMEOUT);
    ofproto_rule_send_removed(rule, reason);
    ofproto_rule_remove(rule);
}

static int
handle_flow_mod(struct ofconn *ofconn, const struct ofp_header *oh)
{
    struct ofproto *p = ofconn_get_ofproto(ofconn);
    struct flow_mod fm;
    int error;

    error = reject_slave_controller(ofconn, "flow_mod");
    if (error) {
        return error;
    }

    error = ofputil_decode_flow_mod(&fm, oh, ofconn_get_flow_format(ofconn));
    if (error) {
        return error;
    }

    /* We do not support the emergency flow cache.  It will hopefully get
     * dropped from OpenFlow in the near future. */
    if (fm.flags & OFPFF_EMERG) {
        /* There isn't a good fit for an error code, so just state that the
         * flow table is full. */
        return ofp_mkerr(OFPET_FLOW_MOD_FAILED, OFPFMFC_ALL_TABLES_FULL);
    }

    switch (fm.command) {
    case OFPFC_ADD:
        return add_flow(ofconn, &fm);

    case OFPFC_MODIFY:
        return modify_flows_loose(ofconn, &fm);

    case OFPFC_MODIFY_STRICT:
        return modify_flow_strict(ofconn, &fm);

    case OFPFC_DELETE:
        delete_flows_loose(p, &fm);
        return 0;

    case OFPFC_DELETE_STRICT:
        delete_flow_strict(p, &fm);
        return 0;

    default:
        return ofp_mkerr(OFPET_FLOW_MOD_FAILED, OFPFMFC_BAD_COMMAND);
    }
}

static int
handle_tun_id_from_cookie(struct ofconn *ofconn, const struct ofp_header *oh)
{
    const struct nxt_tun_id_cookie *msg
        = (const struct nxt_tun_id_cookie *) oh;
    enum nx_flow_format flow_format;

    flow_format = msg->set ? NXFF_TUN_ID_FROM_COOKIE : NXFF_OPENFLOW10;
    ofconn_set_flow_format(ofconn, flow_format);

    return 0;
}

static int
handle_role_request(struct ofconn *ofconn, const struct ofp_header *oh)
{
    struct nx_role_request *nrr = (struct nx_role_request *) oh;
    struct nx_role_request *reply;
    struct ofpbuf *buf;
    uint32_t role;

    if (ofconn_get_type(ofconn) != OFCONN_PRIMARY) {
        VLOG_WARN_RL(&rl, "ignoring role request on service connection");
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_EPERM);
    }

    role = ntohl(nrr->role);
    if (role != NX_ROLE_OTHER && role != NX_ROLE_MASTER
        && role != NX_ROLE_SLAVE) {
        VLOG_WARN_RL(&rl, "received request for unknown role %"PRIu32, role);

        /* There's no good error code for this. */
        return ofp_mkerr(OFPET_BAD_REQUEST, -1);
    }

    ofconn_set_role(ofconn, role);

    reply = make_nxmsg_xid(sizeof *reply, NXT_ROLE_REPLY, oh->xid, &buf);
    reply->role = htonl(role);
    ofconn_send_reply(ofconn, buf);

    return 0;
}

static int
handle_nxt_set_flow_format(struct ofconn *ofconn, const struct ofp_header *oh)
{
    const struct nxt_set_flow_format *msg
        = (const struct nxt_set_flow_format *) oh;
    uint32_t format;

    format = ntohl(msg->format);
    if (format == NXFF_OPENFLOW10
        || format == NXFF_TUN_ID_FROM_COOKIE
        || format == NXFF_NXM) {
        ofconn_set_flow_format(ofconn, format);
        return 0;
    } else {
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_EPERM);
    }
}

static int
handle_barrier_request(struct ofconn *ofconn, const struct ofp_header *oh)
{
    struct ofp_header *ob;
    struct ofpbuf *buf;

    /* Currently, everything executes synchronously, so we can just
     * immediately send the barrier reply. */
    ob = make_openflow_xid(sizeof *ob, OFPT_BARRIER_REPLY, oh->xid, &buf);
    ofconn_send_reply(ofconn, buf);
    return 0;
}

static int
handle_openflow__(struct ofconn *ofconn, const struct ofpbuf *msg)
{
    const struct ofp_header *oh = msg->data;
    const struct ofputil_msg_type *type;
    int error;

    error = ofputil_decode_msg_type(oh, &type);
    if (error) {
        return error;
    }

    switch (ofputil_msg_type_code(type)) {
        /* OpenFlow requests. */
    case OFPUTIL_OFPT_ECHO_REQUEST:
        return handle_echo_request(ofconn, oh);

    case OFPUTIL_OFPT_FEATURES_REQUEST:
        return handle_features_request(ofconn, oh);

    case OFPUTIL_OFPT_GET_CONFIG_REQUEST:
        return handle_get_config_request(ofconn, oh);

    case OFPUTIL_OFPT_SET_CONFIG:
        return handle_set_config(ofconn, msg->data);

    case OFPUTIL_OFPT_PACKET_OUT:
        return handle_packet_out(ofconn, oh);

    case OFPUTIL_OFPT_PORT_MOD:
        return handle_port_mod(ofconn, oh);

    case OFPUTIL_OFPT_FLOW_MOD:
        return handle_flow_mod(ofconn, oh);

    case OFPUTIL_OFPT_BARRIER_REQUEST:
        return handle_barrier_request(ofconn, oh);

        /* OpenFlow replies. */
    case OFPUTIL_OFPT_ECHO_REPLY:
        return 0;

        /* Nicira extension requests. */
    case OFPUTIL_NXT_TUN_ID_FROM_COOKIE:
        return handle_tun_id_from_cookie(ofconn, oh);

    case OFPUTIL_NXT_ROLE_REQUEST:
        return handle_role_request(ofconn, oh);

    case OFPUTIL_NXT_SET_FLOW_FORMAT:
        return handle_nxt_set_flow_format(ofconn, oh);

    case OFPUTIL_NXT_FLOW_MOD:
        return handle_flow_mod(ofconn, oh);

        /* OpenFlow statistics requests. */
    case OFPUTIL_OFPST_DESC_REQUEST:
        return handle_desc_stats_request(ofconn, oh);

    case OFPUTIL_OFPST_FLOW_REQUEST:
        return handle_flow_stats_request(ofconn, oh);

    case OFPUTIL_OFPST_AGGREGATE_REQUEST:
        return handle_aggregate_stats_request(ofconn, oh);

    case OFPUTIL_OFPST_TABLE_REQUEST:
        return handle_table_stats_request(ofconn, oh);

    case OFPUTIL_OFPST_PORT_REQUEST:
        return handle_port_stats_request(ofconn, oh);

    case OFPUTIL_OFPST_QUEUE_REQUEST:
        return handle_queue_stats_request(ofconn, oh);

        /* Nicira extension statistics requests. */
    case OFPUTIL_NXST_FLOW_REQUEST:
        return handle_nxst_flow(ofconn, oh);

    case OFPUTIL_NXST_AGGREGATE_REQUEST:
        return handle_nxst_aggregate(ofconn, oh);

    case OFPUTIL_INVALID:
    case OFPUTIL_OFPT_HELLO:
    case OFPUTIL_OFPT_ERROR:
    case OFPUTIL_OFPT_FEATURES_REPLY:
    case OFPUTIL_OFPT_GET_CONFIG_REPLY:
    case OFPUTIL_OFPT_PACKET_IN:
    case OFPUTIL_OFPT_FLOW_REMOVED:
    case OFPUTIL_OFPT_PORT_STATUS:
    case OFPUTIL_OFPT_BARRIER_REPLY:
    case OFPUTIL_OFPT_QUEUE_GET_CONFIG_REQUEST:
    case OFPUTIL_OFPT_QUEUE_GET_CONFIG_REPLY:
    case OFPUTIL_OFPST_DESC_REPLY:
    case OFPUTIL_OFPST_FLOW_REPLY:
    case OFPUTIL_OFPST_QUEUE_REPLY:
    case OFPUTIL_OFPST_PORT_REPLY:
    case OFPUTIL_OFPST_TABLE_REPLY:
    case OFPUTIL_OFPST_AGGREGATE_REPLY:
    case OFPUTIL_NXT_ROLE_REPLY:
    case OFPUTIL_NXT_FLOW_REMOVED:
    case OFPUTIL_NXST_FLOW_REPLY:
    case OFPUTIL_NXST_AGGREGATE_REPLY:
    default:
        if (VLOG_IS_WARN_ENABLED()) {
            char *s = ofp_to_string(oh, ntohs(oh->length), 2);
            VLOG_DBG_RL(&rl, "OpenFlow message ignored: %s", s);
            free(s);
        }
        if (oh->type == OFPT_STATS_REQUEST || oh->type == OFPT_STATS_REPLY) {
            return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_STAT);
        } else {
            return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
        }
    }
}

static void
handle_openflow(struct ofconn *ofconn, struct ofpbuf *ofp_msg)
{
    int error = handle_openflow__(ofconn, ofp_msg);
    if (error) {
        send_error_oh(ofconn, ofp_msg->data, error);
    }
    COVERAGE_INC(ofproto_recv_openflow);
}

static uint64_t
pick_datapath_id(const struct ofproto *ofproto)
{
    const struct ofport *port;

    port = ofproto_get_port(ofproto, OFPP_LOCAL);
    if (port) {
        uint8_t ea[ETH_ADDR_LEN];
        int error;

        error = netdev_get_etheraddr(port->netdev, ea);
        if (!error) {
            return eth_addr_to_uint64(ea);
        }
        VLOG_WARN("could not get MAC address for %s (%s)",
                  netdev_get_name(port->netdev), strerror(error));
    }
    return ofproto->fallback_dpid;
}

static uint64_t
pick_fallback_dpid(void)
{
    uint8_t ea[ETH_ADDR_LEN];
    eth_addr_nicira_random(ea);
    return eth_addr_to_uint64(ea);
}

/* unixctl commands. */

struct ofproto *
ofproto_lookup(const char *name)
{
    struct ofproto *ofproto;

    HMAP_FOR_EACH_WITH_HASH (ofproto, hmap_node, hash_string(name, 0),
                             &all_ofprotos) {
        if (!strcmp(ofproto->name, name)) {
            return ofproto;
        }
    }
    return NULL;
}

static void
ofproto_unixctl_list(struct unixctl_conn *conn, const char *arg OVS_UNUSED,
                     void *aux OVS_UNUSED)
{
    struct ofproto *ofproto;
    struct ds results;

    ds_init(&results);
    HMAP_FOR_EACH (ofproto, hmap_node, &all_ofprotos) {
        ds_put_format(&results, "%s\n", ofproto->name);
    }
    unixctl_command_reply(conn, 200, ds_cstr(&results));
    ds_destroy(&results);
}

static void
ofproto_unixctl_init(void)
{
    static bool registered;
    if (registered) {
        return;
    }
    registered = true;

    unixctl_command_register("ofproto/list", ofproto_unixctl_list, NULL);
}
