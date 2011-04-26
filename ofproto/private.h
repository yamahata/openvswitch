/*
 * Copyright (c) 2009, 2010, 2011 Nicira Networks.
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

#ifndef OFPROTO_PRIVATE_H
#define OFPROTO_PRIVATE_H 1

/* Definitions for use within ofproto. */

#include "ofproto/ofproto.h"
#include "classifier.h"
#include "list.h"
#include "shash.h"
#include "timeval.h"

/* An OpenFlow switch.
 *
 * With few exceptions, ofproto implementations may look at these fields but
 * should not modify them. */
struct ofproto {
    const struct ofproto_class *ofproto_class;
    char *type;                 /* Datapath type. */
    char *name;                 /* Datapath name. */
    struct hmap_node hmap_node; /* In global 'all_ofprotos' hmap. */

    /* Settings. */
    uint64_t fallback_dpid;     /* Datapath ID if no better choice found. */
    uint64_t datapath_id;       /* Datapath ID. */
    char *mfr_desc;             /* Manufacturer. */
    char *hw_desc;              /* Hardware. */
    char *sw_desc;              /* Software version. */
    char *serial_desc;          /* Serial number. */
    char *dp_desc;              /* Datapath description. */

    /* Datapath. */
    struct netdev_monitor *netdev_monitor;
    struct hmap ports;          /* Contains "struct ofport"s. */
    struct shash port_by_name;

    /* Flow table. */
    struct classifier cls;      /* Contains "struct rule"s. */

    /* OpenFlow connections. */
    struct connmgr *connmgr;
};

struct ofproto *ofproto_lookup(const char *name);
struct ofport *ofproto_get_port(const struct ofproto *, uint16_t ofp_port);

/* An OpenFlow port within a "struct ofproto".
 *
 * With few exceptions, ofproto implementations may look at these fields but
 * should not modify them. */
struct ofport {
    struct ofproto *ofproto;    /* The ofproto that contains this port. */
    struct hmap_node hmap_node; /* In struct ofproto's "ports" hmap. */
    struct netdev *netdev;
    struct ofp_phy_port opp;
    uint16_t ofp_port;          /* OpenFlow port number. */
};

/* An OpenFlow flow within a "struct ofproto".
 *
 * With few exceptions, ofproto implementations may look at these fields but
 * should not modify them. */
struct rule {
    struct ofproto *ofproto;     /* The ofproto that contains this rule. */
    struct cls_rule cr;          /* In owning ofproto's classifier. */

    ovs_be64 flow_cookie;        /* Controller-issued identifier. */

    long long int created;       /* Creation time. */
    uint16_t idle_timeout;       /* In seconds from time of last use. */
    uint16_t hard_timeout;       /* In seconds from time of creation. */
    bool send_flow_removed;      /* Send a flow removed message? */

    union ofp_action *actions;   /* OpenFlow actions. */
    int n_actions;               /* Number of elements in actions[]. */
};

static inline struct rule *
rule_from_cls_rule(const struct cls_rule *cls_rule)
{
    return cls_rule ? CONTAINER_OF(cls_rule, struct rule, cr) : NULL;
}

struct rule *ofproto_rule_lookup(struct ofproto *, const struct flow *);
void ofproto_rule_expire(struct rule *, uint8_t reason);
void ofproto_rule_destroy(struct rule *);

/* ofproto class structure, to be defined by each ofproto implementation.
 *
 *
 * Data Structures
 * ===============
 *
 * These functions work primarily with three different kinds of data
 * structures:
 *
 *   - "struct ofproto", which represents an OpenFlow switch.
 *
 *   - "struct ofport", which represents a port within an ofproto.
 *
 *   - "struct rule", which represents an OpenFlow flow within an ofproto.
 *
 * Each of these data structures contains all of the implementation-independent
 * generic state for the respective concept, called the "base" state.  None of
 * them contains any extra space for ofproto implementations to use.  Instead,
 * each implementation is expected to declare its own data structure that
 * contains an instance of the generic data structure plus additional
 * implementation-specific members, called the "derived" state.  The
 * implementation can use casts or (preferably) the CONTAINER_OF macro to
 * obtain access to derived state given only a pointer to the embedded generic
 * data structure.
 *
 *
 * Life Cycle
 * ==========
 *
 * Four stylized functions accompany each of these data structures:
 *
 *            "alloc"       "construct"       "destruct"       "dealloc"
 *            ------------  ----------------  ---------------  --------------
 *   ofproto  ->alloc       ->construct       ->destruct       ->dealloc
 *   ofport   ->port_alloc  ->port_construct  ->port_destruct  ->port_dealloc
 *   rule     ->rule_alloc  ->rule_construct  ->rule_destruct  ->rule_dealloc
 *
 * Any instance of a given data structure goes through the following life
 * cycle:
 *
 *   1. The client calls the "alloc" function to obtain raw memory.  If "alloc"
 *      fails, skip all the other steps.
 *
 *   2. The client initializes all of the data structure's base state.  If this
 *      fails, skip to step 7.
 *
 *   3. The client calls the "construct" function.  The implementation
 *      initializes derived state.  It may refer to the already-initialized
 *      base state.  If "construct" fails, skip to step 6.
 *
 *   4. The data structure is now initialized and in use.
 *
 *   5. When the data structure is no longer needed, the client calls the
 *      "destruct" function.  The implementation uninitializes derived state.
 *      The base state has not been uninitialized yet, so the implementation
 *      may still refer to it.
 *
 *   6. The client uninitializes all of the data structure's base state.
 *
 *   7. The client calls the "dealloc" to free the raw memory.  The
 *      implementation must not refer to base or derived state in the data
 *      structure, because it has already been uninitialized.
 *
 * Each "alloc" function allocates and returns a new instance of the respective
 * data structure.  The "alloc" function is not given any information about the
 * use of the new data structure, so it cannot perform much initialization.
 * Its purpose is just to ensure that the new data structure has enough room
 * for base and derived state.  It may return a null pointer if memory is not
 * available, in which case none of the other functions is called.
 *
 * Each "construct" function initializes derived state in its respective data
 * structure.  When "construct" is called, all of the base state has already
 * been initialized, so the "construct" function may refer to it.  The
 * "construct" function is allowed to fail, in which case the client calls the
 * "dealloc" function (but not the "destruct" function).
 *
 * Each "destruct" function uninitializes and frees derived state in its
 * respective data structure.  When "destruct" is called, the base state has
 * not yet been uninitialized, so the "destruct" function may refer to it.  The
 * "destruct" function is not allowed to fail.
 *
 * Each "dealloc" function frees raw memory that was allocated by the the
 * "alloc" function.  The memory's base and derived members might not have ever
 * been initialized (but if "construct" returned successfully, then it has been
 * "destruct"ed already).  The "dealloc" function is not allowed to fail.
 *
 *
 * Conventions
 * ===========
 *
 * Most of these functions return 0 if they are successful or a positive error
 * code on failure.  Depending on the function, valid error codes are either
 * errno values or OpenFlow error codes constructed with ofp_mkerr().
 *
 * Most of these functions are expected to execute synchronously, that is, to
 * block as necessary to obtain a result.  Thus, these functions may return
 * EAGAIN (or EWOULDBLOCK or EINPROGRESS) only where the function descriptions
 * explicitly say those errors are a possibility.  We may relax this
 * requirement in the future if and when we encounter performance problems. */
struct ofproto_class {
/* ## ----------------- ## */
/* ## Factory Functions ## */
/* ## ----------------- ## */

    /* Enumerates the types of all support ofproto types into 'types'.  The
     * caller has already initialized 'types' and other ofproto classes might
     * already have added names to it. */
    void (*enumerate_types)(struct sset *types);

    /* Enumerates the names of all existing datapath of the specified 'type'
     * into 'names' 'all_dps'.  The caller has already initialized 'names' as
     * an empty sset.
     *
     * 'type' is one of the types enumerated by ->enumerate_types().
     *
     * Returns 0 if successful, otherwise a positive errno value.
     */
    int (*enumerate_names)(const char *type, struct sset *names);

    /* Deletes the datapath with the specified 'type' and 'name'.  The caller
     * should have closed any open ofproto with this 'type' and 'name'; this
     * function is allowed to fail if that is not the case.
     *
     * 'type' is one of the types enumerated by ->enumerate_types().
     * 'name' is one of the names enumerated by ->enumerate_names() for 'type'.
     *
     * Returns 0 if successful, otherwise a positive errno value.
     */
    int (*del)(const char *type, const char *name);

/* ## --------------------------- ## */
/* ## Top-Level ofproto Functions ## */
/* ## --------------------------- ## */

    /* Life-cycle functions for an "ofproto" (see "Life Cycle" above).
     *
     * ->construct() should not modify any base members of the ofproto, even
     * though it may be tempting in a few cases.  In particular, the client
     * will initialize the ofproto's 'ports' member after construction is
     * complete.  An ofproto's flow table should be initially empty, so
     * ->construct() should delete flows from the underlying datapath, if
     * necessary, rather than populating the ofproto's 'cls'.
     *
     * Only one ofproto instance needs to be supported for any given datapath.
     * If a datapath is already open as part of one "ofproto", then another
     * attempt to "construct" the same datapath as part of another ofproto is
     * allowed to fail with an error.
     *
     * ->construct() returns 0 if successful, otherwise a positive errno
     * value. */
    struct ofproto *(*alloc)(void);
    int (*construct)(struct ofproto *ofproto);
    void (*destruct)(struct ofproto *ofproto);
    void (*dealloc)(struct ofproto *ofproto);

    /* Performs any periodic activity required by 'ofproto'.  It should:
     *
     *   - Call connmgr_send_packet_in() for each received packet that missed
     *     in the OpenFlow flow table or that had a OFPP_CONTROLLER output
     *     action.
     *
     *   - Call ofproto_rule_expire() for each OpenFlow flow that has reached
     *     its hard_timeout or idle_timeout, to expire the flow.
     *
     * Returns 0 if successful, otherwise a positive errno value.  The ENODEV
     * return value specifically means that the datapath underlying 'ofproto'
     * has been destroyed (externally, e.g. by an admin running ovs-dpctl).
     */
    int (*run)(struct ofproto *ofproto);

    /* Causes the poll loop to wake up when 'ofproto''s 'run' function needs to
     * be called, e.g. by calling the timer or fd waiting functions in
     * poll-loop.h.  */
    void (*wait)(struct ofproto *ofproto);

    /* Every "struct rule"s in 'ofproto' is about to be deleted, one by one.
     * This function may prepare for that, for example by clearing state in
     * advance.  It should *not* actually delete any "struct rule"s from
     * 'ofproto', only prepare for it.
     *
     * This function is optional; it's really just for optimization in case
     * it's cheaper to delete all the flows from your hardware in a single pass
     * than to do it one by one. */
    void (*flush)(struct ofproto *ofproto);

/* ## ---------------- ## */
/* ## ofport Functions ## */
/* ## ---------------- ## */

    /* Life-cycle functions for a "struct ofport" (see "Life Cycle" above).
     *
     * ->port_construct() should not modify any base members of the ofport.
     *
     * ofports are managed by the base ofproto code.  The ofproto
     * implementation should only create and destroy them in response to calls
     * to these functions.  The base ofproto code will create and destroy
     * ofports in the following situations:
     *
     *   - Just after the ->construct() function is called, the base ofproto
     *     iterates over all of the implementation's ports, using
     *     ->port_dump_start() and related functions, and constructs an ofport
     *     for each dumped port.
     *
     *   - If ->port_poll() reports that a specific port has changed, then the
     *     base ofproto will query that port with ->port_query_by_name() and
     *     construct or destruct ofports as necessary to reflect the updated
     *     set of ports.
     *
     *   - If ->port_poll() returns ENOBUFS to report an unspecified port set
     *     change, then the base ofproto will iterate over all of the
     *     implementation's ports, in the same way as at ofproto
     *     initialization, and construct and destruct ofports to reflect all of
     *     the changes.
     *
     * ->port_construct() returns 0 if successful, otherwise a positive errno
     * value.
     */
    struct ofport *(*port_alloc)(void);
    int (*port_construct)(struct ofport *ofport);
    void (*port_destruct)(struct ofport *ofport);
    void (*port_dealloc)(struct ofport *ofport);

    /* Called after 'ofport->netdev' is replaced by a new netdev object.  If
     * the ofproto implementation uses the ofport's netdev internally, then it
     * should switch to using the new one.  The old one has been closed.
     *
     * An ofproto implementation that doesn't need to do anything in this
     * function may use a null pointer. */
    void (*port_modified)(struct ofport *ofport);

    /* Called after an OpenFlow OFPT_PORT_MOD request changes a port's
     * configuration.  'ofport->opp.config' contains the new configuration.
     * 'old_config' contains the previous configuration.
     *
     * The caller implements OFPPC_PORT_DOWN using netdev functions to turn
     * NETDEV_UP on and off, so this function doesn't have to do anything for
     * that bit (and it won't be called if that is the only bit that
     * changes). */
    void (*port_reconfigured)(struct ofport *ofport, ovs_be32 old_config);

    /* Looks up a port named 'devname' in 'ofproto'.  On success, initializes
     * '*port' appropriately.
     *
     * The caller owns the data in 'port' and must free it with
     * ofproto_port_destroy() when it is no longer needed. */
    int (*port_query_by_name)(const struct ofproto *ofproto,
                              const char *devname, struct ofproto_port *port);

    /* Attempts to add 'netdev' as a port on 'ofproto'.  Returns 0 if
     * successful, otherwise a positive errno value.  If successful, sets
     * '*ofp_portp' to the new port's port number.
     *
     * It doesn't matter whether the new port will be returned by a later call
     * to ->port_poll(); the implementation may do whatever is more
     * convenient. */
    int (*port_add)(struct ofproto *ofproto, struct netdev *netdev,
                    uint16_t *ofp_portp);

    /* Deletes port number 'ofp_port' from the datapath for 'ofproto'.  Returns
     * 0 if successful, otherwise a positive errno value.
     *
     * It doesn't matter whether the new port will be returned by a later call
     * to ->port_poll(); the implementation may do whatever is more
     * convenient. */
    int (*port_del)(struct ofproto *ofproto, uint16_t ofp_port);

    /* Attempts to begin dumping the ports in 'ofproto'.  On success, returns 0
     * and initializes '*statep' with any data needed for iteration.  On
     * failure, returns a positive errno value. */
    int (*port_dump_start)(const struct ofproto *ofproto, void **statep);

    /* Attempts to retrieve another port from 'ofproto' for 'state', which was
     * initialized by a successful call to the 'port_dump_start' function for
     * 'ofproto'.  On success, stores a new ofproto_port into 'port' and
     * returns 0.  Returns EOF if the end of the port table has been reached,
     * or a positive errno value on error.  This function will not be called
     * again once it returns nonzero once for a given iteration (but the
     * 'port_dump_done' function will be called afterward).
     *
     * The ofproto provider retains ownership of the data stored in 'port'.  It
     * must remain valid until at least the next call to 'port_dump_next' or
     * 'port_dump_done' for 'state'. */
    int (*port_dump_next)(const struct ofproto *ofproto, void *state,
                          struct ofproto_port *port);

    /* Releases resources from 'ofproto' for 'state', which was initialized by
     * a successful call to the 'port_dump_start' function for 'ofproto'.  */
    int (*port_dump_done)(const struct ofproto *ofproto, void *state);

    /* Polls for changes in the set of ports in 'ofproto'.  If the set of ports
     * in 'ofproto' has changed, then this function should do one of the
     * following:
     *
     * - Preferably: store the name of the device that was added to or deleted
     *   from 'ofproto' in '*devnamep' and return 0.  The caller is responsible
     *   for freeing '*devnamep' (with free()) when it no longer needs it.
     *
     * - Alternatively: return ENOBUFS, without indicating the device that was
     *   added or deleted.
     *
     * Occasional 'false positives', in which the function returns 0 while
     * indicating a device that was not actually added or deleted or returns
     * ENOBUFS without any change, are acceptable.
     *
     * The purpose of 'port_poll' is to let 'ofproto' know about changes made
     * externally to the 'ofproto' object, e.g. by a system administrator via
     * ovs-dpctl.  Therefore, it's OK, and even preferable, for port_poll() to
     * not report changes made through calls to 'port_add' or 'port_del' on the
     * same 'ofproto' object.  (But it's OK for it to report them too, just
     * slightly less efficient.)
     *
     * If the set of ports in 'ofproto' has not changed, returns EAGAIN.  May
     * also return other positive errno values to indicate that something has
     * gone wrong.
     *
     * If the set of ports in a datapath is fixed, or if the only way that the
     * set of ports in a datapath can change is through ->port_add() and
     * ->port_del(), then this function may be a null pointer.
     */
    int (*port_poll)(const struct ofproto *ofproto, char **devnamep);

    /* Arranges for the poll loop to wake up when ->port_poll() will return a
     * value other than EAGAIN.
     *
     * If the set of ports in a datapath is fixed, or if the only way that the
     * set of ports in a datapath can change is through ->port_add() and
     * ->port_del(), or if the poll loop will always wake up anyway when
     * ->port_poll() will return a value other than EAGAIN, then this function
     * may be a null pointer.
     */
    void (*port_poll_wait)(const struct ofproto *ofproto);

    /* Checks the status of LACP negotiation for 'port'.  Returns 1 if LACP
     * partner information for 'port' is up-to-date, 0 if LACP partner
     * information is not current (generally indicating a connectivity
     * problem), or -1 if LACP is not enabled on 'port'.
     *
     * This function may be a null pointer if the ofproto implementation does
     * not support LACP. */
    int (*port_is_lacp_current)(const struct ofport *port);

/* ## ----------------------- ## */
/* ## OpenFlow Rule Functions ## */
/* ## ----------------------- ## */

    /* Life-cycle functions for a "struct rule" (see "Life Cycle" above).
     *
     * ->rule_construct() should first check whether the rule is acceptable:
     *
     *   - Validate that the matching rule in 'rule->cr' is supported by the
     *     datapath.  If not, then return an OpenFlow error code (as returned
     *     by ofp_mkerr()).
     *
     *     For example, if the datapath does not support registers, then it
     *     should return an error if 'rule->cr' does not wildcard all
     *     registers.
     *
     *   - Validate that 'rule->actions' and 'rule->n_actions' are well-formed
     *     OpenFlow actions that can be correctly implemented by the datapath.
     *     If not, then return an OpenFlow error code (as returned by
     *     ofp_mkerr()).
     *
     *     The validate_actions() function (in ofp-util.c) can be useful as a
     *     model for action validation, but it accepts all of the OpenFlow
     *     actions that OVS understands.  If your ofproto implementation only
     *     implements a subset of those, then you should implement your own
     *     action validation.
     *
     * If the rule is acceptable, then ->rule_construct() should modify the
     * flow table:
     *
     *   - If there was already a rule with exactly the same matching criteria
     *     and priority in the classifier, then it should remove that rule from
     *     the classifier and destroy it (with ofproto_rule_destroy()).
     *
     *   - Insert the new rule into the ofproto's 'cls' classifier, and into
     *     the datapath flow table.
     *
     *     (The function classifier_insert() both inserts a rule into the
     *     classifier and removes any rule with identical matching criteria, so
     *     this single call implements parts of both steps above.)
     *
     * Other than inserting 'rule->cr' into the classifier, ->rule_construct()
     * should not modify any base members of struct rule.
     *
     * When ->rule_destruct() is called, 'rule' has already been removed from
     * the classifier and the datapath flow table (by calling ->rule_remove()),
     * so ->rule_destruct() should not duplicate that behavior. */
    struct rule *(*rule_alloc)(void);
    int (*rule_construct)(struct rule *rule);
    void (*rule_destruct)(struct rule *rule);
    void (*rule_dealloc)(struct rule *rule);

    /* Removes 'rule' from 'rule->ofproto->cls' and from the datapath.
     *
     * 'rule' will be destructed, with ->rule_destruct(), soon after. */
    void (*rule_remove)(struct rule *rule);

    /* Obtains statistics for 'rule', storing the number of packets that have
     * matched it in '*packet_count' and the number of bytes in those packets
     * in '*byte_count'. */
    void (*rule_get_stats)(struct rule *rule, uint64_t *packet_count,
                           uint64_t *byte_count);

    /* Applies the actions in 'rule' to 'packet'.  (This implements sending
     * buffered packets for OpenFlow OFPT_FLOW_MOD commands.)
     *
     * Takes ownership of 'packet' (so it should eventually free it, with
     * ofpbuf_delete()).
     *
     * 'flow' reflects the flow information for 'packet'.  All of the
     * information in 'flow' is extracted from 'packet', except for
     * flow->tun_id and flow->in_port, which are assigned the correct values
     * for the incoming packet.  The register values are zeroed.
     *
     * The statistics for 'packet' should be included in 'rule'.
     *
     * Returns 0 if successful, otherwise an OpenFlow error code (as returned
     * by ofp_mkerr()). */
    int (*rule_execute)(struct rule *rule, struct flow *flow,
                        struct ofpbuf *packet);

    /* Validates that the 'n' elements in 'actions' are well-formed OpenFlow
     * actions that can be correctly implemented by the datapath.  If not, then
     * return an OpenFlow error code (as returned by ofp_mkerr()).  If so,
     * then update the datapath to implement the new actions and return 0.
     *
     * When this function runs, 'rule' still has its original actions.  If this
     * function returns 0, then the caller will update 'rule' with the new
     * actions and free the old ones. */
    int (*rule_modify_actions)(struct rule *rule,
                               const union ofp_action *actions, size_t n);

    /* These functions implement the OpenFlow IP fragment handling policy.  By
     * default ('drop_frags' == false), an OpenFlow switch should treat IP
     * fragments the same way as other packets (although TCP and UDP port
     * numbers cannot be determined).  With 'drop_frags' == true, the switch
     * should drop all IP fragments without passing them through the flow
     * table. */
    bool (*get_drop_frags)(struct ofproto *ofproto);
    void (*set_drop_frags)(struct ofproto *ofproto, bool drop_frags);

    /* Implements the OpenFlow OFPT_PACKET_OUT command.  The datapath should
     * execute the 'n_actions' in the 'actions' array on 'packet'.
     *
     * The caller retains ownership of 'packet', so ->packet_out() should not
     * modify or free it.
     *
     * This function must validate that the 'n_actions' elements in 'actions'
     * are well-formed OpenFlow actions that can be correctly implemented by
     * the datapath.  If not, then it should return an OpenFlow error code (as
     * returned by ofp_mkerr()).
     *
     * 'flow' reflects the flow information for 'packet'.  All of the
     * information in 'flow' is extracted from 'packet', except for
     * flow->in_port, which is taken from the OFPT_PACKET_OUT message.
     * flow->tun_id and its register values are zeroed.
     *
     * 'packet' is not matched against the OpenFlow flow table, so its
     * statistics should not be included in OpenFlow flow statistics.
     *
     * Returns 0 if successful, otherwise an OpenFlow error code (as returned
     * by ofp_mkerr()). */
    int (*packet_out)(struct ofproto *ofproto, struct ofpbuf *packet,
                      const struct flow *flow,
                      const union ofp_action *actions,
                      size_t n_actions);

/* ## ------------------------- ## */
/* ## OFPP_NORMAL configuration ## */
/* ## ------------------------- ## */

    /* Configures NetFlow on 'ofproto' according to the options in
     * 'netflow_options', or turns off NetFlow if 'netflow_options' is NULL.
     *
     * EOPNOTSUPP as a return value indicates that 'ofproto' does not support
     * sFlow, as does a null pointer. */
    int (*set_netflow)(struct ofproto *ofproto,
                       const struct netflow_options *netflow_options);

    void (*get_netflow_ids)(const struct ofproto *ofproto,
                            uint8_t *engine_type, uint8_t *engine_id);

    /* Configures sFlow on 'ofproto' according to the options in
     * 'sflow_options', or turns off sFlow if 'sflow_options' is NULL.
     *
     * EOPNOTSUPP as a return value indicates that 'ofproto' does not support
     * sFlow, as does a null pointer. */
    int (*set_sflow)(struct ofproto *ofproto,
                     const struct ofproto_sflow_options *sflow_options);

    /* Configures connectivity fault management on 'ofport'.
     *
     * If 'cfm' is nonnull, takes basic configuration from the configuration
     * members in 'cfm', and the set of remote maintenance points from the
     * 'n_remote_mps' elements in 'remote_mps'.  Ignores the statistics members
     * of 'cfm'.
     *
     * If 'cfm' is null, removes any connectivity fault management
     * configuration from 'ofport'.
     *
     * EOPNOTSUPP as a return value indicates that this ofproto_class does not
     * support CFM, as does a null pointer. */
    int (*set_cfm)(struct ofport *ofport, const struct cfm *cfm,
                   const uint16_t *remote_mps, size_t n_remote_mps);

    /* Stores the connectivity fault management object associated with 'ofport'
     * in '*cfmp'.  Stores a null pointer in '*cfmp' if CFM is not configured
     * on 'ofport'.  The caller must not modify or destroy the returned object.
     *
     * This function may be NULL if this ofproto_class does not support CFM. */
    int (*get_cfm)(struct ofport *ofport, const struct cfm **cfmp);

    /* If 's' is nonnull, this function registers a "bundle" associated with
     * client data pointer 'aux' in 'ofproto'.  A bundle is the same concept as
     * a Port in OVSDB, that is, it consists of one or more "slave" devices
     * (Interfaces, in OVSDB) along with VLAN and LACP configuration and, if
     * there is more than one slave, a bonding configuration.  If 'aux' is
     * already registered then this function updates its configuration to 's'.
     * Otherwise, this function registers a new bundle.
     *
     * If 's' is NULL, this function unregisters the bundle registered on
     * 'ofproto' associated with client data pointer 'aux'.  If no such bundle
     * has been registered, this has no effect.
     *
     * This function affects only the behavior of the OFPP_NORMAL action.  An
     * implementation that does not to support it at all may set it to NULL or
     * return EOPNOTSUPP.  An implementation that supports only a subset of the
     * functionality should implement what it can and return 0. */
    int (*bundle_set)(struct ofproto *ofproto, void *aux,
                      const struct ofproto_bundle_settings *s);

    /* If 'port' is part of any bundle, removes it from that bundle.  If the
     * bundle now has no ports, deletes the bundle.  If the bundle now has only
     * one port, deconfigures the bundle's bonding configuration. */
    void (*bundle_remove)(struct ofport *ofport);

    /* If 's' is nonnull, this function registers a mirror associated with
     * client data pointer 'aux' in 'ofproto'.  A mirror is the same concept as
     * a Mirror in OVSDB.  If 'aux' is already registered then this function
     * updates its configuration to 's'.  Otherwise, this function registers a
     * new mirror.
     *
     * If 's' is NULL, this function unregisters the mirror registered on
     * 'ofproto' associated with client data pointer 'aux'.  If no such mirror
     * has been registered, this has no effect.
     *
     * This function affects only the behavior of the OFPP_NORMAL action.  An
     * implementation that does not to support it at all may set it to NULL or
     * return EOPNOTSUPP.  An implementation that supports only a subset of the
     * functionality should implement what it can and return 0. */
    int (*mirror_set)(struct ofproto *ofproto, void *aux,
                      const struct ofproto_mirror_settings *s);

    /* Configures the VLANs whose bits are set to 1 in 'flood_vlans' as VLANs
     * on which all packets are flooded, instead of using MAC learning.  If
     * 'flood_vlans' is NULL, then MAC learning applies to all VLANs.
     *
     * This function affects only the behavior of the OFPP_NORMAL action.  An
     * implementation that does not to support it may set it to NULL or return
     * EOPNOTSUPP. */
    int (*set_flood_vlans)(struct ofproto *ofproto,
                           unsigned long *flood_vlans);

    /* Returns true if 'aux' is a registered bundle that is currently in use as
     * the output for a mirror. */
    bool (*is_mirror_output_bundle)(struct ofproto *ofproto, void *aux);
};

extern const struct ofproto_class ofproto_dpif_class;

int ofproto_class_register(const struct ofproto_class *);
int ofproto_class_unregister(const struct ofproto_class *);

void ofproto_add_flow(struct ofproto *, const struct cls_rule *,
                      const union ofp_action *, size_t n_actions);
void ofproto_delete_flow(struct ofproto *, const struct cls_rule *);
void ofproto_flush_flows(struct ofproto *);

#endif /* ofproto/private.h */
