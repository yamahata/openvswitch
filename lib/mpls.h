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
#ifndef MPLS_H
#define MPLS_H 1

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include "ofpbuf.h"
#include "openvswitch/types.h"
#include "packets.h"

#define MPLS_LSE_MAX    16      /* This must be matches with kernel value */
struct mpls_lses {
    uint8_t n_lses;
    uint8_t pads[3];
    ovs_be32 lses[MPLS_LSE_MAX];
};

static inline void
mpls_lses_init(struct mpls_lses *mpls)
{
    memset(mpls, 0, sizeof(*mpls));
}

#if 0
static inline void
mpls_turncate_lses(struct mpls_lses *mpls)
{
    /* TODO:XXX corner cases for truncated MPLS header */
    while (mpls->n_lses > 0 && mpls->lses[0] == htonl(0)) {
        memmove(mpls->lses, mpls->lses + 1,
                sizeof(mpls->lses[0]) * (mpls->n_lses - 1));
        mpls->n_lses--;
        mpls->lses[mpls->n_lses] = htonl(0);
    }
}
#endif

static inline void
mpls_lses_parsed(struct mpls_lses *mpls, const struct ofpbuf *packet)
{
    const struct mpls_hdr *outer;
    const struct mpls_hdr *end;
    if (packet == NULL) {
        return; /* TODO:XXX for xlate_actions_for_side_effects() */
    }

    outer = packet->l2_5;
    end = packet->l3;
    if (outer == NULL || end == NULL) {
        mpls->n_lses = 0;
        return;
    }
    mpls->n_lses = end - outer;
    assert(mpls->n_lses <= MPLS_LSE_MAX);       /* TODO:XXX */
    memcpy(mpls->lses, outer, sizeof(*outer) * mpls->n_lses);
    // mpls_truncate_lses(mpls); /* TODO:XXX */
}

static inline int
mpls_lses_from_keys(struct mpls_lses *mpls, const ovs_be32* lses, size_t len)
{
    uint8_t n_lses = len / sizeof(lses[0]);
    if (n_lses > MPLS_LSE_MAX) {
        return -E2BIG;
    }
    if ((len % sizeof(lses[0])) != 0 ||
        (lses[n_lses - 1] & htonl(MPLS_STACK_MASK)) == 0) {
        /* kernel returned unexpected key. What to do? */
        abort();
        return -EINVAL;
    }
    mpls->n_lses = n_lses;
    memcpy(mpls->lses, lses, len);
    // mpls_truncate_lses(mpls); /* TODO:XXX */
    return 0;
}

static inline void
mpls_lses_pop(struct mpls_lses *mpls)
{
    if (mpls->n_lses == 0) {
        return;
    }
    mpls->n_lses--;
    memmove(mpls->lses, mpls->lses + 1, sizeof(mpls->lses[0]) * mpls->n_lses);
    mpls->lses[mpls->n_lses] = htonl(0);
}

static inline void
mpls_lses_push(struct mpls_lses *mpls, ovs_be32 lse)
{
    assert(mpls->n_lses < MPLS_LSE_MAX);        /* TODO:XXX */

    if (mpls->n_lses == 0) {
        assert(lse & htonl(MPLS_STACK_MASK));
        lse |= htonl(MPLS_STACK_MASK);
    } else if (mpls->n_lses > 0) {
        assert((lse & htonl(MPLS_STACK_MASK)) == 0);
        memmove(mpls->lses + 1, mpls->lses,
                sizeof(mpls->lses[0]) * mpls->n_lses);
        mpls->lses[0] &= htonl(MPLS_STACK_MASK);
    }
    mpls->n_lses++;
}

static inline void
mpls_lses_set(struct mpls_lses *mpls, ovs_be32 lse)
{
    if (mpls->n_lses == 0) {
        return;
    }
    if (mpls->n_lses == 1) {
        assert(lse & htonl(MPLS_STACK_MASK));
    } else {
        assert((lse & htonl(MPLS_STACK_MASK)) == 0);
    }
    mpls->lses[0] = lse;
}

static inline void
mpls_lses_set_label(struct mpls_lses *mpls, ovs_be32 mpls_label)
{
    assert(mpls->n_lses > 0);
    mpls->lses[0] &= ~htonl(MPLS_LABEL_MASK);
    mpls->lses[0] |= mpls_label & htonl(MPLS_LABEL_MASK);
}

static inline void
mpls_lses_set_tc(struct mpls_lses *mpls, ovs_be32 mpls_tc)
{
    assert(mpls->n_lses > 0);
    mpls->lses[0] &= ~htonl(MPLS_TC_MASK);
    mpls->lses[0] |= mpls_tc & htonl(MPLS_TC_MASK);
}

static inline void
mpls_lses_set_ttl(struct mpls_lses *mpls, ovs_be32 mpls_ttl)
{
    assert(mpls->n_lses > 0);
    mpls->lses[0] &= ~htonl(MPLS_TTL_MASK);
    mpls->lses[0] |= mpls_ttl & htonl(MPLS_TTL_MASK);
}

#endif /* mpls.h */
