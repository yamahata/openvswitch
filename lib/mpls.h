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

#include "ofpbuf.h"
#include "openvswitch/types.h"

#define MPLS_LSE_MAX    8
struct mpls_lses {
    unsigned int n_lses;
    ovs_be32 lses[MPLS_LSE_MAX];
};

static inline void
mpls_lses_init(struct mpls_lses *mpls)
{
    mpls->n_lses = 0;
}

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
}

static inline void
mpls_lses_pop(struct mpls_lses *mpls)
{
    if (mpls->n_lses == 0) {
        return;
    }
    mpls->n_lses--;
    memmove(mpls->lses, mpls->lses + 1, sizeof(mpls->lses[0]) * mpls->n_lses);
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

#endif /* mpls.h */
