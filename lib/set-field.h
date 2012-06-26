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

#ifndef SET_FIELD_H
#define SET_FIELD_H 1

struct ds;
struct ofp12_action_set_field;
struct ofpbuf;
struct ofpact_set_field;
enum mf_field_id;

enum ofperr
set_field_put(struct ofpbuf *out, enum mf_field_id id, const void *valuep);
enum ofperr
set_field_check(const struct ofpact_set_field *set_field,
                const struct flow *flow);

enum ofperr
set_field_from_openflow(const struct ofp12_action_set_field* oasf,
                        struct ofpbuf *ofpacts);
void
set_field_to_nxact(const struct ofpact_set_field *set_field,
                   struct ofpbuf *out);
bool
set_field_to_openflow10(const struct ofpact_set_field *set_field,
                        struct ofpbuf *out);
bool
set_field_to_openflow11(const struct ofpact_set_field *set_field,
                        struct ofpbuf *out);

void
set_field_parse_with_id(enum mf_field_id id,
                        const char *arg, struct ofpbuf *ofpacts);
void set_field_parse(const char *s, struct ofpbuf *ofpacts);
void
set_field_format(const struct ofpact_set_field *set_field, struct ds *s);
void
set_field_execute(const struct ofpact_set_field *set_field,
                  struct flow *flow, struct flow *base_flow,
                  struct ofpbuf *odp_actions);


#endif /* SET_FIELD_H */
