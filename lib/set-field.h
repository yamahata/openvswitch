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
struct ofpbuf;
struct ofpact_reg_load;

struct ofpact_reg_load*
set_field_put(const struct mf_field *mf, struct ofpbuf *ofpacts);
void set_field_parse(const char *s, struct ofpbuf *ofpacts);
void set_field_format(const struct ofpact_reg_load *load, struct ds *s);

#endif /* SET_FIELD_H */
