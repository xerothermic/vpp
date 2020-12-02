
/*
 * patlu.h - skeleton vpp engine plug-in header file
 *
 * Copyright (c) <current-year> <your-organization>
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
#ifndef __included_patlu_h__
#define __included_patlu_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>

#include <stdio.h>
typedef struct {
    /* API message ID base */
    u16 msg_id_base;

    /* on/off switch for the periodic function */
    u8 periodic_timer_enabled;
    /* Node index, non-zero if the periodic process has been created */
    u32 periodic_node_index;

    /* convenience */
    vlib_main_t * vlib_main;
    vnet_main_t * vnet_main;
    ethernet_main_t * ethernet_main;
    u64 epoch_base;
    const char * log_path;
    FILE * fp;
} patlu_main_t;

extern patlu_main_t patlu_main;

extern vlib_node_registration_t patlu_node;
extern vlib_node_registration_t patlu_periodic_node;

/* Periodic function events */
#define PATLU_EVENT1 1
#define PATLU_EVENT2 2
#define PATLU_EVENT_PERIODIC_ENABLE_DISABLE 3

void patlu_create_periodic_process (patlu_main_t *);

#endif /* __included_patlu_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

