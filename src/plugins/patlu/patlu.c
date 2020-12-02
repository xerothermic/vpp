/*
 * patlu.c - skeleton vpp engine plug-in
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

#include <vnet/vnet.h>
#include <vnet/udp/udp.h>
#include <vnet/l2/l2_in_out_feat_arc.h>
#include <vnet/plugin/plugin.h>
#include <patlu/patlu.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <stdbool.h>

#include <patlu/patlu.api_enum.h>
#include <patlu/patlu.api_types.h>

#define REPLY_MSG_ID_BASE pmp->msg_id_base
#include <vlibapi/api_helper_macros.h>

patlu_main_t patlu_main;

/* Action function shared between message handler and debug CLI */

int patlu_enable_disable (patlu_main_t * pmp, u32 sw_if_index,
                                   int is_enable)
{
  vnet_sw_interface_t * sw;
  int rv = 0;

  /* Utterly wrong? */
  if (pool_is_free_index (pmp->vnet_main->interface_main.sw_interfaces,
                          sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /* Not a physical port? */
  sw = vnet_get_sw_interface (pmp->vnet_main, sw_if_index);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  patlu_create_periodic_process (pmp);
#if 0
  if (is_enable) {
    udp_register_dst_port(pmp->vlib_main, 53, patlu_node.index, 1);
  } else {
    udp_unregister_dst_port(pmp->vlib_main, 53, 1);
  }
#endif
  vnet_feature_enable_disable ("ip4-unicast", patlu_node.name,
                               sw_if_index, is_enable, 0, 0);

  // XXX: What does below do and do we need it?
  /* Send an event to enable/disable the periodic scanner process */
  vlib_process_signal_event (pmp->vlib_main,
                             pmp->periodic_node_index,
                             PATLU_EVENT_PERIODIC_ENABLE_DISABLE,
                            (uword)is_enable);
  return rv;
}

static clib_error_t *
patlu_enable_disable_command_fn (vlib_main_t * vm,
                                   unformat_input_t * input,
                                   vlib_cli_command_t * cmd)
{
  patlu_main_t * pmp = &patlu_main;
  u32 sw_if_index = ~0;
  int enable_disable = 1;

  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
        enable_disable = 0;
      else if (unformat (input, "%U", unformat_vnet_sw_interface,
                         pmp->vnet_main, &sw_if_index))
        ;
      else
        break;
  }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface...");

  rv = patlu_enable_disable (pmp, sw_if_index, enable_disable);

  switch(rv)
    {
  case 0:
    break;

  case VNET_API_ERROR_INVALID_SW_IF_INDEX:
    return clib_error_return
      (0, "Invalid interface, only works on physical ports");
    break;

  case VNET_API_ERROR_UNIMPLEMENTED:
    return clib_error_return (0, "Device driver doesn't support redirection");
    break;

  default:
    return clib_error_return (0, "patlu_enable_disable returned %d",
                              rv);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (patlu_enable_disable_command, static) =
{
  .path = "patlu enable-disable",
  .short_help =
  "patlu enable-disable <interface-name> [disable]",
  .function = patlu_enable_disable_command_fn,
};
/* *INDENT-ON* */

/* API message handler */
static void vl_api_patlu_enable_disable_t_handler
(vl_api_patlu_enable_disable_t * mp)
{
  vl_api_patlu_enable_disable_reply_t * rmp;
  patlu_main_t * pmp = &patlu_main;
  int rv;

  rv = patlu_enable_disable (pmp, ntohl(mp->sw_if_index),
                                      (int) (mp->enable_disable));

  REPLY_MACRO(VL_API_PATLU_ENABLE_DISABLE_REPLY);
}

/* API definitions */
#include <patlu/patlu.api.c>

static clib_error_t * patlu_init (vlib_main_t * vm)
{
  patlu_main_t * pmp = &patlu_main;
  clib_error_t * error = 0;

  pmp->vlib_main = vm;
  pmp->vnet_main = vnet_get_main();

  /* Add our API messages to the global name_crc hash table */
  pmp->msg_id_base = setup_message_id_table ();
  if (!pmp->log_path)
    pmp->log_path = "/tmp/dns.log";
  fformat(stdout, "Save dns log to: %s\n", pmp->log_path);
  pmp->fp = fopen(pmp->log_path, "a");
  pmp->epoch_base = unix_time_now_nsec();
  if (!pmp->fp)
    error->code = -1; // XXX: Can we be more specific?
  return error;
}

VLIB_INIT_FUNCTION (patlu_init);

static clib_error_t *
patlu_config (vlib_main_t * vm, unformat_input_t * input) {
  patlu_main_t * pm = &patlu_main;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (input, "log-path %s", &pm->log_path))
      fformat (stdout, "Load DNS log-path from config file [%s]\n", pm->log_path);
    else
      return clib_error_return (0, "unknown input '%U'",
        format_unformat_error, input);
  }
  return 0;
}

VLIB_EARLY_CONFIG_FUNCTION (patlu_config, "patlu");

// using udp_register_dst_port mechanism instead.
/* *INDENT-OFF* */
VNET_FEATURE_INIT (patlu, static) =
{
  // XXX: remember to change vnet_l2_feature_enable_disable above!
  .arc_name = "ip4-unicast",
  .node_name = "patlu",
  .runs_after = VNET_FEATURES ("nat-pre-out2in"),
};
/* *INDENT-ON */

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "patlu plugin description goes here",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
