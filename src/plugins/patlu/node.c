/*
 * node.c - skeleton vpp engine plug-in dual-loop node skeleton
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
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/error.h>
#include <patlu/patlu.h>

#include <dns/dns_packet.h>
#include <dns/dns.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vlib/unix/plugin.h>
#include <vppinfra/format.h>
#include <dns/dns.api_types.h>

typedef struct
{
  bool is_dns_reply;
  ip4_address_t dns_client_ip;
  u8 *dns_request_name;
  ip4_address_t dns_resp_ip;
} patlu_trace_t;

#ifndef CLIB_MARCH_VARIANT

/* packet trace format function */
static u8 *format_patlu_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  patlu_trace_t *t = va_arg (*args, patlu_trace_t *);

  if (t->is_dns_reply) {
    s = format (s, "PATLU: %U requests %s -> %U",
              format_ip4_address, &t->dns_client_ip, t->dns_request_name,
              format_ip4_address, &t->dns_resp_ip);
  }
  else
    s = format (s, "PATLU: non-DNS requests pass-through");
  return s;
}

vlib_node_registration_t patlu_node;

#endif /* CLIB_MARCH_VARIANT */

#define foreach_patlu_error               \
_ (REPLY, "DNS reply packets processed")  \
_ (OTHER, "non-DNS packets processed")

typedef enum
{
#define _(sym, str) PATLU_ERROR_##sym,
  foreach_patlu_error
#undef _
      PATLU_N_ERROR,
} patlu_error_t;

#ifndef CLIB_MARCH_VARIANT
static char *patlu_error_strings[] = {
#define _(sym, string) string,
    foreach_patlu_error
#undef _
};
#endif /* CLIB_MARCH_VARIANT */

typedef enum
{
  PATLU_NEXT_NODE,
  PATLU_N_NEXT,
} patlu_next_t;

static inline void handle (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b0,
                          u32* reply_pkts, u32* other_pkts)
{
  //vlib_buffer_advance(b0, sizeof (ethernet_header_t));
  ip4_header_t *ip40 = (ip4_header_t *) vlib_buffer_get_current(b0);
  udp_header_t *u0 = (udp_header_t *) (ip40 + 1);
  dns_header_t *d0 = (dns_header_t *) (u0 + 1);
  dns_query_t *q0 = (dns_query_t *) (d0 + 1);
  bool is_dns_reply = false;

  u8 *name0;
  vl_api_dns_resolve_name_reply_t rmp;

  /**
   *  XXX: What's the implication of buffer_advance for next node?
   *       Since I don't know the implication, better to shift back now.
   */
  //vlib_buffer_advance(b0, -sizeof (ethernet_header_t));

  if (ip40->protocol == 17 && clib_net_to_host_u16 (u0->src_port) == 53) {
    u16 flags = clib_net_to_host_u16(d0->flags);
    if (flags & DNS_QR) {
      (*reply_pkts)++;
      is_dns_reply = true;
    } else
      clib_warning ("DNS resp packet error!? src_port=53, DNS_QR bit is 0");
  } else
    (*other_pkts)++;

  if (is_dns_reply) {
    // parse the packet
    // call fformat
    u8 * label0 = (u8 *) q0;
    u8 *(*fp) (u8 *, u8 *, u8 **) = vlib_get_plugin_symbol ("dns_plugin.so", "vnet_dns_labels_to_name");
    int (*fp2) (u8*, vl_api_dns_resolve_name_reply_t *, u32 *) = vlib_get_plugin_symbol("dns_plugin.so", "vnet_dns_response_to_reply");

    if (fp == 0 || fp2 == 0)
      clib_warning ("dns_plugin.so not loaded...");
    else {
      // 1. extract domain name
      name0 = (*fp) (label0, (u8 *)d0, (u8 **)&q0);
      // needs to make name0 null-terminated.
      name0 = format (name0, "%c", 0);

      // 2. extract resolved IP
      int rv = (*fp2) ((u8 *)d0, &rmp, 0);
      if (rv)
        clib_warning ("vnet_dns_response_to_reply failed with rv=%d", rv);
      else if (rmp.ip4_set) {
        u64 ts = patlu_main.epoch_base + vlib_time_now(vm) * 1e9;
        fformat (patlu_main.fp, "%llu %U %s %U\n",
              ts,
              format_ip4_address, &ip40->dst_address, name0,
              format_ip4_address, &rmp.ip4_address);
        fflush(patlu_main.fp);
      }
    }
  }

  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
                     (b0->flags & VLIB_BUFFER_IS_TRACED)))
    {
      patlu_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
      t->is_dns_reply = is_dns_reply;
      if (PREDICT_FALSE (is_dns_reply)) {
        t->dns_client_ip = ip40->dst_address;
        t->dns_request_name = name0;
        clib_memcpy_fast(t->dns_resp_ip.as_u8, rmp.ip4_address, 4);
      }
    }
}

VLIB_NODE_FN (patlu_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_left_from, *from, *to_next;
  patlu_next_t next_index;
  u32 dns_reply_pkts = 0;
  u32 other_pkts = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
        {
          u32 next0 = PATLU_NEXT_NODE;
          u32 next1 = PATLU_NEXT_NODE;
          u32 bi0, bi1;
          vlib_buffer_t *b0, *b1;

          /* Prefetch next iteration. */
          {
            vlib_buffer_t *p2, *p3;

            p2 = vlib_get_buffer (vm, from[2]);
            p3 = vlib_get_buffer (vm, from[3]);

            vlib_prefetch_buffer_header (p2, LOAD);
            vlib_prefetch_buffer_header (p3, LOAD);

            CLIB_PREFETCH (p2->data, CLIB_CACHE_LINE_BYTES, STORE);
            CLIB_PREFETCH (p3->data, CLIB_CACHE_LINE_BYTES, STORE);
          }

          /* speculatively enqueue b0 and b1 to the current next frame */
          to_next[0] = bi0 = from[0];
          to_next[1] = bi1 = from[1];
          from += 2;
          to_next += 2;
          n_left_from -= 2;
          n_left_to_next -= 2;

          b0 = vlib_get_buffer (vm, bi0);
          b1 = vlib_get_buffer (vm, bi1);

          ASSERT (b0->current_data == 0);
          ASSERT (b1->current_data == 0);

          vnet_feature_next (&next0, b0);
          vnet_feature_next (&next1, b1);

          handle(vm, node, b0, &dns_reply_pkts, &other_pkts);
          handle(vm, node, b1, &dns_reply_pkts, &other_pkts);

          /* verify speculative enqueues, maybe switch current next frame */
          vlib_validate_buffer_enqueue_x2 (vm, node, next_index, to_next,
                                           n_left_to_next, bi0, bi1, next0,
                                           next1);
        }
      while (n_left_from > 0 && n_left_to_next > 0)
        {
          u32 bi0;
          vlib_buffer_t *b0;
          u32 next0 = PATLU_NEXT_NODE;

          /* speculatively enqueue b0 to the current next frame */
          bi0 = from[0];
          to_next[0] = bi0;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b0 = vlib_get_buffer (vm, bi0);
          /**
           * l2-input-ip4 feature arc should hand us packet from offset 0
           * aka at &b0->data[0]
           */
          ASSERT (b0->current_data == 0);
          vnet_feature_next (&next0, b0);
          handle(vm, node, b0, &dns_reply_pkts, &other_pkts);

          /* verify speculative enqueue, maybe switch current next frame */
          vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
                                           n_left_to_next, bi0, next0);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, patlu_node.index, PATLU_ERROR_REPLY,
                               dns_reply_pkts);
  vlib_node_increment_counter (vm, patlu_node.index, PATLU_ERROR_OTHER,
                               other_pkts);
  return frame->n_vectors;
}

/* *INDENT-OFF* */
#ifndef CLIB_MARCH_VARIANT
VLIB_REGISTER_NODE (patlu_node) = {
    .name = "patlu",
    .vector_size = sizeof (u32),
    .format_trace = format_patlu_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,

    .n_errors = ARRAY_LEN (patlu_error_strings),
    .error_strings = patlu_error_strings,

    .n_next_nodes = PATLU_N_NEXT,

    /* edit / add dispositions here */
    .next_nodes =
        {
            [PATLU_NEXT_NODE] = "error-punt",
        },
};
#endif /* CLIB_MARCH_VARIANT */
/* *INDENT-ON* */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
