/* Copyright (c) 2011, TrafficLab, Ericsson Research, Hungary
 * Copyright (c) 2012, CPqD, Brazil
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of the Ericsson Research nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include "packet_handle_std.h"
#include "packet.h"
#include "packets.h"
#include "oflib/ofl-structs.h"
#include "openflow/openflow.h"
#include "compiler.h"

#include "lib/hash.h"
#include "lib/util.h"
#include "oflib/oxm-match.h"

#include "dp_capabilities.h"
#include "oflib-exp/ofl-exp-beba.h"

#include "../config.h"


int packet_parse(struct packet const *pkt, struct oxm_packet_info *, struct protocols_std *proto);

int packet_parse(struct packet const *pkt, struct oxm_packet_info *info, struct protocols_std *proto)
{
	size_t offset = 0;
	uint16_t eth_type = 0x0000;
        uint8_t next_proto = 0;

	/* Resets all protocol fields to NULL */

	protocol_reset(proto);

#ifdef SKIP_TRILL
	/* Optional functionality that removes TRILL encapsulation in live trials. */
	size_t search_offset = 0;

	/* Search for network layer protocol or TRILL header. */
	if (pkt->buffer->size > search_offset + sizeof(struct eth_header)) {
		struct eth_header* outer_eth = (struct eth_header *)((uint8_t const *) pkt->buffer->data + search_offset);
		search_offset += sizeof(struct eth_header);
		uint16_t outer_type = ntohs(outer_eth->eth_type);
		while ((outer_type >= ETH_TYPE_II_START) && (
				(outer_type == ETH_TYPE_VLAN) ||
				(outer_type == ETH_TYPE_SVLAN) ||
				(outer_type == ETH_TYPE_VLAN_QinQ) ||
				(outer_type == ETH_TYPE_VLAN_PBB_B) ||
				(outer_type == ETH_TYPE_VLAN_PBB_S)
			) && (pkt->buffer->size > search_offset + sizeof(struct vlan_header))
		)	{
			/* Skip VLANs */
			struct vlan_header* outer_vlan = (struct vlan_header *)((uint8_t const *) pkt->buffer->data + search_offset);
			search_offset += sizeof(struct vlan_header);
			outer_type = ntohs(outer_vlan->vlan_next_type);
		}
		if (outer_type == ETH_TYPE_TRILL) {
			uint8_t const *trill = (uint8_t const *) pkt->buffer->data;
			uint16_t o1 = (trill[search_offset] & 0x07) << 2;
			uint16_t o2 = (trill[search_offset + 1] & 0xc0) >> 2;
			uint16_t trill_options = o1 | o2;
			offset = search_offset + 6 + trill_options * 4;
		}
	}
#endif

        /* Ethernet */

	if (unlikely(pkt->buffer->size < offset + sizeof(struct eth_header))) {
            return -1;
        }

        proto->eth = (struct eth_header *)((uint8_t const *) pkt->buffer->data + offset);
        offset += sizeof(struct eth_header);

	eth_type = ntohs(proto->eth->eth_type);

        if (eth_type >= ETH_TYPE_II_START) {

            /* Ethernet II */

	    memcpy(info->eth_src, proto->eth->eth_src, ETH_ADDR_LEN);
	    memcpy(info->eth_dst, proto->eth->eth_dst, ETH_ADDR_LEN);

	    oxm_set_valid(info,eth_src);
	    oxm_set_valid(info,eth_dst);

            if (eth_type != ETH_TYPE_VLAN &&
                eth_type != ETH_TYPE_VLAN_PBB) {

		oxm_set_info(info, eth_type, eth_type);
            };

        } else {

            /* Ethernet 802.3 */

            struct llc_header const *llc;

	    if (unlikely(pkt->buffer->size < offset + sizeof(struct llc_header))) {
                return -1;
            }

            llc = (struct llc_header const *)((uint8_t const *)pkt->buffer->data + offset);
            offset += sizeof(struct llc_header);

		if (unlikely(!(llc->llc_dsap == LLC_DSAP_SNAP &&
			       llc->llc_ssap == LLC_SSAP_SNAP &&
			       llc->llc_cntl == LLC_CNTL_SNAP))) {
                return -1;
            }

	    if (unlikely(pkt->buffer->size < offset + sizeof(struct snap_header))) {
                return -1;
            }

            proto->eth_snap = (struct snap_header *)((uint8_t const *) pkt->buffer->data + offset);
            offset += sizeof(struct snap_header);

	    if (unlikely(memcmp(proto->eth_snap->snap_org, SNAP_ORG_ETHERNET, sizeof(SNAP_ORG_ETHERNET)) != 0)) {
                return -1;
            }

	    eth_type = ntohs(proto->eth->eth_type);

	    memcpy(info->eth_src, proto->eth->eth_src, ETH_ADDR_LEN);
	    memcpy(info->eth_dst, proto->eth->eth_dst, ETH_ADDR_LEN);

	    oxm_set_valid(info, eth_src);
	    oxm_set_valid(info, eth_dst);

            oxm_set_info(info, eth_type, eth_type);
        }

        /* VLAN */

        if (eth_type == ETH_TYPE_VLAN || eth_type == ETH_TYPE_VLAN_PBB) {

            uint16_t vlan_id;
            uint8_t vlan_pcp;

	    if (unlikely(pkt->buffer->size < offset + sizeof(struct vlan_header))) {
                return -1;
            }

            proto->vlan = (struct vlan_header *)((uint8_t const *) pkt->buffer->data + offset);
            proto->vlan_last = proto->vlan;
            offset += sizeof(struct vlan_header);
            vlan_id  = (ntohs(proto->vlan->vlan_tci) & VLAN_VID_MASK) >> VLAN_VID_SHIFT;
            vlan_pcp = (ntohs(proto->vlan->vlan_tci) & VLAN_PCP_MASK) >> VLAN_PCP_SHIFT;

	    oxm_set_info(info, vlan_id, vlan_id);
	    oxm_set_info(info, vlan_pcp, vlan_pcp);

            // Note: DL type is updated
            //
	    eth_type = ntohs(proto->vlan->vlan_next_type);
            if (eth_type != ETH_TYPE_VLAN &&
                eth_type != ETH_TYPE_VLAN_PBB) {

                oxm_set_info(info, eth_type, eth_type);
            };
        }

        /* skip through rest of VLAN tags */

        while (eth_type == ETH_TYPE_VLAN || eth_type == ETH_TYPE_VLAN_PBB) {

	    if (unlikely(pkt->buffer->size < offset + sizeof(struct vlan_header))) {
                return -1;
            }
            proto->vlan_last = (struct vlan_header *)((uint8_t const *) pkt->buffer->data + offset);
            offset += sizeof(struct vlan_header);

	    eth_type = ntohs(proto->vlan->vlan_next_type);
            if (eth_type != ETH_TYPE_VLAN &&
                eth_type != ETH_TYPE_VLAN_PBB) {

                oxm_set_info(info, eth_type, eth_type);
            };
        }


	switch(eth_type) {

	case ETH_TYPE_PBB:  {
            uint32_t isid;

	    if (unlikely(pkt->buffer->size < offset + sizeof(struct pbb_header))) {
                return -1;
            }
            proto->pbb = (struct pbb_header*) ((uint8_t const *) pkt->buffer->data + offset);

            offset += sizeof(struct pbb_header);
            isid = ntohl( proto->pbb->id)  & PBB_ISID_MASK;

	    oxm_set_info(info, pbb_isid, isid);

            return 0;
        }

	case ETH_TYPE_MPLS:
	case ETH_TYPE_MPLS_MCAST: {
            uint32_t mpls_label;
            uint32_t mpls_tc;
            uint32_t mpls_bos;

	    if (unlikely(pkt->buffer->size < offset + sizeof(struct mpls_header))) {
                return -1;
            }

            proto->mpls = (struct mpls_header *)((uint8_t const *) pkt->buffer->data + offset);
            offset += sizeof(struct mpls_header);

            mpls_label = (ntohl(proto->mpls->fields) & MPLS_LABEL_MASK) >> MPLS_LABEL_SHIFT;
            mpls_bos = (ntohl(proto->mpls->fields) & MPLS_S_MASK) >> MPLS_S_SHIFT;
            mpls_tc = (ntohl(proto->mpls->fields) & MPLS_TC_MASK) >> MPLS_TC_SHIFT;

	    oxm_set_info(info, mpls_label, mpls_label);
	    oxm_set_info(info, mpls_tc, mpls_tc);
	    oxm_set_info(info, mpls_bos, mpls_bos);

            /* no processing past MPLS */
            return 0;
        }

	case ETH_TYPE_ARP: {

	    if (unlikely(pkt->buffer->size < offset + sizeof(struct arp_eth_header))) {
                return -1;
            }
            proto->arp = (struct arp_eth_header *)((uint8_t const *) pkt->buffer->data + offset);
            offset += sizeof(struct arp_eth_header);

            if (ntohs(proto->arp->ar_hrd) == 1 &&
                ntohs(proto->arp->ar_pro) == ETH_TYPE_IP &&
                proto->arp->ar_hln == ETH_ADDR_LEN &&
                proto->arp->ar_pln == 4) {

                if (ntohs(proto->arp->ar_op) <= 0xff) {

		    oxm_set_info(info, arp_ar_op, proto->arp->ar_op);

                }
                if (ntohs(proto->arp->ar_op) == ARP_OP_REQUEST ||
                    ntohs(proto->arp->ar_op) == ARP_OP_REPLY) {

		    memcpy(&info->arp_ar_sha, proto->arp->ar_sha, ETH_ADDR_LEN);
		    oxm_set_valid(info, arp_ar_sha);

		    memcpy(&info->arp_ar_tha, proto->arp->ar_tha, ETH_ADDR_LEN);
		    oxm_set_valid(info, arp_ar_tha);

		    oxm_set_info(info, arp_ar_spa, proto->arp->ar_spa);
		    oxm_set_info(info, arp_ar_tpa, proto->arp->ar_tpa);
                }
            }

            return 0;
        }

	case ETH_TYPE_IPV6: {

            uint32_t ipv6_fl;

	    if (unlikely(pkt->buffer->size < offset + sizeof(struct ipv6_header))) {
                return -1;
            }
            proto->ipv6 = (struct ipv6_header *)((uint8_t const *) pkt->buffer->data + offset);

            offset += sizeof(struct ipv6_header);

	    memcpy(&info->ipv6_src, proto->ipv6->ipv6_src.s6_addr, IPv6_ADDR_LEN);
	    memcpy(&info->ipv6_dst, proto->ipv6->ipv6_dst.s6_addr, IPv6_ADDR_LEN);

	    oxm_set_valid(info, ipv6_src);
	    oxm_set_valid(info, ipv6_dst);

            ipv6_fl =  IPV6_FLABEL(ntohl(proto->ipv6->ipv6_ver_tc_fl));

	    oxm_set_info(info, ipv6_fl,ipv6_fl);
	    oxm_set_info(info, ipv6_next_hd, proto->ipv6->ipv6_next_hd);

            next_proto = proto->ipv6->ipv6_next_hd;

            /*TODO: Check for extension headers*/
        }

	case ETH_TYPE_IP: {

	    if (unlikely(pkt->buffer->size < offset + sizeof(struct ip_header))) {
                return -1;
            }

            proto->ipv4 = (struct ip_header *)((uint8_t const *) pkt->buffer->data + offset);
            offset += sizeof(struct ip_header);

	    oxm_set_info(info, ip_src,   proto->ipv4->ip_src);
	    oxm_set_info(info, ip_dst,   proto->ipv4->ip_dst);
	    oxm_set_info(info, ip_proto, proto->ipv4->ip_proto);
            oxm_set_info(info, ip_ecn,   proto->ipv4->ip_tos & IP_ECN_MASK);
            oxm_set_info(info, ip_dscp,  proto->ipv4->ip_tos >> 2);

            if (IP_IS_FRAGMENT(proto->ipv4->ip_frag_off)) {
                /* No further processing for fragmented IPv4 */
                return 0;
            }
            next_proto = proto->ipv4->ip_proto;
        }
	}

	switch (next_proto) {

	case IP_TYPE_TCP: {
            uint16_t maskedFlags;

	    if (unlikely(pkt->buffer->size < offset + sizeof(struct tcp_header))) {
                return -1;
            }
            proto->tcp = (struct tcp_header *)((uint8_t const *) pkt->buffer->data + offset);
            offset += sizeof(struct tcp_header);

	    oxm_set_info(info, tcp_src, ntohs(proto->tcp->tcp_src));
	    oxm_set_info(info, tcp_dst, ntohs(proto->tcp->tcp_dst));

            maskedFlags = ntohs(proto->tcp->tcp_ctl) & 0x1ff;

	    oxm_set_info(info, tcp_flags, maskedFlags);

            return 0;
        }
	case IP_TYPE_UDP: {

	    if (unlikely(pkt->buffer->size < offset + sizeof(struct udp_header))) {
                return -1;
            }
            proto->udp = (struct udp_header *)((uint8_t const *) pkt->buffer->data + offset);
            offset += sizeof(struct udp_header);

	    oxm_set_info(info, udp_src, ntohs(proto->udp->udp_src));
	    oxm_set_info(info, udp_dst, ntohs(proto->udp->udp_dst));

            return 0;

        }
	case IP_TYPE_ICMP: {

	    if (unlikely(pkt->buffer->size < offset + sizeof(struct icmp_header))) {
                return -1;
            }
            proto->icmp = (struct icmp_header *)((uint8_t const *) pkt->buffer->data + offset);
            offset += sizeof(struct icmp_header);

            oxm_set_info(info, icmp_type, proto->icmp->icmp_type);
            oxm_set_info(info, icmp_code, proto->icmp->icmp_code);

            return 0;

        }
	case IPV6_TYPE_ICMPV6: {

	    if (unlikely(pkt->buffer->size < offset + sizeof(struct icmp_header))) {
                return -1;
            }
            proto->icmp = (struct icmp_header *)((uint8_t const *) pkt->buffer->data + offset);
            offset += sizeof(struct icmp_header);

            oxm_set_info(info, icmp6_type, proto->icmp->icmp_type);
            oxm_set_info(info, icmp6_code, proto->icmp->icmp_code);

            /*IPV6 Neighbor Discovery */
            if(proto->icmp->icmp_type == ICMPV6_NEIGHSOL ||
               proto->icmp->icmp_type == ICMPV6_NEIGHADV){

                struct ipv6_nd_header *nd;
                struct ipv6_nd_options_hd *opt;
			if (unlikely(pkt->buffer->size < offset + sizeof(struct ipv6_nd_header))) {
                    return -1;
                }
                nd = (struct ipv6_nd_header*) ((uint8_t const *) pkt->buffer->data + offset);
                offset += sizeof(struct ipv6_nd_header);

		memcpy(info->ipv6_nd_target, nd->target_addr.s6_addr, IPv6_ADDR_LEN);
		oxm_set_valid(info, ipv6_nd_target);

		if (unlikely(pkt->buffer->size < offset + IPV6_ND_OPT_HD_LEN)) {
                    return -1;
                }
                opt = (struct ipv6_nd_options_hd*)((uint8_t const *) pkt->buffer->data + offset);
                if(opt->type == ND_OPT_SLL){

                    memcpy(info->ipv6_nd_sll, ((uint8_t const *)pkt->buffer->data + offset + IPV6_ND_OPT_HD_LEN), ETH_ADDR_LEN);
		    oxm_set_valid(info, ipv6_nd_sll);

                    offset += IPV6_ND_OPT_HD_LEN + ETH_ADDR_LEN;
                }
                else if(opt->type == ND_OPT_TLL){

                    memcpy(info->ipv6_nd_tll, ((uint8_t const *)pkt->buffer->data + offset + IPV6_ND_OPT_HD_LEN), ETH_ADDR_LEN);
		    oxm_set_valid(info, ipv6_nd_tll);

                    offset += IPV6_ND_OPT_HD_LEN + ETH_ADDR_LEN;
                }
            }

            return 0;
        }
	case IP_TYPE_SCTP: {

	    if (unlikely(pkt->buffer->size < offset + sizeof(struct sctp_header))) {
                return -1;
            }
            proto->sctp = (struct sctp_header *)((uint8_t const *)pkt->buffer->data + offset);
            offset += sizeof(struct sctp_header);

            oxm_set_info(info, sctp_src, ntohs(proto->sctp->sctp_src));
            oxm_set_info(info, sctp_dst, ntohs(proto->sctp->sctp_dst));

            return 0;
        }
	}

        return -1;
}


void
packet_handle_std_validate(struct packet_handle_std *handle) {

    // struct ofl_match_tlv * iter, *next, *f;
    //

    uint64_t metadata     = 0;
    uint64_t tunnel_id    = 0;
    uint32_t state        = 0;
    uint32_t global_state = OFP_GLOBAL_STATE_DEFAULT;

    bool has_state = false;

    if(handle->valid)
        return;

    if (oxm_has_valid(&handle->info, metadata))
    {
	metadata = handle->info.metadata;
    }

    if (oxm_has_valid(&handle->info, tunnel_id))
    {
	tunnel_id = handle->info.tunnel_id;
    }

    #if BEBA_STATE_ENABLED != 0

    if (oxm_has_valid(&handle->info, global_state))
    {
	global_state = handle->info.global_state;
    }

    if (oxm_has_valid(&handle->info, state))
    {
	state = handle->info.state;
	has_state = true;
    }

    #endif


    oxm_reset_all(&handle->info);

    if (packet_parse(handle->pkt, &handle->info, &handle->proto) < 0)
        return;

    handle->valid = true;

    /* Add in_port value to the hash_map */

    oxm_set_info(&handle->info, in_port, handle->pkt->in_port);

    #if BEBA_STATE_ENABLED != 0

    oxm_set_info(&handle->info, global_state, global_state);

    /* Add global register value to the hash_map */

    if(has_state)
    {
	oxm_set_info(&handle->info, state, state);
    }
    #endif

    /*Add metadata  and tunnel_id value to the hash_map */

    oxm_set_info(&handle->info, metadata, metadata);
    oxm_set_info(&handle->info, tunnel_id, tunnel_id);
}


bool
packet_handle_std_is_ttl_valid(struct packet_handle_std *handle) {
    packet_handle_std_validate(handle);

    if (handle->proto.mpls != NULL) {
        uint32_t ttl = ntohl(handle->proto.mpls->fields) & MPLS_TTL_MASK;
        if (ttl <= 1) {
            return false;
        }
    }
    if (handle->proto.ipv4 != NULL) {
        if (handle->proto.ipv4->ip_ttl < 1) {
            return false;
        }
    }
    return true;
}


/* If pointer is not null, returns str; otherwise returns an empty string. */
static inline const char *
pstr(void *ptr, const char *str) {
    return (ptr == NULL) ? "" : str;
}

/* Prints the names of protocols that are available in the given protocol stack. */

static void
proto_print(FILE *stream, struct protocols_std *p) {
    fprintf(stream, "{%s%s%s%s%s%s%s%s%s}",
            pstr(p->eth, "eth"), pstr(p->vlan, ",vlan"), pstr(p->mpls, ",mpls"), pstr(p->ipv4, ",ipv4"),
            pstr(p->arp, ",arp"), pstr(p->tcp, ",tcp"), pstr(p->udp, ",udp"), pstr(p->sctp, ",sctp"),
            pstr(p->icmp, ",icmp"));
}

char *
packet_handle_std_to_string(struct packet_handle_std *handle) {
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    packet_handle_std_print(stream, handle);

    fclose(stream);
    return str;
}

void
packet_handle_std_print(FILE *stream, struct packet_handle_std *handle) {
    packet_handle_std_validate(handle);

    fprintf(stream, "{proto=");
    proto_print(stream, &handle->proto);

    fprintf(stream, ", match=");
    // OXM_TODO
    // ofl_structs_match_print(stream, (struct ofl_match_header *)(&handle->pkt_match), handle->pkt->dp->exp);
    fprintf(stream, "\"}");
}

