/************************************************************************************
* Copyright (C) 2016                                                               *
* TETCOS, Bangalore. India                                                         *
*                                                                                  *
* Tetcos owns the intellectual property rights in the Product and its content.     *
* The copying, redistribution, reselling or publication of any or all of the       *
* Product or its content without express prior written consent of Tetcos is        *
* prohibited. Ownership and / or any other right relating to the software and all  *
* intellectual property rights therein shall remain at all times with Tetcos.      *
*                                                                                  *
* Author:    Shashi Kant Suman                                                     *
*                                                                                  *
* ---------------------------------------------------------------------------------*/
#include "main.h"
#include "RPL.h"
#include "RPL_Message.h"

static bool dio_pdu_dodag_config_changed(PRPL_CTRL_MSG c1, PRPL_CTRL_MSG c2)
{
	PRPL_DODAG_CONFIG_OPTION d1 = get_option_from_msg(c1, RPLOPTION_DODAGConfiguration);
	PRPL_DODAG_CONFIG_OPTION d2 = get_option_from_msg(c2, RPLOPTION_DODAGConfiguration);

	if (!d2)
		return FALSE;

	if (!d1)
		return true;

	return memcmp(d1, d2, sizeof* d1);
}

static bool dio_pdu_changed(PRPL_NEIGHBOR neighbor, PRPL_CTRL_MSG dio_pdu)
{
	if (neighbor->lastDIOMSG == NULL)
	{
		return TRUE;
	}
	else
	{ 
		PRPL_CTRL_MSG msg = dio_pdu;
		PRPL_DIO_BASE b = msg->Base;
		PRPL_DIO_BASE lb = ((PRPL_CTRL_MSG)neighbor->lastDIOMSG)->Base;

		bool base_changed = (IP_COMPARE(lb->DODAGID, b->DODAGID)) ||
			(lb->Prf != b->Prf) ||
			(lb->DTSN != b->DTSN) ||
			(lb->Rank != b->Rank) ||
			(lb->G != b->G) ||
			(lb->MOP != b->MOP) ||
			(lb->RPLInstanceID != b->RPLInstanceID) ||
			(lb->Version_Number != b->Version_Number);

		bool dodag_config_changed = dio_pdu_dodag_config_changed(neighbor->lastDIOMSG,
																 msg);

		return base_changed || dodag_config_changed;
	}
}

void start_dio_poisoning(NETSIM_ID d)
{
	PRPL_NODE rpl = GET_RPL_NODE(d);
	/* forget about all DIO routes */
	rpl_delete_all_route(d);

	rpl_node_remove_all_parents(d);
	rpl->joined_dodag->pref_parent = NULL;
	
	forget_neighbor_messages(rpl);

	rpl->joined_dodag->rank = INFINITE_RANK;
	rpl->joined_dodag->lowest_rank = INFINITE_RANK;
	rpl->poison_count_so_far = 0;

	rpl_trickle_reset(d);
}

PRPL_CTRL_MSG get_preferred_dodag_dio_pdu(NETSIM_ID d, bool *same,double time)
{
	PRPL_NODE rpl = GET_RPL_NODE(d);
	NetSim_PACKET* root_packet = create_root_dio_message(d, time, FALSE, FALSE);
	PRPL_CTRL_MSG root_dio_pdu = root_packet->pstruNetworkData->Packet_RoutingProtocol;
	PRPL_CTRL_MSG best_dio_pdu = root_dio_pdu;
	PRPL_DIO_BASE best_dio_base = root_dio_pdu->Base;
	root_packet->pstruNetworkData->Packet_RoutingProtocol = NULL;
	fn_NetSim_Packet_FreePacket(root_packet);

	PRPL_NEIGHBOR old_pref_parent = rpl_node_is_joined(rpl) ? rpl->joined_dodag->pref_parent : NULL;

	UINT16 i;
	for (i = 0; i < rpl->neighbor_count; i++)
	{
		PRPL_NEIGHBOR neighbor = rpl->neighbor_list[i];

		if (neighbor->lastDIOMSG == NULL)
		{ /* ignore neighbors who haven't sent any DIO */
			continue;
		}

		PRPL_OPTION dodag_config_suboption = get_option_from_msg(neighbor->lastDIOMSG,RPLOPTION_DODAGConfiguration);
		if (dodag_config_suboption == NULL)
		{ /* ignore neighbors for whom no DODAG config info is available */
			continue;
		}
		PRPL_DIO_BASE diobase = neighbor->lastDIOMSG->Base;

		if (diobase->Rank >= INFINITE_RANK)
		{ /* ignore neighbors that started poisoning */
			continue;
		}

		if (rpl_node_is_joined(rpl) &&
			IP_COMPARE(diobase->DODAGID, rpl->joined_dodag->dodag_id) == 0 &&
			diobase->Rank >= rpl->joined_dodag->rank)
		{ /* ignore neighbors of our DODAG with greater or equal rank */

			continue;
		}

		if (!best_dio_base->G && diobase->G)
		{
			best_dio_pdu = neighbor->lastDIOMSG;
			best_dio_base = best_dio_pdu->Base;
		}
		else if (best_dio_base->G == diobase->G)
		{
			if (best_dio_base->Prf < diobase->Prf)
			{
				best_dio_pdu = neighbor->lastDIOMSG;
				best_dio_base = best_dio_pdu->Base;
			}
			else if (best_dio_base->Prf == diobase->Prf)
			{
				if (best_dio_base->DTSN < diobase->DTSN)
				{
					best_dio_pdu = neighbor->lastDIOMSG;
					best_dio_base = best_dio_pdu->Base;
				}
			}
		}
	}

	if (best_dio_pdu != root_dio_pdu)
	{
		rpl_dio_pdu_free(root_dio_pdu);

		if (rpl_node_is_joined(rpl) || rpl_node_is_poisoning(rpl))
		{
			*same = (IP_COMPARE(rpl->joined_dodag->dodag_id, best_dio_base->DODAGID) == 0) &&
				(rpl->joined_dodag->seq_num == best_dio_base->DTSN);
		}
		else
		{
			*same = FALSE;
		}
		return best_dio_pdu;
	}
	else
	{
		print_rpl_log("node '%d': no preferable DODAG iterations around", d);
		/* give priority to the former parent, to follow him if necessary */

		if (old_pref_parent != NULL &&
			old_pref_parent->lastDIOMSG != NULL)
		{
			PRPL_DIO_BASE diobase = old_pref_parent->lastDIOMSG->Base;
			if (diobase->G == best_dio_base->G &&
				diobase->Prf == best_dio_base->Prf)
			{
				*same = ((IP_COMPARE(rpl->joined_dodag->dodag_id, diobase->DODAGID) == 0) &&
					rpl->joined_dodag->seq_num == diobase->DTSN);

				best_dio_pdu = old_pref_parent->lastDIOMSG;
				best_dio_base = best_dio_pdu->Base;

				rpl_dio_pdu_free(root_dio_pdu);
				return best_dio_pdu;
			}
		}
		else
		{
			rpl_dio_pdu_free(root_dio_pdu);

			*same = rpl_node_is_root(rpl);
			return NULL;
		}
	}
	return NULL;
}

void rpl_process_dio_msg()
{
	NETSIM_ID d = pstruEventDetails->nDeviceId;
	PRPL_CTRL_MSG dioPdu = GET_PRPL_CTRL_MSG(pstruEventDetails->pPacket);
	NETSIM_ID r = pstruEventDetails->pPacket->nTransmitterId;
	PRPL_NODE drpl = GET_RPL_NODE(d);
	PRPL_NODE rrpl = GET_RPL_NODE(r);
	PRPL_DIO_BASE diobase = dioPdu->Base;

	PRPL_NEIGHBOR neighbor = rpl_find_neighbor(d, r);

	if (dio_pdu_changed(neighbor, dioPdu))
	{

		/* ignore messages from members of our DODAG which are neither parents nor siblings and emit a greater rank than us */
		if (rpl_node_is_joined(drpl))
		{
			if (IP_COMPARE(drpl->joined_dodag->dodag_id, diobase->DODAGID) == 0 &&
				drpl->joined_dodag->rank < diobase->Rank &&
				!rpl_node_has_parent(d, r) &&
				!rpl_node_has_sibling(d, r))
			{

				neighbor->lastDIOMSG = NULL; /* make sure we "forgot" the last message for this neighbor */
				return;
			}
		}
		else if (rpl_node_is_root(drpl))
		{
			if (IP_COMPARE(drpl->root_info->dodag_id, diobase->DODAGID) == 0)
			{

				neighbor->lastDIOMSG = NULL; /* make sure we "forgot" the last message for this */
				return;
			}
		}

		print_rpl_log("node '%d': received a new/modified message from node '%d' with dodag_id = '%s'",
				 d, r, RPL_IP_TO_STR(diobase->DODAGID));


		bool dodag_config_changed = dio_pdu_dodag_config_changed(neighbor->lastDIOMSG, dioPdu);

		update_neighbor_dio_message(neighbor, dioPdu);

		/*
		* If we get poison from the preferred parent, we propagate the poisoning mechanism
		*/
		if (rpl_node_is_joined(drpl))
		{
			if ((drpl->joined_dodag->pref_parent == neighbor) &&
				(((PRPL_DIO_BASE)neighbor->lastDIOMSG->Base)->Rank == INFINITE_RANK))
			{
				start_dio_poisoning(d);
				return;
			}
		}
		/* end of poisoning procedure */


		bool same;
		PRPL_CTRL_MSG preferred_dodag_pdu = get_preferred_dodag_dio_pdu(d, &same, pstruEventDetails->dEventTime);

		if (rpl_node_is_isolated(drpl))
		{
			if (preferred_dodag_pdu != NULL) 
			{
				PRPL_DIO_BASE b = preferred_dodag_pdu->Base;
				print_rpl_log("node '%d': was isolated, now found dodag_id = '%s'",
						 d, RPL_IP_TO_STR(b->DODAGID));
				join_dodag_iteration(d, preferred_dodag_pdu);
				choose_parents_and_siblings(d);
			}
			else
			{
				/* don't start as root, since we were configured to start as isolated */
			}
		}
		else if (rpl_node_is_root(drpl))
		{
			if (preferred_dodag_pdu != NULL)
			{
				PRPL_DIO_BASE b = preferred_dodag_pdu->Base;
				print_rpl_log("node '%d': was root of dodag_id = '%s', now found a better one with dodag_id = '%s'",
						 d, drpl->root_info->dodag_id, b->DODAGID);

				join_dodag_iteration(d, preferred_dodag_pdu);
				choose_parents_and_siblings(d);
			}
			else
			{
				/* we're already root */
			}
		}
		else if (rpl_node_is_poisoning(drpl)) 
		{
			/* we ignore everything in this temporary state */
		}
		else if (rpl_node_is_joined(drpl))
		{
			if (!same)
			{
				if (preferred_dodag_pdu != NULL) 
				{
					PRPL_DIO_BASE b = preferred_dodag_pdu->Base;
					print_rpl_log("node '%d': was member of dodag_id = '%s', now found a better one with dodag_id = '%s'",
							 d, drpl->joined_dodag->dodag_id, b->DODAGID);

					join_dodag_iteration(d, preferred_dodag_pdu);
					choose_parents_and_siblings(d);
				}
				else
				{
					print_rpl_log("node '%d': was member of dodag_id = '%s', now starting own root",
							 d, drpl->joined_dodag->dodag_id);
					start_as_root(d);
				}
			}
			else
			{
				PRPL_DIO_BASE dbase = neighbor->lastDIOMSG->Base;
				/* a new member of our DODAG is a potential parent/sibling, need to reevaluate our neighbors */
				if (IP_COMPARE(dbase->DODAGID, drpl->joined_dodag->dodag_id) == 0) 
				{
					print_rpl_log("node '%d': '%d' sent a modified DIO message and is a member of dodag_id = '%s', reevaluating our neighbors",
							 d, r, RPL_IP_TO_STR(drpl->joined_dodag->dodag_id));

					choose_parents_and_siblings(d);
				}
				else 
				{
					print_rpl_log("node '%d': remaining in dodag_id = '%s'", d, RPL_IP_TO_STR(drpl->joined_dodag->dodag_id));
				}

				/* consider dodag config updates, but only from parents */
				if (dodag_config_changed && rpl_node_has_parent(d, r))
				{
					update_dodag_config(d, dioPdu);
				}
			}
		}
		else 
		{ /* this should never happen */
			fnNetSimError("node '%d': not root, not joined, not poisoning and not isolated either, what are we anyway?", d);
		}
	}
}

void rpl_dio_msg_copy(const NetSim_PACKET* destPacket, const NetSim_PACKET* srcPacket)
{
	PRPL_CTRL_MSG srpl = srcPacket->pstruNetworkData->Packet_RoutingProtocol;
	PRPL_CTRL_MSG drpl = rpl_dio_pdu_duplicate(srpl);
	destPacket->pstruNetworkData->Packet_RoutingProtocol = drpl;
}

void rpl_dio_msg_destroy(NetSim_PACKET* packet)
{
	PRPL_CTRL_MSG srpl = packet->pstruNetworkData->Packet_RoutingProtocol;
	rpl_dio_pdu_free(srpl);
	packet->pstruNetworkData->Packet_RoutingProtocol = NULL;
}