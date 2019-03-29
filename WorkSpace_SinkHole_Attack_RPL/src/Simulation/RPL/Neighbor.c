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
#include "RPL_enum.h"

PRPL_NEIGHBOR rpl_find_neighbor(NETSIM_ID d, NETSIM_ID r)
{
	PRPL_NODE rpl = GET_RPL_NODE(d);
	UINT i;
	for (i = 0; i < rpl->neighbor_count; i++)
	{
		if (rpl->neighbor_list[i]->nodeId == r)
			return rpl->neighbor_list[i];
	}
	return NULL;
}

static void add_neighbor(NETSIM_ID d, NETSIM_ID r)
{
	PRPL_NODE rpl = GET_RPL_NODE(d);
	if (rpl->neighbor_count)
		rpl->neighbor_list = (PRPL_NEIGHBOR*)realloc(rpl->neighbor_list,(rpl->neighbor_count + 1)* (sizeof* rpl->neighbor_list));
	else
		rpl->neighbor_list = (PRPL_NEIGHBOR*)calloc(1, sizeof* rpl->neighbor_list);
	PRPL_NEIGHBOR neighbor = (PRPL_NEIGHBOR)calloc(1, sizeof* neighbor);
	neighbor->nodeId = r;
	rpl->neighbor_list[rpl->neighbor_count] = neighbor;
	rpl->neighbor_count++;
}

void rpl_add_to_neighbor_list()
{
	NETSIM_ID d = pstruEventDetails->nDeviceId;
	NETSIM_ID r = pstruEventDetails->pPacket->nTransmitterId;

	if (is_rpl_configured(d) && is_rpl_configured(r))
	{
		PRPL_NODE rpl = GET_RPL_NODE(d);
		PRPL_NEIGHBOR neighbor = rpl_find_neighbor(d, r);
		if (!neighbor)
			add_neighbor(d, r);
	}
}

void update_neighbor_dio_message(PRPL_NEIGHBOR neighbor, PRPL_CTRL_MSG dio_pdu)
{
	rpl_dio_pdu_free(neighbor->lastDIOMSG);
	neighbor->lastDIOMSG = rpl_dio_pdu_duplicate(dio_pdu);
}

void rpl_node_add_parent(NETSIM_ID d, PRPL_NEIGHBOR parent)
{
	PRPL_NODE rpl = GET_RPL_NODE(d);
	if (!rpl->joined_dodag)
		fnNetSimError("joined_dodag is null for %d device in %s\n", d, __FUNCTION__);

	PRPL_DODAG dodag = rpl->joined_dodag;

	dodag->parent_list = (PRPL_NEIGHBOR*)realloc(dodag->parent_list, (dodag->parent_count + 1) * sizeof(PRPL_NEIGHBOR));
	dodag->parent_list[dodag->parent_count++] = parent;
}

PRPL_NEIGHBOR rpl_node_find_parent(NETSIM_ID d, NETSIM_ID parent)
{
	PRPL_NODE drpl = GET_RPL_NODE(d);
	if (drpl->joined_dodag == NULL)
		return NULL;

	PRPL_DODAG dodag = drpl->joined_dodag;

	int i;
	for (i = 0; i < dodag->parent_count; i++)
	{
		if (dodag->parent_list[i]->nodeId == parent)
			return dodag->parent_list[i];
	}

	return NULL;
}

void rpl_node_remove_all_parents(NETSIM_ID d)
{
	PRPL_NODE rpl = GET_RPL_NODE(d);
	UINT16 i;
	for (i = 0; i < rpl->joined_dodag->parent_count; i++)
	{
		//Don't free because same pointer is present in neighbor list and siblings also.
		rpl->joined_dodag->parent_list[i] = NULL;
	}
	rpl->joined_dodag->parent_list = NULL;
	rpl->joined_dodag->parent_count = 0;
}

void forget_neighbor_messages(PRPL_NODE rpl)
{
	UINT16 i;
	for (i = 0; i < rpl->neighbor_count; i++)
	{
		PRPL_NEIGHBOR neighbor = rpl->neighbor_list[i];

		if (neighbor->lastDIOMSG != NULL)
		{
			rpl_dio_pdu_free(neighbor->lastDIOMSG);
			neighbor->lastDIOMSG = NULL;
		}
	}
}

void rpl_node_add_sibling(NETSIM_ID d, PRPL_NEIGHBOR sibling)
{
	PRPL_NODE rpl = GET_RPL_NODE(d);

	if (!rpl->joined_dodag)
		fnNetSimError("joined_dodag is null for %d in %s\n", d, __FUNCTION__);

	PRPL_DODAG dodag = rpl->joined_dodag;

	dodag->sibling_list = (PRPL_NEIGHBOR*)realloc(dodag->sibling_list, (dodag->sibling_count + 1) * sizeof(PRPL_NEIGHBOR));
	dodag->sibling_list[dodag->sibling_count++] = sibling;
}

PRPL_NEIGHBOR rpl_node_find_sibling(NETSIM_ID d, NETSIM_ID sibling)
{
	PRPL_NODE drpl = GET_RPL_NODE(d);
	if (drpl->joined_dodag == NULL)
		return NULL;

	PRPL_DODAG dodag = drpl->joined_dodag;

	int i;
	for (i = 0; i < dodag->sibling_count; i++)
	{
		if (dodag->sibling_list[i]->nodeId == sibling)
			return dodag->sibling_list[i];
	}

	return NULL;
}

void rpl_node_remove_all_siblings(NETSIM_ID d)
{
	PRPL_NODE rpl = GET_RPL_NODE(d);
	if (!rpl->joined_dodag)
		fnNetSimError("joined_dodag is null for %d device in %s\n", d, __FUNCTION__);

	PRPL_DODAG dodag = rpl->joined_dodag;

	if (dodag->sibling_list != NULL)
	{
		free(dodag->sibling_list);
		dodag->sibling_list = NULL;
	}

	dodag->sibling_count = 0;
}

static UINT16 compute_candidate_rank(NETSIM_ID d, PRPL_NEIGHBOR neighbor)
{
	if (neighbor->nodeId == 0)
		return INFINITE_RANK;

	double send_link_quality = fn_NetSim_stack_get_link_quality(d, 1, neighbor->nodeId, 1);
	double receive_link_quality = fn_NetSim_stack_get_link_quality(neighbor->nodeId, 1, d, 1);
	double link_quality = (send_link_quality + receive_link_quality) / 2;

	// Objective function. Rank calculation done by default using link quality.
	// Users can change suitable
	UINT16 rank = (UINT16)((RPL_MAXIMUM_RANK_INCREMENT - RPL_MINIMUM_RANK_INCREMENT) * pow((1 - link_quality), 2) + RPL_MINIMUM_RANK_INCREMENT);

	PRPL_DIO_BASE Base = neighbor->lastDIOMSG->Base;
	rank += Base->Rank;

	return rank > INFINITE_RANK ? INFINITE_RANK : rank;
}

void choose_parents_and_siblings(NETSIM_ID d)
{
	PRPL_NODE rpl = GET_RPL_NODE(d);

	if (!rpl->joined_dodag)
		fnNetSimError("joined_dodag is null for %d device in %s\n", d, __FUNCTION__);

	PRPL_DODAG dodag = rpl->joined_dodag;

	/* forget about previous DIO routes */
	rpl_delete_all_route(d);

	rpl_node_remove_all_parents(d);
	rpl_node_remove_all_siblings(d);

	INT16 best_rank_index = -1;

	UINT16* matching_ranks = (UINT16*)calloc(rpl->neighbor_count,sizeof* matching_ranks);

	UINT16 i;
	for (i = 0; i < rpl->neighbor_count; i++)
	{
		PRPL_NEIGHBOR neighbor = rpl->neighbor_list[i];

		matching_ranks[i] = INFINITE_RANK;

		if (neighbor->lastDIOMSG == NULL)
		{ /* ignore neighbors who haven't sent any DIO */
			continue;
		}

		PRPL_DIO_BASE nBase = neighbor->lastDIOMSG->Base;

		if (IP_COMPARE(nBase->DODAGID, dodag->dodag_id) != 0)
		{ /* ignore neighbors from different DODAGs */
			continue;
		}

		if (nBase->DTSN != dodag->seq_num)
		{ /* ignore neighbors from different DODAG iterations */
			continue;
		}

		if (nBase->Rank >= INFINITE_RANK)
		{ /* ignore neighbors that started poisoning */
			continue;
		}

		if (nBase->Rank > dodag->rank)
		{ /* ignore and forget neighbors that aren't our parents or siblings */
			rpl_dio_pdu_free(neighbor->lastDIOMSG);
			neighbor->lastDIOMSG = NULL;
			continue;
		}

		matching_ranks[i] = compute_candidate_rank(d, neighbor);

		if (best_rank_index == -1)
		{
			best_rank_index = i;
			continue;
		}

		if (matching_ranks[i] < matching_ranks[best_rank_index])
		{
			best_rank_index = i;
		}
	}

	if (best_rank_index == -1)
	{ /* no valid neighbors found for this current DODAG iteration */
		print_rpl_log("node '%d': no valid neighbors left in dodag_id = '%s'", d, RPL_IP_TO_STR(dodag->dodag_id));
		bool same;
		PRPL_CTRL_MSG preferred_dodag_pdu = get_preferred_dodag_dio_pdu(d, &same, pstruEventDetails->dEventTime);

		if (preferred_dodag_pdu != NULL && !same)
		{ /* found something interesting around */
			join_dodag_iteration(d, preferred_dodag_pdu);
			choose_parents_and_siblings(d);
		}
		else
		{ /* didn't find anything interesting, we're the best, start floating or poisoning */
			start_dio_poisoning(d);
		}

		return;
	}

	UINT16 best_rank = matching_ranks[best_rank_index];
	if (best_rank - dodag->lowest_rank > dodag->max_rank_inc || best_rank >= INFINITE_RANK)
	{ /* rank would increase too much */
		print_rpl_log("node '%d': in dodag_id = '%s', new rank (%d) would exceed the limit (%d + %d)",
				 d, RPL_IP_TO_STR(dodag->dodag_id), best_rank, dodag->lowest_rank, dodag->max_rank_inc);

		if (rpl->joined_dodag->pref_parent != NULL &&
			rpl->joined_dodag->pref_parent->lastDIOMSG != NULL &&
			((PRPL_DIO_BASE)rpl->joined_dodag->pref_parent->lastDIOMSG)->Rank < INFINITE_RANK)
		{

			print_rpl_log("node '%d': following parent on dodag_id = '%s'",
					 d, ((PRPL_DIO_BASE)rpl->joined_dodag->pref_parent->lastDIOMSG)->DODAGID);

			join_dodag_iteration(d, rpl->joined_dodag->pref_parent->lastDIOMSG);
			choose_parents_and_siblings(d);
		}
		else
		{
			print_rpl_log("node '%d': couldn't follow preferred parent, need to poison", d);
			start_dio_poisoning(d);
		}
		return;
	}

	dodag->rank = best_rank;
	if (best_rank < dodag->lowest_rank)
		dodag->lowest_rank = best_rank;


	NETSIM_ID old_pref_parent = ((dodag->pref_parent == NULL) ? (0) : (dodag->pref_parent->nodeId));
	dodag->pref_parent = rpl->neighbor_list[best_rank_index];
	if (dodag->pref_parent->nodeId != old_pref_parent)
	{
		NetSim_EVENTDETAILS pevent;
		memset(&pevent, 0, sizeof pevent);
		pevent.dEventTime = pstruEventDetails->dEventTime;
		pevent.nDeviceId = d;
		pevent.nDeviceType = DEVICE_TYPE(d);
		pevent.nEventType = TIMER_EVENT;
		pevent.nProtocolId = NW_PROTOCOL_RPL;
		pevent.nSubEventType = RPL_NEW_PREF_PARENT;
		fnpAddEvent(&pevent);
	}
	rpl_add_route_to_parent(d, dodag->pref_parent->nodeId);

	for (i = 0; i < rpl->neighbor_count; i++)
	{
		PRPL_NEIGHBOR neighbor = rpl->neighbor_list[i];

		if (matching_ranks[i] >= INFINITE_RANK)
		{
			if (neighbor->lastDIOMSG != NULL)
			{ /* forget messages from other DODAG iterations */
				rpl_dio_pdu_free(neighbor->lastDIOMSG);
				neighbor->lastDIOMSG = NULL;
			}
			continue;
		}

		PRPL_DIO_BASE dbase = neighbor->lastDIOMSG->Base;

		if (dbase->Rank < best_rank) 
		{ /* a parent */
			rpl_node_add_parent(d, neighbor);
		}
		else if (dbase->Rank == best_rank)
		{ /* a sibling */
			rpl_node_add_sibling(d, neighbor);
		}
		else
		{ /* forget messages from higher ranked nodes */
			if (neighbor->lastDIOMSG != NULL)
			{
				rpl_dio_pdu_free(neighbor->lastDIOMSG);
				neighbor->lastDIOMSG = NULL;
			}
		}
	}

#ifdef DEBUG_RPL

	char parent_list_str[256];
	char sibling_list_str[256];

	dodag = rpl->joined_dodag;

	parent_list_str[0] = '\0';
	for (i = 0; i < dodag->parent_count; i++)
	{
		PRPL_NEIGHBOR neighbor = dodag->parent_list[i];

		if (neighbor == dodag->pref_parent)
		{
			char sz[10];
			sprintf(sz, "(%d)", neighbor->nodeId);
			strcat(parent_list_str, sz);
		}
		else 
		{
			char sz[10];
			sprintf(sz, "%d", neighbor->nodeId);
			strcat(parent_list_str, sz);
		}

		if (i < dodag->parent_count - 1)
		{
			strcat(parent_list_str, ", ");
		}
	}

	sibling_list_str[0] = '\0';
	for (i = 0; i < dodag->sibling_count; i++)
	{
		PRPL_NEIGHBOR neighbor = dodag->sibling_list[i];

		char sz[10];
		sprintf(sz, "%d", neighbor->nodeId);
		strcat(sibling_list_str, sz);
		if (i < dodag->sibling_count - 1)
		{
			strcat(sibling_list_str, ", ");
		}
	}
	print_rpl_log("node '%d': chosen parents and siblings in dodag_id = '%s': new rank = %d, parents = [%s], siblings = [%s]",
			 d, RPL_IP_TO_STR(dodag->dodag_id), dodag->rank, parent_list_str, sibling_list_str);

#endif /* DEBUG_RPL */
}

void free_all_neighbor(PRPL_NODE rpl)
{
	UINT16 i;
	for (i = 0; i < rpl->neighbor_count; i++)
	{
		PRPL_NEIGHBOR n = rpl->neighbor_list[i];
		free(n);
	}
	rpl->neighbor_count = 0;
}