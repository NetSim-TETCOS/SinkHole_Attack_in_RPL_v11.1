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
#include "RPL_enum.h"

PRPL_DODAG rpl_dodag_create(PRPL_CTRL_MSG dio_pdu)
{
	PRPL_DIO_BASE diobase = dio_pdu->Base;
	PRPL_DODAG_CONFIG_OPTION dodag_config_suboption = get_option_from_msg(dio_pdu, RPLOPTION_DODAGConfiguration);

	if (!dodag_config_suboption)
		fnNetSimError("%s function is called without dodag config suboption\n", __FUNCTION__);

	PRPL_DODAG dodag = (PRPL_DODAG)calloc(1,sizeof* dodag);

	dodag->dodag_id = IP_COPY(diobase->DODAGID);
	dodag->dodag_pref = diobase->Prf;
	dodag->grounded = diobase->G;
	dodag->dao_supported = true;
	dodag->dao_trigger = true;

	dodag->dio_interval_doublings = dodag_config_suboption->DIOIntDoubl;
	dodag->dio_interval_min = dodag_config_suboption->DIOIntMin;
	dodag->dio_redundancy_constant = dodag_config_suboption->DIORedun;
	dodag->max_rank_inc = dodag_config_suboption->MaxRankIncrease;
	dodag->min_hop_rank_inc = dodag_config_suboption->MinHopRankIncrease;

	dodag->seq_num = diobase->DTSN;
	dodag->lowest_rank = INFINITE_RANK;
	dodag->rank = INFINITE_RANK;

	dodag->parent_list = NULL;
	dodag->parent_count = 0;
	dodag->sibling_list = NULL;
	dodag->sibling_count = 0;
	dodag->pref_parent = NULL;

	return dodag;
}

void rpl_dodag_destroy(PRPL_DODAG dodag)
{
	if (dodag->dodag_id != NULL)
	{
		IP_FREE(dodag->dodag_id);
	}

	if (dodag->parent_list != NULL)
	{
		free(dodag->parent_list);
	}

	if (dodag->sibling_list != NULL)
	{
		free(dodag->sibling_list);
	}

	free(dodag);
}

void join_dodag_iteration(NETSIM_ID d, PRPL_CTRL_MSG dio_pdu)
{
	PRPL_NODE rpl = GET_RPL_NODE(d);

	if (rpl->joined_dodag != NULL)
	{
		/* forget about previously learned DIO routes */
		rpl_delete_all_route(d);
		rpl_dodag_destroy(rpl->joined_dodag);
	}

	if (rpl->root_info->dodag_id != NULL)
	{ /* if we were previously a root */
		IP_FREE(rpl->root_info->dodag_id);
		rpl->root_info->dodag_id = NULL;
	}

	rpl->joined_dodag = rpl_dodag_create(dio_pdu);

	fnDeleteEvent(rpl->dao_send_eventid);
	
	if (rpl->joined_dodag->dao_supported)
	{
		NetSim_EVENTDETAILS pevent;
		memset(&pevent, 0, sizeof pevent);
		pevent.dEventTime = pstruEventDetails->dEventTime;
		pevent.nDeviceId = d;
		pevent.nDeviceType = DEVICE_TYPE(d);
		pevent.nEventType = TIMER_EVENT;
		pevent.nProtocolId = NW_PROTOCOL_RPL;
		pevent.nSubEventType = RPL_SEND_DAO;
		rpl->dao_send_eventid = fnpAddEvent(&pevent);
	}

	seq_num_mapping_cleanup();

	rpl_trickle_reset(d);
}

void update_dodag_config(NETSIM_ID node, PRPL_CTRL_MSG dio_pdu)
{
	PRPL_DIO_BASE dBase = dio_pdu->Base;
	PRPL_NODE rpl = GET_RPL_NODE(node);
	PRPL_DODAG_CONFIG_OPTION dodag_config_suboption = get_option_from_msg(dio_pdu, RPLOPTION_DODAGConfiguration);
	if (!rpl->joined_dodag)
		fnNetSimError("joined_dodag is null for %d in %s\n", node, __FUNCTION__);

	if (!dodag_config_suboption)
		fnNetSimError("dodag_config_suboption is not present in dio msg in %s\n", __FUNCTION__);

	PRPL_DODAG dodag = rpl->joined_dodag;

	dodag->dio_interval_doublings = dodag_config_suboption->DIOIntDoubl;
	dodag->dio_interval_min = dodag_config_suboption->DIOIntMin;
	dodag->dio_redundancy_constant = dodag_config_suboption->DIORedun;
	dodag->max_rank_inc = dodag_config_suboption->MaxRankIncrease;
	dodag->min_hop_rank_inc = dodag_config_suboption->MinHopRankIncrease;

	print_rpl_log("node '%d': in dodag_id = '%s', updated dodag config (i_min = %d, i_doublings = %d, c_treshold = %d, max_rank_inc = %d, min_hop_rank_inc = %d)",
			 node,
			RPL_IP_TO_STR(dodag->dodag_id),
			 dodag->dio_interval_min,
			 dodag->dio_interval_doublings,
			 dodag->dio_redundancy_constant,
			 dodag->max_rank_inc,
			 dodag->min_hop_rank_inc);

	fnDeleteEvent(rpl->dao_send_eventid);
	if (rpl->joined_dodag->dao_supported)
	{
		NetSim_EVENTDETAILS pevent;
		memset(&pevent, 0, sizeof pevent);
		pevent.dEventTime = pstruEventDetails->dEventTime;
		pevent.nDeviceId = node;
		pevent.nDeviceType = DEVICE_TYPE(node);
		pevent.nEventType = TIMER_EVENT;
		pevent.nProtocolId = NW_PROTOCOL_RPL;
		pevent.nSubEventType = RPL_SEND_DAO;
		rpl->dao_send_eventid = fnpAddEvent(&pevent);
	}

	rpl_trickle_reset(node);
}
