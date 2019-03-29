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

static void set_trickle_t_time(PRPL_NODE r)
{
	r->trickle.t = ((UINT)NETSIM_RAND() % ((UINT)(r->trickle.I / 2))) + r->trickle.I / 2;
}

void rpl_trickle_reset(NETSIM_ID ndevId)
{
	NetSim_EVENTDETAILS pevent;
	PRPL_NODE r = GET_RPL_NODE(ndevId);

#ifdef DEBUG_RPL_TRICKLE
	print_rpl_log("node '%d',Time '%0.3lf ms': resetting trickle timer", ndevId,pstruEventDetails->dEventTime/1000);
#endif

	if (rpl_node_is_root(r))
	{
		r->trickle.Imin = pow(2, r->root_info->dio_interval_min)*MILLISECOND;
		r->trickle.Imax = r->root_info->dio_interval_doublings;
		r->trickle.k = r->root_info->dio_redundancy_constant;
	}
	else if (rpl_node_is_joined(r) || rpl_node_is_poisoning(r))
	{
		r->trickle.Imin = pow(2, r->joined_dodag->dio_interval_min)*MILLISECOND;
		r->trickle.Imax = r->joined_dodag->dio_interval_doublings;
		r->trickle.k = r->joined_dodag->dio_redundancy_constant;
	}
	else
	{
		return; /* no trickle timer in isolated state */
	}

	r->trickle.I = r->trickle.Imin;

	set_trickle_t_time(r);

	//Delete the old trickle event
	fnDeleteEvent(r->trickle.trickle_i_eventid);
	fnDeleteEvent(r->trickle.trickle_t_eventid);

	memset(&pevent, 0, sizeof pevent);

	//Schedule the Trickle_t time out event
	r->trickle.last_trickle_t_schedule_time = ldEventTime + r->trickle.t;
	pevent.dEventTime = r->trickle.last_trickle_t_schedule_time;
	pevent.nDeviceId = ndevId;
	pevent.nDeviceType = DEVICE_TYPE(ndevId);
	pevent.nEventType = TIMER_EVENT;
	pevent.nProtocolId = NW_PROTOCOL_RPL;
	pevent.nSubEventType = RPL_TRICKLE_T_TIMEOUT;
	r->trickle.trickle_t_eventid = fnpAddEvent(&pevent);

	//Schedule the Trickle_i time out event
	r->trickle.last_trickle_i_schedule_time = ldEventTime + r->trickle.I;
	pevent.dEventTime = r->trickle.last_trickle_i_schedule_time;
	pevent.nSubEventType = RPL_TRICKLE_I_TIMEOUT;
	r->trickle.trickle_i_eventid = fnpAddEvent(&pevent);
}

void rpl_trickle_handle_t_timeout()
{
	PRPL_NODE r = GET_RPL_NODE(pstruEventDetails->nDeviceId);

	NetSim_PACKET *dio_pdu = create_current_dio_message(pstruEventDetails->nDeviceId, pstruEventDetails->dEventTime, TRUE);
	
	if (dio_pdu != NULL)
		rpl_node_send_msg(pstruEventDetails->nDeviceId, dio_pdu);
}

void rpl_trickle_handle_i_timeout()
{
	PRPL_NODE rpl = GET_RPL_NODE(pstruEventDetails->nDeviceId);

	if (rpl_node_is_root(rpl))
	{
		if (rpl->trickle.C < rpl->trickle.Imax)
		{
			rpl->trickle.C++;
			rpl->trickle.I *= 2;
		}
	}
	else if (rpl_node_is_joined(rpl))
	{
		if (rpl->trickle.C < rpl->trickle.Imax)
		{
			rpl->trickle.C++;
			rpl->trickle.I *= 2;
		}
	}
	else if (rpl_node_is_poisoning(rpl))
	{
		if (rpl->poison_count_so_far < RPL_DEFAULT_POISON_COUNT)
		{
			rpl->poison_count_so_far++;
		}
		else
		{ /* enough with poisoning */
			bool same;
			PRPL_CTRL_MSG preferred_dodag_pdu = get_preferred_dodag_dio_pdu(pstruEventDetails->nDeviceId,
																			 &same,
																			 pstruEventDetails->dEventTime);

			if (preferred_dodag_pdu != NULL)
			{
				join_dodag_iteration(pstruEventDetails->nDeviceId, preferred_dodag_pdu);
				choose_parents_and_siblings(pstruEventDetails->nDeviceId);
			}
			else 
			{
				start_as_root(pstruEventDetails->nDeviceId);
			}

			return;
		}
	}
	else
	{
		fnNetSimError("Unknown node status for node %s in rpl\n", pstruEventDetails->nDeviceId);
		return; /* this should never happen */
	}

	set_trickle_t_time(rpl);

#ifdef DEBUG_RPL_TRICKLE
	print_rpl_log("node '%d': trickle time is generated at t=%0.3lf, i=%0.2lf",
				  pstruEventDetails->nDeviceId,
				  (ldEventTime + rpl->trickle.t) / 1000,
				  (ldEventTime + rpl->trickle.I) / 1000);
#endif

	NetSim_EVENTDETAILS pevent;

	memset(&pevent, 0, sizeof pevent);

	//Schedule the Trickle_t time out event
	rpl->trickle.last_trickle_t_schedule_time = ldEventTime + rpl->trickle.t;
	pevent.dEventTime = rpl->trickle.last_trickle_t_schedule_time;
	pevent.nDeviceId = pstruEventDetails->nDeviceId;
	pevent.nDeviceType = pstruEventDetails->nDeviceType;
	pevent.nEventType = TIMER_EVENT;
	pevent.nProtocolId = NW_PROTOCOL_RPL;
	pevent.nSubEventType = RPL_TRICKLE_T_TIMEOUT;
	rpl->trickle.trickle_t_eventid = fnpAddEvent(&pevent);

	//Schedule the Trickle_i time out event
	rpl->trickle.last_trickle_i_schedule_time = ldEventTime + rpl->trickle.I;
	pevent.dEventTime = rpl->trickle.last_trickle_i_schedule_time;
	pevent.nSubEventType = RPL_TRICKLE_I_TIMEOUT;
	rpl->trickle.trickle_i_eventid = fnpAddEvent(&pevent);
}
