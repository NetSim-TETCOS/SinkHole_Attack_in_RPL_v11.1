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
#include "../IP/IP.h"
#include "RPL_enum.h"

static double compute_dao_delay(NETSIM_ID d)
{
	PRPL_NODE rpl = GET_RPL_NODE(d);

	if (rpl_node_is_joined(rpl))
	{
		double min_time = rpl->DAODelayTime / 100;
		double max_time = rpl->DAODelayTime;

		UINT16 min_rank = RPL_RANK_ROOT;
		UINT16 max_rank = INFINITE_RANK;

		UINT16 rank = rpl->joined_dodag->rank;
		double delay = max_time + min_time - ((rank - min_rank) * (max_time - min_time) / (max_rank - min_rank) + min_time);

		return delay;
	}
	else 
	{
		return rpl->DAODelayTime;
	}
}

void rpl_send_dao()
{
	NETSIM_ID d = pstruEventDetails->nDeviceId;
	PRPL_NODE rpl = GET_RPL_NODE(d);

	if (!rpl_node_is_joined(rpl) || !rpl->joined_dodag->dao_supported)
	{
		print_rpl_log("node '%d': canceled DAO mechanism", d);
		return;
	}
	NetSim_PACKET* dao_pdu = create_dao_message(d,
												pstruEventDetails->dEventTime,
												rpl->joined_dodag->pref_parent->nodeId);

	/* for every DAO unicast route send a DAO message to the preferred parent */
	UINT i, route_count;
	ptrIP_ROUTINGTABLE* route_list = iptable_get_table_by_type(IP_TABLE_GET(d), "RPL_DAO", &route_count);

	for (i = 0; i < route_count; i++)
	{
		ptrIP_ROUTINGTABLE route = route_list[i];
		create_and_add_rpl_target_option(dao_pdu,
										 route->prefix_len,
										 route->networkDestination);
	}

	if (route_list != NULL)
		free(route_list);

	/* send a DAO message for ourselves */
	create_and_add_rpl_target_option(dao_pdu,
									 128,
									 DEVICE_NWADDRESS(d,1));
	rpl_node_send_msg(d, dao_pdu);

	/* reschedule the "Delay DAO timer" */
	NetSim_EVENTDETAILS pevent;
	memset(&pevent, 0, sizeof pevent);
	pevent.dEventTime = pstruEventDetails->dEventTime + compute_dao_delay(d);
	pevent.nDeviceId = d;
	pevent.nDeviceType = DEVICE_TYPE(d);
	pevent.nEventType = TIMER_EVENT;
	pevent.nProtocolId = NW_PROTOCOL_RPL;
	pevent.nSubEventType = RPL_SEND_DAO;
	fnpAddEvent(&pevent);
}

static ptrIP_ROUTINGTABLE check_is_route_is_present(PRPL_TARGET_OPTION target,
												  ptrIP_ROUTINGTABLE* route_list,
												  UINT route_count)
{
	UINT i;
	for (i = 0; i < route_count; i++)
	{
		if (!IP_COMPARE(target->Traget_Prefix, route_list[i]->networkDestination)
			&& target->Prefix_Length == route_list[i]->prefix_len)
			return route_list[i];
	}
	return NULL;
}

void rpl_process_dao_msg()
{
	NETSIM_ID d = pstruEventDetails->nDeviceId;
	PRPL_CTRL_MSG daoPdu = GET_PRPL_CTRL_MSG(pstruEventDetails->pPacket);
	PRPL_NODE drpl = GET_RPL_NODE(d);
	PRPL_DIO_BASE daobase = daoPdu->Base;
	NETSIM_IPAddress gateway = IP_COPY(pstruEventDetails->pPacket->pstruNetworkData->szSourceIP);
	UINT target_count;
	PRPL_TARGET_OPTION* target = (PRPL_TARGET_OPTION*)get_all_option_from_msg(daoPdu,RPLOPTION_RPLTARGET,&target_count);

	bool* ispresent;
	ispresent = (bool*)calloc(target_count, sizeof* ispresent);

	/* check if the route already exists */
	UINT i, route_count;
	ptrIP_ROUTINGTABLE* route_list = iptable_get_table_by_type(IP_TABLE_GET(d), "RPL_DAO", &route_count);

	for (i = 0; i < target_count; i++)
	{
		/* mark routes as updated, if they exist */
		ptrIP_ROUTINGTABLE route;
		route = check_is_route_is_present(target[i], route_list, route_count);
		if (route)
		{
			ispresent[i] = true;
			route->update_time = pstruEventDetails->dEventTime;
#ifdef DEBUG_RPL_PRINT_DAO_ROUTE_INFOMATION
			print_rpl_log("Node '%d',%0.3lfms: received dao msg with old route information. dest = %s, gateway=%s.",
						  d,
						  pstruEventDetails->dEventTime/1000,
						  RPL_IP_TO_STR(target[i]->Traget_Prefix),
						  RPL_IP_TO_STR(route->gateway));
#endif
		}
	}

	if (route_list != NULL)
		free(route_list);
	
	for (i = 0; i < target_count; i++)
	{
		if (!ispresent[i])
		{ /* the route doesn't exist */
#ifdef DEBUG_RPL_PRINT_DAO_ROUTE_INFOMATION
			print_rpl_log("Node '%d',%0.3lfms: received dao msg with new route information. dest = %s, gateway= %s.",
						  d,
						  pstruEventDetails->dEventTime/1000,
						  RPL_IP_TO_STR(target[i]->Traget_Prefix),
						  RPL_IP_TO_STR(gateway));
#endif
			NETSIM_ID inetrfaceId = 1;
			ptrIP_ROUTINGTABLE route = iptable_add(IP_WRAPPER_GET(d),
												 target[i]->Traget_Prefix,
												 NULL,
												 target[i]->Prefix_Length,
												 gateway,
												 1,
												 &DEVICE_NWADDRESS(d, 1),
												 &inetrfaceId,
												 1,
												 "RPL_DAO");
			route->update_time = pstruEventDetails->dEventTime;

			/* schedule a timeout to remove this route */
			NetSim_EVENTDETAILS pevent;
			memset(&pevent, 0, sizeof pevent);
			pevent.dEventTime = pstruEventDetails->dEventTime + RPL_DEFAULT_DAO_REMOVE_TIMEOUT;
			pevent.nDeviceId = d;
			pevent.nDeviceType = DEVICE_TYPE(d);
			pevent.nEventType = TIMER_EVENT;
			pevent.nProtocolId = NW_PROTOCOL_RPL;
			pevent.nSubEventType = RPL_DAO_ROUTE_TIMEOUT;
			fnpAddEvent(&pevent);
		}
	}
	free(target);
	free(ispresent);
}

void rpl_dao_route_timeout()
{
	double time = pstruEventDetails->dEventTime;
	NETSIM_ID d = pstruEventDetails->nDeviceId;
	UINT i, route_count;
	double minupdatetime = 0xFFFFFFFFFFFF;
	ptrIP_ROUTINGTABLE* route_list = iptable_get_table_by_type(IP_TABLE_GET(d), "RPL_DAO", &route_count);
	for (i = 0; i < route_count; i++)
	{
		ptrIP_ROUTINGTABLE route = route_list[i];
		if (route->update_time + RPL_DEFAULT_DAO_REMOVE_TIMEOUT <= time)
		{
#ifdef DEBUG_RPL_PRINT_DAO_ROUTE_INFOMATION
			print_rpl_log("Node '%d',%0.3lfms: Route %s, prefix %d is expired.",
						  d,
						  time/1000,
						  RPL_IP_TO_STR(route->networkDestination),
						  route->prefix_len);
#endif
			//Delete the old route
			iptable_delete_by_route(IP_WRAPPER_GET(d), route);
		}
		else
		{
			minupdatetime = min(minupdatetime, route->update_time);
		}
	}
	//Add the route time out event
	pstruEventDetails->dEventTime = minupdatetime + RPL_DEFAULT_DAO_REMOVE_TIMEOUT;
	fnpAddEvent(pstruEventDetails);

	if (route_list)
		free(route_list);
}

void rpl_dao_msg_destroy(NetSim_PACKET* packet)
{
	PRPL_CTRL_MSG rpl = packet->pstruNetworkData->Packet_RoutingProtocol;
	PRPL_DAO_BASE b = rpl->Base;

	free(b);

	UINT i;
	for (i = 0; i < rpl->option_count; i++)
		rpl_option_destroy(rpl->options[i]);

	free(rpl);
}

void rpl_dao_msg_copy(const NetSim_PACKET* destPacket, const NetSim_PACKET* srcPacket)
{
	PRPL_CTRL_MSG srpl = srcPacket->pstruNetworkData->Packet_RoutingProtocol;
	PRPL_CTRL_MSG drpl = (PRPL_CTRL_MSG)calloc(1, sizeof* drpl);
	memcpy(drpl, srpl, sizeof* drpl);
	destPacket->pstruNetworkData->Packet_RoutingProtocol = drpl;

	PRPL_DAO_BASE b = srpl->Base;
	PRPL_DAO_BASE db = (PRPL_DAO_BASE)calloc(1, sizeof* db);
	memcpy(db, b, sizeof* db);
	drpl->Base = db;

	UINT i;
	drpl->options = (PRPL_OPTION*)calloc(drpl->option_count, sizeof* drpl->options);
	for (i = 0; i < srpl->option_count; i++)
		drpl->options[i] = rpl_option_copy(srpl->options[i]);
}
