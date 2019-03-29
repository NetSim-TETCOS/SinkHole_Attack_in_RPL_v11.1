/************************************************************************************
* Copyright (C) 2017                                                               *
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
#include "List.h"
#include "IP.h"
#include "PIM_SM.h"
#include "PIM_Msg.h"

static ptrPIM_JOINPRUNE_MSG alloc_pim_joinprune()
{
	ptrPIM_JOINPRUNE_MSG jp = (ptrPIM_JOINPRUNE_MSG)calloc(1, sizeof* jp);
	set_pim_hdr(&jp->hdr, PIMMSG_JoinPrune);

	return jp;
}

static NetSim_PACKET* create_pim_joinprune(NETSIM_ID dev,
										   double time,
										   ptrPIM_GROUP group)
{
	ptrPIM_JOINPRUNE_MSG jp = alloc_pim_joinprune();
	NetSim_PACKET* packet = create_pim_packet(PIMMSG_JoinPrune,
											  jp,
											  time,
											  dev,
											  DEVICE_NWADDRESS(dev, 1),
											  1,
											  &group->RPId,
											  group->RP,
											  MAX_TTL);
	return packet;
}

static ptrPIM_JOINMSG_GROUP pim_join_add_group_member(NETSIM_ID d, 
													  NETSIM_IPAddress groupAddr,
													  ptrPIM_JOINPRUNE_MSG jp,
													  UINT c)
{
	UINT i;
	ptrPIM_JOINMSG_GROUP msg = jp->groups[c];
	if (!msg)
	{
		msg = calloc(1, sizeof* msg);
		jp->groups[c] = msg;
		msg->numJoinedSource = 1;
		msg->joinedSourceAddr = calloc(1, sizeof* msg->joinedSourceAddr);
		i = 0;
		msg->multicastAddr = encode_group_addr(groupAddr);
	}
	else
	{
		msg->joinedSourceAddr = realloc(msg->joinedSourceAddr,
			(msg->numJoinedSource + 1) * sizeof* msg->joinedSourceAddr);
		i = msg->numJoinedSource;
		msg->numJoinedSource++;
	}
	msg->joinedSourceAddr[i] = encode_source_addr(DEVICE_NWADDRESS(d, 1),
												  DEVICE_INTERFACE(d, 1)->szSubnetMask);
	return msg;
}

static ptrPIM_JOINMSG_GROUP jP_find_groups(ptrPIM_JOINPRUNE_MSG jp, NETSIM_IPAddress m, UINT* in)
{
	UINT i;
	for (i = 0; i < jp->numGroups; i++)
	{
		if (!IP_COMPARE(jp->groups[i]->multicastAddr->GroupMulticastAddr, m))
		{
			*in = i;
			return jp->groups[i];
		}
	}
	return NULL;
}

static void pim_join_add_group(NETSIM_ID d,
							   NetSim_PACKET* packet,
							   ptrPIM_GROUP group,
							   ptrPIM_NEIGHBOR neighbor)
{
	ptrPIM_JOINPRUNE_MSG jp = get_PIM_MSG(packet);
	if (!jp)
	{
		jp->numGroups = 1;
		jp->holdTime = (UINT16)(3.5*(GET_PIM_VAR(d)->t_periodic / SECOND));
		jp->unicastAddr = encode_unicast_addr(neighbor->neighborAddr);
		jp->groups = calloc(jp->numGroups, sizeof* jp->groups);
		jp->groups[0] = pim_join_add_group_member(d, group->groupAddress, jp, 0);
	}
	else
	{
		UINT i;
		jp->holdTime = (UINT16)(3.5*(GET_PIM_VAR(d)->t_periodic / SECOND));
		jp->unicastAddr = encode_unicast_addr(neighbor->neighborAddr);
		ptrPIM_JOINMSG_GROUP g = jP_find_groups(jp, group->groupAddress,&i);
		if (!g)
		{
			if (jp->groups)
				jp->groups = realloc(jp->groups, (jp->numGroups + 1) * sizeof* jp->groups);
			else
				jp->groups = calloc(1, sizeof* jp->groups);
			g = jp->groups[jp->numGroups];
			jp->numGroups++;
			i = jp->numGroups - 1;
		}
		jp->groups[i] = pim_join_add_group_member(d, group->groupAddress, jp, i);
	}
}

static ptrPIM_NEIGHBOR pimjoin_find_neighbor(NETSIM_ID d, NETSIM_IPAddress rp)
{
	NETSIM_IPAddress nexthop = pimroute_find_nexthop(d, rp);
	return find_neighbor(d, nexthop);
}

void pim_send_joinprune(NETSIM_ID d, double time,ptrPIM_GROUP group)
{
	ptrPIM_VAR var = GET_PIM_VAR(d);
	NetSim_PACKET* packet = create_pim_joinprune(d, time, group);

	ptrPIM_NEIGHBOR neighbor = pimjoin_find_neighbor(d, group->RP);

	assert(neighbor);

	pim_join_add_group(d, packet, group, neighbor);

	send_pim_msg(d, time, packet);
	print_pim_sm_log("sending PIM_Join msg.");
	print_pim_sm_log("Adding JT timer event at %0.3lf", time + var->t_periodic);
	pim_add_timeout_event(d, time + var->t_periodic, EVENT_PIM_JT, group->groupAddress);
	print_pim_sm_log("\n");
}

static bool validate_RP(NETSIM_ID d, NETSIM_IPAddress rp, NETSIM_IPAddress gaddr)
{
	ptrPIM_GROUP g = pim_find_group(d, gaddr);
	if (!IP_COMPARE(g->RP, rp))
		return true;
	else
		return false;
}

static ptrPIM_JP_STATE get_Pim_jp_state(NETSIM_ID d, NETSIM_ID i, ptrPIM_GROUP gr)
{
	if (!gr->jpState_G)
		gr->jpState_G = (ptrPIM_JP_STATE*)calloc(DEVICE(d)->nNumOfInterface, sizeof* gr->jpState_G);

	if (!gr->jpState_G[i - 1])
		gr->jpState_G[i - 1] = (ptrPIM_JP_STATE)calloc(1, sizeof* gr->jpState_G[i]);

	return gr->jpState_G[i - 1];
}

static bool amIRP(NETSIM_ID d, ptrPIM_GROUP g)
{
	return g->RPId == d;
}

void pim_forward_join()
{
	NETSIM_ID d = pstruEventDetails->nDeviceId;
	NetSim_PACKET* packet = pstruEventDetails->pPacket;
	double time = pstruEventDetails->dEventTime;
	ptrPIM_VAR var = GET_PIM_VAR(d);
	ptrPIM_JOINPRUNE_MSG msg = get_PIM_MSG(packet);
	NETSIM_IPAddress maddr = msg->groups[0]->multicastAddr->GroupMulticastAddr;
	ptrPIM_GROUP g = pim_find_group(d, maddr);

	ptrPIM_NEIGHBOR neighbor = pimjoin_find_neighbor(d, g->RP);
	pim_join_add_group(d, packet, g, neighbor);

	packet->pstruNetworkData->szGatewayIP = NULL;
	packet->pstruNetworkData->szNextHopIp = NULL;
	send_pim_msg(d, time, packet);
	print_pim_sm_log("sending PIM_Join msg.");
	print_pim_sm_log("Adding JT timer event at %0.3lf", time + var->t_periodic);
	pim_add_timeout_event(d, time + var->t_periodic, EVENT_PIM_JT, g->groupAddress);
	print_pim_sm_log("\n");
}

bool pim_process_join()
{
	NETSIM_ID d = pstruEventDetails->nDeviceId;
	NetSim_PACKET* packet = pstruEventDetails->pPacket;
	double time = pstruEventDetails->dEventTime;
	ptrPIM_VAR var = GET_PIM_VAR(d);
	ptrPIM_JOINPRUNE_MSG msg = get_PIM_MSG(packet);
	NETSIM_IPAddress maddr = msg->groups[0]->multicastAddr->GroupMulticastAddr;

	print_pim_sm_log("Received PIM_JOIN msg from %s for group address %s",
					 packet->pstruNetworkData->szGatewayIP->str_ip,
					 maddr->str_ip);
	
	NETSIM_IPAddress msgRP = packet->pstruNetworkData->szDestIP;

	if (!validate_RP(d, msgRP, maddr))
	{
		print_pim_sm_log("RP is not matched for group");
		return true; // RP is not matched for group
	}
	ptrPIM_GROUP g = pim_find_group(d, maddr);

	ptrPIM_JP_STATE state = get_Pim_jp_state(d,
											 pstruEventDetails->nInterfaceId,
											 g);

	if (state->state == JPS_NI)
	{
		state->state = JPS_J;
		state->ET = time + msg->holdTime*SECOND;
		print_pim_sm_log("Adding JT timer event at %0.3lf", state->ET/1000);
		pim_add_timeout_event(d, state->ET, EVENT_PIM_ET, g->groupAddress);
	}
	else
	{
		state->ET = time + msg->holdTime*SECOND;
		print_pim_sm_log("ET timer is updated to %0.3lf", state->ET / 1000);
	}

	pim_add_interface_to_group(d, pstruEventDetails->nInterfaceId, g);

	//pim_route_add(d, pstruEventDetails->nInterfaceId, 330, g->groupAddress);

	if (amIRP(d, g))
	{
#ifdef PRINT_RPT_TREE
		print_RPT_Tree(d, g);
#endif
		return true;
	}
	else
	{
		pim_forward_join();
		return false;
	}
}
