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
#include "IGMP.h"

ptrIGMP_ROUTER_DB find_or_alloc_multicast_db_router(NETSIM_IPAddress addr,
													NETSIM_ID d,
													bool* isAlreadyJoined)
{
	ptrIGMP_ROUTER_DB r = GET_IGMP_ROUTER(d)->database;

	while (r)
	{
		if (!IP_COMPARE(r->group, addr))
		{
			*isAlreadyJoined = true;
			return r;
		}
		r = LIST_NEXT(r);
	}

	*isAlreadyJoined = false;
	r = (ptrIGMP_ROUTER_DB)IGMP_ROUTER_DB_ALLOC();
	r->group = IP_COPY(addr);
	r->state = RouterState_Querier;

	IGMP_ROUTER_DB_ADD(d, r);

	return r;
}

static ptrIGMP_ROUTER_DB router_join_multicast_group(NETSIM_ID d, NETSIM_IPAddress group)
{
	bool isAlreadyJoined = false;
	ptrIGMP_ROUTER router = GET_IGMP_ROUTER(d);
	ptrIGMP_ROUTER_DB db = find_or_alloc_multicast_db_router(group, d, &isAlreadyJoined);
	if (!isAlreadyJoined)
	{
		print_igmp_log("Calling PIM to join group %s", group->str_ip);
		pim_join_group(d, group);
	}
	return db;
}

ptrIGMP_ROUTER_DB router_get_multicast_db(NETSIM_ID d,
										  NETSIM_IPAddress ip)
{
	ptrIGMP_ROUTER_DB db = GET_IGMP_ROUTER(d)->database;
	while (db)
	{
		if (!IP_COMPARE(db->group, ip))
			return db;
		db = LIST_NEXT(db);
	}
	return NULL;
}

static void router_delete_multicast_db(NETSIM_ID d,
										  ptrIGMP_ROUTER_DB db)
{
	LIST_FREE(&GET_IGMP_ROUTER(d)->database, db);
}

static bool isBroadcastInterfacePresent(NETSIM_ID d)
{
	NETSIM_ID i;
	for (i = 0; i < DEVICE(d)->nNumOfInterface; i++)
	{
		if (isBroadcastInterface(d, i + 1))
		{
			return true;
		}
	}
	return false;
}

static bool isInterfacePresentInDatabase(ptrIGMP_ROUTER_DB db,
										 NETSIM_ID ifid)
{
	UINT i;
	for (i = 0; i < db->count; i++)
		if (db->ifids[i] == ifid)
			return true;
	return false;
}

static bool isOtherInterfacePresentInDatabase(ptrIGMP_ROUTER_DB db,
										 NETSIM_ID ifid)
{
	UINT i;
	for (i = 0; i < db->count; i++)
		if (db->ifids[i] != ifid)
			return true;
	return false;
}

static void router_add_ip_route(ptrIGMP_ROUTER_DB db,
								NETSIM_ID d,
								NETSIM_ID ifid)
{	
	if (db->isRouteAlreadyAdded)
	{
		UINT c = db->count;
		db->count++;
		db->ifids = realloc(db->ifids, db->count * sizeof* db->ifids);
		db->ifids[c] = ifid;

		NETSIM_IPAddress* ip = calloc(db->count, sizeof* ip);
		UINT i;
		for (i = 0; i < db->count; i++)
			ip[i] = DEVICE_NWADDRESS(d, db->ifids[i]);

		iptable_change(IP_WRAPPER_GET(d),
					   db->group,
					   STR_TO_IP4("255.255.255.255"),
					   0,
					   db->group,
					   db->count,
					   ip,
					   db->ifids,
					   330);

		free(ip);
	}
	else
	{
		iptable_add(IP_WRAPPER_GET(d),
					db->group,
					STR_TO_IP4("255.255.255.255"),
					0,
					db->group,
					1,
					&DEVICE_NWADDRESS(d, ifid),
					&ifid,
					330,
					"Multicast");
		db->isRouteAlreadyAdded = true;
		db->ifids = (NETSIM_ID*)calloc(1, sizeof* db->ifids);
		db->ifids[0] = ifid;
		db->count = 1;
	}
}

void igmp_router_init(NETSIM_ID d)
{
	ptrIGMP_VAR var = GET_IGMP_VAR(d);

	var->StartupQueryInterval = var->QueryInterval / 4;

	var->StartupQueryCount = var->RobustnessVar;

	if (isBroadcastInterfacePresent(d))
	{
		NETSIM_IPAddress g = STR_TO_IP4("224.0.0.1");
		
		print_igmp_log("\nRouter %d, Time 0.0: Joining multicast group %s.",
					   d,
					   g->str_ip);
		print_igmp_log("Sending query msg after %0.0lf.",(double)IGMP_STARTUP_DELAY);

		router_join_multicast_group(d, g);
		send_query_msg(d, g, IGMP_STARTUP_DELAY);
	}
}

IP_PROTOCOL_ACTION router_is_ip_present_in_db(NETSIM_ID d, NETSIM_IPAddress ip, NetSim_PACKET* packet)
{
	ptrIGMP_ROUTER_DB db = GET_IGMP_ROUTER(d)->database;
	while (db)
	{
		if (!IP_COMPARE(db->group, ip))
		{
			if (!isInterfacePresentInDatabase(db, pstruEventDetails->nInterfaceId))
				return ACTION_DROP;

			if (isOtherInterfacePresentInDatabase(db, pstruEventDetails->nInterfaceId))
				return ACTION_REROUTE;
			else
				return ACTION_DROP;
		}
		db = LIST_NEXT(db);
	}
	return ACTION_DROP;
}

bool router_process_query(NetSim_PACKET* packet, ptrIGMP_MSG msg, NETSIM_ID d)
{
	ptrIGMP_ROUTER r = GET_IGMP_ROUTER(d);

	NETSIM_IPAddress src = packet->pstruNetworkData->szSourceIP;

	if (isIPForSameDevice(src, d))
		return false; // No processing required

	print_igmp_log("\nRouter %d, Time %0.0lf: Query received for group address %s.",
				   d,
				   pstruEventDetails->dEventTime,
				   msg->GroupAddress->str_ip);

	NETSIM_IPAddress same = get_ip_from_same_subnet(d, src);

	if (same->int_ip[0] > src->int_ip[0])
	{
		print_igmp_log("Received from lower ip address %s. Changing state to NonQuerier",
					   src->str_ip);

		ptrIGMP_ROUTER_DB db = router_get_multicast_db(d, msg->GroupAddress);
		db->state = RouterState_NonQuerier;
		db->otherQuerierPresentTime = pstruEventDetails->dEventTime;

		if (!db->isOtherquerierTimerStarted)
		{
			print_igmp_log("Starting Other querier present timer");
			db->isOtherquerierTimerStarted = true;
			start_timer(d,
						EVENT_IGMP_OtherQuerierPresentTimer,
						msg->GroupAddress,
						pstruEventDetails->dEventTime);
		}
	}

	return false;
}

void igmp_router_processOtherQuerierPresentTime()
{
	ptrIGMP_VAR igmp = GET_IGMP_VAR(pstruEventDetails->nDeviceId);
	ptrIGMP_ROUTER_DB db = router_get_multicast_db(pstruEventDetails->nDeviceId,
												   pstruEventDetails->szOtherDetails);

	if (pstruEventDetails->dEventTime >=
		db->otherQuerierPresentTime +
		igmp->QueryPresentInterval*0.1*SECOND)
	{
		// Start as querier
		print_igmp_log("\nRouter %d, Time %0.0lf: Other querier present timer expire for group address %s. Starting as querier.",
					   pstruEventDetails->nDeviceId,
					   pstruEventDetails->dEventTime,
					   db->group->str_ip);

		db->state = RouterState_Querier;
		send_query_msg(pstruEventDetails->nDeviceId,
					   db->group,
					   pstruEventDetails->dEventTime);
	}
	else
	{
		//Keep checking
		print_igmp_log("\nRouter %d, Time %0.0lf: Query is already received for group address %s. Continuing as Non querier.",
					   pstruEventDetails->nDeviceId,
					   pstruEventDetails->dEventTime,
					   db->group->str_ip);

		pstruEventDetails->dEventTime = db->otherQuerierPresentTime +
			igmp->QueryPresentInterval;
		fnpAddEvent(pstruEventDetails);
	}
}

bool router_process_report(NetSim_PACKET* packet,
						   ptrIGMP_MSG msg,
						   NETSIM_ID d)
{
	print_igmp_log("\nRouter %d, Time %0.0lf: Report received for group address %s.",
				   d,
				   pstruEventDetails->dEventTime,
				   msg->GroupAddress->str_ip);

	ptrIGMP_ROUTER_DB r = router_join_multicast_group(d, msg->GroupAddress);

	r->reportRcvTime = pstruEventDetails->dEventTime;

	if (!r->isGroupMembershipTimerStarted)
	{
		print_igmp_log("Router %d, Time %0.0lf: Starting group membership timer for group addr %s",
					   d,
					   pstruEventDetails->dEventTime,
					   msg->GroupAddress->str_ip);
		start_timer(d,
					EVENT_IGMP_GroupMembershipTimer,
					msg->GroupAddress,
					pstruEventDetails->dEventTime);
		r->isGroupMembershipTimerStarted = true;
		print_igmp_log("Starting query msg");
		send_query_msg(d, msg->GroupAddress, pstruEventDetails->dEventTime);
	}
	if(!isInterfacePresentInDatabase(r,pstruEventDetails->nInterfaceId))
		router_add_ip_route(r, d, pstruEventDetails->nInterfaceId);

	return false;
}

void igmp_router_ProcessGroupMembershipTimer()
{
	NETSIM_ID d = pstruEventDetails->nDeviceId;
	NETSIM_IPAddress group = pstruEventDetails->szOtherDetails;

	ptrIGMP_VAR igmp = GET_IGMP_VAR(d);

	ptrIGMP_ROUTER_DB db = router_get_multicast_db(d, group);

	if (pstruEventDetails->dEventTime >=
		db->reportRcvTime +
		igmp->GroupMembershipInterval*0.1*SECOND)
	{
		// No member on this group.
		print_igmp_log("\nRouter %d, Time %0.0lf: Group membership timer expires for group addr %s. Deleting from database.",
					   d,
					   pstruEventDetails->dEventTime,
					   group->str_ip);
		router_delete_multicast_db(d, db);
	}
	else
	{
		//Keep checking
		print_igmp_log("\nRouter %d, Time %0.0lf: Refreshing Group membership timer for group addr %s.",
					   d,
					   pstruEventDetails->dEventTime,
					   group->str_ip);

		pstruEventDetails->dEventTime = db->reportRcvTime +
			igmp->GroupMembershipInterval*0.1*SECOND;
		fnpAddEvent(pstruEventDetails);
	}
}

void router_free(NETSIM_ID d)
{
	ptrIGMP_ROUTER r = GET_IGMP_ROUTER(d);
	ptrIGMP_ROUTER_DB db = r->database;
	while (db)
	{
		LIST_FREE(&db, db);
	}
	free(r);
	SET_IGMP_ROUTER(d, NULL);
}
