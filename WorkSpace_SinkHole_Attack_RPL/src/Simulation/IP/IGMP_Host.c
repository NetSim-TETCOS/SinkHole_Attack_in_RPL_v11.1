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

static ptrIGMP_HOST_DB find_or_alloc_multicast_db_host(NETSIM_ID d, NETSIM_IPAddress group)
{
	ptrIGMP_HOST_DB r = GET_IGMP_HOST(d)->database;

	while (r)
	{
		if (!IP_COMPARE(r->group, group))
			return r;
		r = LIST_NEXT(r);
	}

	r = (ptrIGMP_HOST_DB)IGMP_HOST_DB_ALLOC();
	r->group = IP_COPY(group);
	r->state = HostState_IdleMember;

	IGMP_HOST_DB_ADD(d, r);

	return r;
}

static void host_join_multicast_group(NETSIM_ID d, NETSIM_IPAddress group)
{
	find_or_alloc_multicast_db_host(d, group);
}

ptrIGMP_HOST_DB host_get_multicast_db(NETSIM_ID d, NETSIM_IPAddress addr)
{
	ptrIGMP_HOST_DB r = GET_IGMP_HOST(d)->database;

	while (r)
	{
		if (!IP_COMPARE(r->group, addr))
			return r;
		r = LIST_NEXT(r);
	}
	return NULL;
}

void igmp_host_init(NETSIM_ID d)
{
	ptrIGMP_HOST host = GET_IGMP_HOST(d);

	print_igmp_log("\nHost %d, Time 0: joining multicast group %s.",
				   d,
				   "224.0.0.1");

	host_join_multicast_group(d, STR_TO_IP4("224.0.0.1"));
}

IP_PROTOCOL_ACTION host_is_ip_present_in_db(NETSIM_ID d, NETSIM_IPAddress ip, NetSim_PACKET* packet)
{
	IP_DEVVAR* dip = GET_IP_DEVVAR(d);
	ptrIGMP_HOST_DB db = dip->isIGMPConfigured ? GET_IGMP_HOST(d)->database : NULL;
	while (db)
	{
		if (!IP_COMPARE(db->group, ip))
			return ACTION_MOVEUP;
		db = LIST_NEXT(db);
	}
	return ACTION_DROP;
}

bool host_process_query(NetSim_PACKET* packet,
						ptrIGMP_MSG msg,
						NETSIM_ID d)
{
	bool isTimerReqd = false;
	ptrIGMP_HOST_DB db = host_get_multicast_db(d, msg->GroupAddress);

	print_igmp_log("\nHost %d, Time %0.0lf: Query received for group address %s.",
				   d,
				   pstruEventDetails->dEventTime,
				   msg->GroupAddress->str_ip);

	if (!db->isReportreqd ||
		pstruEventDetails->dEventTime -
		db->queryRecvTime - 
		db->delayTime >=
		msg->MaxRespTime*0.1*SECOND)
		isTimerReqd = true;

	db->maxResponseTime = msg->MaxRespTime;
	db->queryRecvTime = pstruEventDetails->dEventTime;

	if (isTimerReqd)
	{
		print_igmp_log("Starting Delay timer.");
		start_timer(d,
					EVENT_IGMP_DelayTimer,
					msg->GroupAddress,
					pstruEventDetails->dEventTime);
		db->isReportreqd = true;
		print_igmp_log("Changing host state to delaying member");
		db->state = HostState_DelayingMember;
	}

	return false;
}

void host_send_report()
{
	NETSIM_IPAddress g = pstruEventDetails->szOtherDetails;
	ptrIGMP_HOST_DB db = host_get_multicast_db(pstruEventDetails->nDeviceId,
											   g);

	if (db->isReportreqd)
	{
		print_igmp_log("\nHost %d, Time %0.0lf: Sending report for group address %s.",
					   pstruEventDetails->nDeviceId,
					   pstruEventDetails->dEventTime,
					   g->str_ip);

		send_membership_report(pstruEventDetails->nDeviceId,
							   g);
		db->isReportreqd = false;
		print_igmp_log("Changing host state to idle member");
		db->state = HostState_IdleMember;
	}
}

bool host_process_report(NetSim_PACKET* packet,
						 ptrIGMP_MSG msg,
						 NETSIM_ID d)
{
	ptrIGMP_HOST_DB db = host_get_multicast_db(d, msg->GroupAddress);
	if (db)
	{
		print_igmp_log("\nHost %d, Time %0.0lf: report received for group address %s.",
					   d,
					   pstruEventDetails->dEventTime,
					   msg->GroupAddress->str_ip);
		print_igmp_log("Report is not required.");
		db->isReportreqd = false;
		print_igmp_log("Changing host state to Idle member");
		db->state = HostState_IdleMember;
	}
	return false;
}

void igmp_host_join_group(NETSIM_ID d, NETSIM_IPAddress group)
{
	if (!isHost(d))
		fnNetSimError("%s is called for Non-Host device %d.\n", __FUNCTION__, d);

	print_igmp_log("\nHost %d, Time %0.0lf: Joining multicast group %s.",
				   d,
				   pstruEventDetails->dEventTime,
				   group->str_ip);
	print_igmp_log("Sending membership report.");

	ptrIGMP_HOST_DB db = find_or_alloc_multicast_db_host(d, group);

	send_membership_report(d, group);
	db->reportSentCount++;
	print_igmp_log("Changing host state to delaying member");
	db->state = HostState_DelayingMember;
	print_igmp_log("Starting Unsolicited report timer");
	start_timer(d,
				EVENT_IGMP_Unsolicited_report,
				group,
				pstruEventDetails->dEventTime);
}

void host_handle_unsolicited_report_timer()
{
	NETSIM_ID d = pstruEventDetails->nDeviceId;
	NETSIM_IPAddress group = pstruEventDetails->szOtherDetails;

	ptrIGMP_HOST_DB db = find_or_alloc_multicast_db_host(d, group);

	if (db->reportSentCount < 2 && db->isReportreqd)
	{
		print_igmp_log("\nHost %d, Time %0.0lf: Unsolicited report timer triggered. Sending membership report.");
		send_membership_report(d, group);
		db->reportSentCount++;
		print_igmp_log("Changing host state to delaying member");
		db->state = HostState_DelayingMember;
		print_igmp_log("Starting Unsolicited report timer");
		start_timer(d,
					EVENT_IGMP_Unsolicited_report,
					group,
					pstruEventDetails->dEventTime);
	}
}

void host_free(NETSIM_ID d)
{
	ptrIGMP_HOST h = GET_IGMP_HOST(d);
	ptrIGMP_HOST_DB db = h->database;
	while (db)
	{
		LIST_FREE(&db, db);
	}
	free(h);
	SET_IGMP_HOST(d, NULL);
}
