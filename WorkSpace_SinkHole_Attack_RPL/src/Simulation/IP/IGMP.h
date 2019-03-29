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
/*
Updated by: 3376                                       PROPOSED STANDARD
Errata Exist
Network Working Group                                            W. Fenner
Request for Comments: 2236                                      Xerox PARC
Updates: 1112                                                November 1997
Category: Standards Track


Internet Group Management Protocol, Version 2
*/
#pragma once

#ifndef _NETSIM_IGMP_H_
#define _NETSIM_IGMP_H_
#ifdef  __cplusplus
extern "C" {
#endif

//SECTION 8:List of timers and default values
#define IGMP_ROBUSTNESS_VARIABLE_DEFAULT		2
#define IGMP_QUERY_INTERVAL_DEFAULT				125 // 1/10 sec
#define IGMP_QUERY_RESPONSE_INTERVAL_DEFAULT	100 // 1/10sec
#define IGMP_GROUP_MEMBERSHIP_INTERVAL_DEFAULT	IGMP_ROBUSTNESS_VARIABLE_DEFAULT*IGMP_QUERY_INTERVAL_DEFAULT +\
												(IGMP_QUERY_RESPONSE_INTERVAL_DEFAULT)
#define IGMP_QUERIER_PRESENT_INTERVAL_DEFAULT	IGMP_ROBUSTNESS_VARIABLE_DEFAULT*IGMP_QUERY_INTERVAL_DEFAULT +\
												(1/2.0*IGMP_QUERY_RESPONSE_INTERVAL_DEFAULT)
#define IGMP_STARTUP_QUERY_INTERVAL_DEFAULT		(1/4.0*IGMP_QUERY_INTERVAL_DEFAULT)
#define IGMP_STARTUP_QUERY_COUNT_DEFAULT		IGMP_ROBUSTNESS_VARIABLE_DEFAULT
#define IGMP_LAST_MEMBER_QUERY_INTERVAL_DEFAULT	10
#define IGMP_LAST_MEMBER_QUERY_COUNT_DEFAULT	IGMP_ROBUSTNESS_VARIABLE_DEFAULT
#define IGMP_UNSOLICITED_REPORT_INTERVAL_DEFAULT (10) //Second

#define IGMP_STARTUP_DELAY	1*MILLISECOND

#define isBroadcastInterface(d,i) (DEVICE_INTERFACE(d,i)->nInterfaceType != INTERFACE_WAN_ROUTER)

	typedef enum
	{
		IP_HOST,
		IP_ROUTER,
	}DEV_TYPE;

	typedef enum
	{
		IGMPMSG_MembershipQuery = 0x11,
		IGMPMSG_V2MembershipReport = 0x16,
		IGMPMSG_LeaveGroup = 0x17,
		IGMPMSG_V1MembershipReport = 0x12,
	}IGMPMSG_TYPE;
#define isIGMPPacket(packet) (packet->nControlDataType / 100 == NW_PROTOCOL_IPV4 && packet->nControlDataType % 100 >= 30 && packet->nControlDataType % 100 < 40)

	/*
	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|      Type     | Max Resp Time |           Checksum            |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                         Group Address                         |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	*/
	typedef struct stru_igmp_msg
	{
		IGMPMSG_TYPE Type;
		UINT8 MaxRespTime;
		UINT16 Checksum;
		NETSIM_IPAddress GroupAddress;
	}IGMP_MSG, *ptrIGMP_MSG;
#define IGMP_HDR_SIZE 8 //Bytes

	typedef enum 
	{
		HostState_NonMember,
		HostState_IdleMember,
		HostState_DelayingMember,
	}IGMP_HOST_STATE;

	typedef struct stru_host_database
	{
		NETSIM_IPAddress group;
		IGMP_HOST_STATE state;
		UINT8 maxResponseTime;
		double queryRecvTime;
		double delayTime;
		bool isReportreqd;
		UINT reportSentCount;
		_ele* ele;
}IGMP_HOST_DB, *ptrIGMP_HOST_DB;
#define IGMP_HOST_DB_ALLOC() (ptrIGMP_HOST_DB)list_alloc(sizeof(IGMP_HOST_DB),offsetof(IGMP_HOST_DB,ele))
#define IGMP_HOST_DB_ADD(d,db) LIST_ADD_LAST((void**)&GET_IGMP_HOST(d)->database,db)

	typedef struct stru_igmp_host
	{
		ptrIGMP_HOST_DB database;
	}IGMP_HOST, *ptrIGMP_HOST;

	typedef enum
	{
		RouterState_Querier,
		RouterState_NonQuerier,
	}IGMP_ROUTER_STATE;

	typedef struct stru_router_database
	{
		NETSIM_IPAddress group;
		IGMP_ROUTER_STATE state;

		bool isOtherquerierTimerStarted;
		double otherQuerierPresentTime;

		UINT sentCount;
		
		bool isGroupMembershipTimerStarted;
		double reportRcvTime;

		bool isRouteAlreadyAdded;
		NETSIM_ID* ifids;
		UINT count;
		_ele* ele;
	}IGMP_ROUTER_DB, *ptrIGMP_ROUTER_DB;
#define IGMP_ROUTER_DB_ALLOC() (ptrIGMP_ROUTER_DB)list_alloc(sizeof(IGMP_ROUTER_DB),offsetof(IGMP_ROUTER_DB,ele))
#define IGMP_ROUTER_DB_ADD(d,db) LIST_ADD_LAST((void**)&GET_IGMP_ROUTER(d)->database,db)

	typedef struct stru_igmp_router
	{
		UINT startup_query_sent_count;
		ptrIGMP_ROUTER_DB database;
	}IGMP_ROUTER, *ptrIGMP_ROUTER;

	typedef struct stru_igmpvar
	{
		DEV_TYPE devType;
		union
		{
			ptrIGMP_ROUTER router;
			ptrIGMP_HOST host;
		}DEV;

		//Config parameter for host only
		double UnsolicitedReportInterval;

		//Config parameter for router only
		UINT QueryResponseInterval;
		UINT StartupQueryInterval;
		UINT StartupQueryCount;

		//Config parameter
		UINT QueryInterval;
		UINT RobustnessVar;
		double GroupMembershipInterval;
		UINT QueryPresentInterval;
		double lastMemQueryInterval;
		UINT lastMemQueryCount;


	}IGMP_VAR, *ptrIGMP_VAR;
#define GET_IGMP_VAR(d) ((ptrIGMP_VAR)GET_IP_DEVVAR(d)->igmp)
#define SET_IGMP_VAR(d,var) (GET_IP_DEVVAR(d)->igmp = (void*)var)
#define isIPHOST(d) (GET_IGMP_VAR(d)->devType == IP_HOST)
#define isIPRouter(d) (GET_IGMP_VAR(d)->devType == IP_ROUTER)
#define GET_IGMP_HOST(d) ((ptrIGMP_HOST)(GET_IGMP_VAR(d)->DEV.host))
#define GET_IGMP_ROUTER(d) ((ptrIGMP_ROUTER)(GET_IGMP_VAR(d)->DEV.router))
#define SET_IGMP_HOST(d,var) (GET_IGMP_VAR(d)->DEV.host = var)
#define SET_IGMP_ROUTER(d,var) (GET_IGMP_VAR(d)->DEV.router = var)

	//Function used by IGMP module only
	//IGMP Router
	void igmp_router_init(NETSIM_ID d);
	ptrIGMP_ROUTER_DB find_or_alloc_multicast_db_router(NETSIM_IPAddress addr,
														NETSIM_ID d,
														bool* isAlreadyJoined);
	ptrIGMP_ROUTER_DB router_get_multicast_db(NETSIM_ID d,
											  NETSIM_IPAddress ip);
	bool router_process_report(NetSim_PACKET* packet,
							   ptrIGMP_MSG msg,
							   NETSIM_ID d);
	bool router_process_query(NetSim_PACKET* packet, ptrIGMP_MSG msg, NETSIM_ID d);
	void router_free(NETSIM_ID d);


	//IGMP Host
	void igmp_host_init(NETSIM_ID d);
	ptrIGMP_HOST_DB host_get_multicast_db(NETSIM_ID d, NETSIM_IPAddress addr);
	bool host_process_report(NetSim_PACKET* packet,
							 ptrIGMP_MSG msg,
							 NETSIM_ID d);
	bool host_process_query(NetSim_PACKET* packet,
							ptrIGMP_MSG msg,
							NETSIM_ID d);
	void host_free(NETSIM_ID d);

	//IGMP MSG
	void send_membership_report(NETSIM_ID d, NETSIM_IPAddress group);

	//IGMP
	void print_igmp_log(char* format, ...);
	void start_timer(NETSIM_ID d,
					 IP_SUBEVENT sev,
					 NETSIM_IPAddress addr,
					 double time);

#ifdef  __cplusplus
}
#endif
#endif

