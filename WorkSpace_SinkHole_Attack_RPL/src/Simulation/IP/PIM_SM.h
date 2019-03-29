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
Internet Engineering Task Force (IETF)
Request for Comments: 7761
STD: 83                  
Obsoletes: 4601          
Category: Standards Track
ISSN: 2070-1721

Protocol Independent Multicast - Sparse Mode (PIM-SM):
Protocol Specification (Revised)

*/
#pragma once
#ifndef _NETSIM_PIM_SM_H_
#define _NETSIM_PIM_SM_H_
#ifdef  __cplusplus
extern "C" {
#endif

//#define PRINT_RPT_TREE

#define time_interval						UINT16	// In millisecond
#define Propagation_delay_default			500		// millisecond
#define t_override_default					2500	// millisecond

	//Config parameter
#define PIM_HELLO_PERIOD_DEFAULT			30	//Second
#define PIM_TRIGGERED_HELLO_DELAY_DEFAULT	5	//Second
#define PIM_DR_PRIORITY_DEFAULT				1
#define PIM_PROPAGATION_DELAY_DEFAULT		Propagation_delay_default
#define PIM_OVERRIDE_INTERVAL_DEFAULT		t_override_default
#define PIM_T_PERIODIC_DEFAULT				60	//Second

	//Const
	NETSIM_IPAddress ALL_PIM_ROUTERS_ADDRESS;

	typedef enum
	{
		DISABLE,
		ENABLE,
	}EN_DIS;

	typedef enum
	{
		LMS_NoInfo,
		LMS_Include,
		LMS_Exclude,
	}LMS;

	typedef enum
	{
		JPS_NI, // NoInfo
		JPS_J,	// Join
		JPS_PP,	// Prune-pending
		JPS_P,	// Prune
		JPS_JP,	// Join-Pending
	}JPS;

	typedef enum
	{
		AWS_NI,	// NoInfo
		AWS_L,	// I lost assert
		AWS_W,	// I Won assert
	}AWS;

	typedef enum
	{
		UJPS_NotJoined,
		UJPS_Joined,
		UJPS_NotPruned,
		UJPS_Pruned,
	}UJPS;

	typedef struct stru_pim_neighbor_state
	{
		NETSIM_IPAddress address;
		
		void* infoNeighHello;
		UINT neighGenId;
		double NLT;
	}PIM_NEIGH_STATE,*ptrPIM_NEIGH_STATE;

	typedef struct stru_pim_state
	{
		NETSIM_ID interfaceId;
		NETSIM_ID groupId;
		NETSIM_IPAddress groupAddress;
		NETSIM_ID sourceId;
		NETSIM_IPAddress sourceAddress;
		NETSIM_ID rptId;

		//General purpose state -- For each Interface
		double effOverrideInterval;
		double effProppagationDelay;
		EN_DIS suppressionState;
		ptrPIM_NEIGH_STATE* neighState;
		struct stru_DR_state
		{
			NETSIM_IPAddress DRIPaddress;
			UINT DRPriority;
		}DR_STATE;

		//(*,G) State -- For each interface
		LMS LMSState;
		JPS JPSState;
		double PPT; // Prune-pending timer
		double ET;	// Join/Prune expiry timer
		AWS AWSState;
		double AT;	// Assert Timer
		NETSIM_IPAddress assertWinner;	// Assert winner IP address
		UINT assertWinnerMetric;		// Assert winner assert metric

		//(*,G) state -- For not interface specific
		UJPS UJPSState;
		double JT; // Upstream join/prune timer
		UINT lastRPUsed;
		UINT lastRPFNeigh;

		//(S,G) state -- For each interface
		//same as (*,G) state
		
		//(S,G) State -- For not interface specific. Extra from (*,G) state
		bool sptBit;
		double KAT; // (S,G) keep alive timer
		JPS registerState;
		double RST; //Register-stop timer

		//(S,G,RPT) state -- Extra from above
		double OT; // Override timer

		_ele* ele;
	}PIM_STATE,*ptrPIM_STATE;
#define PIM_STATE_ALLOC() (ptrPIM_STATE)list_alloc(sizeof(PIM_STATE),offsetof(PIM_STATE,ele))
#define PIM_STATE_NEXT(state) state = (ptrPIM_STATE)LIST_NEXT(state)
#define PIM_STATE_ADD(l,m) LIST_ADD_LAST((void**)l,m)

	typedef struct stru_pim_JP_state
	{
		JPS state;
		double PPT;
		double ET;
	}PIM_JP_STATE, *ptrPIM_JP_STATE;

	typedef struct stru_pim_neighbor
	{
		NETSIM_ID neighborId;
		NETSIM_IPAddress neighborAddr;
		NETSIM_ID incomingInterface;
		UINT gen_id;
		UINT16 dr_priority;
		bool dr_priority_present;
		bool isTimeoutAdded;
		double timeout;

		bool lan_prune_delay_present;
		bool tracking_support;
		UINT16 propagation_delay;	//In millisecond
		UINT16 override_interval;	//In millisecond

		UINT secondary_address_count;
		NETSIM_IPAddress* secondary_address_list;

		_ele* ele;
	}PIM_NEIGHBOR, *ptrPIM_NEIGHBOR;
#define PIM_NEIGHBOR_ALLOC() (ptrPIM_NEIGHBOR)list_alloc(sizeof(PIM_NEIGHBOR),offsetof(PIM_NEIGHBOR,ele))
#define PIM_NEIGHBOR_NEXT(neigh) neigh = (ptrPIM_NEIGHBOR)LIST_NEXT(neigh)
#define PIM_NEIGHBOR_ADD(l,m) LIST_ADD_LAST((void**)l,m)

	typedef struct stru_pim_group
	{
		NETSIM_ID groupId;
		NETSIM_IPAddress groupAddress;
		NETSIM_IPAddress RP;
		NETSIM_ID RPId;

		//(*,G) State
		ptrPIM_JP_STATE* jpState_G;

		//Forward Interface
		UINT count;
		NETSIM_ID* ifid;

		_ele* ele;
	}PIM_GROUP, *ptrPIM_GROUP;
#define PIM_GROUP_ALLOC() (ptrPIM_GROUP)list_alloc(sizeof(PIM_GROUP),offsetof(PIM_GROUP,ele))
#define PIM_GROUP_NEXT(gr) gr = (ptrPIM_GROUP)LIST_NEXT(gr)
#define PIM_GROUP_ADD(l,m) LIST_ADD_LAST((void**)l,m)


	typedef struct stru_pim_var
	{
		UINT interfaceCount;
		
		UINT neighCount;
		ptrPIM_NEIGHBOR neighborList;
		NETSIM_IPAddress* DR;

		UINT groupCount;
		ptrPIM_GROUP groupList;

		ptrPIM_STATE pimState;

		UINT genId;

		//Config parameter
		double helloPeriod;
		double triggeredHelloDelay;
		double t_periodic;
		UINT DRPriority;
		UINT16 propagationDelay;
		UINT16 overrideInterval;
	}PIM_VAR, *ptrPIM_VAR;
#define GET_PIM_VAR(d) ((ptrPIM_VAR)(GET_IP_DEVVAR(d)->pim))
#define SET_PIM_VAR(d,var) (GET_IP_DEVVAR(d)->pim = (void*)var)

	//Function prototype
	void pim_add_timeout_event(NETSIM_ID d,
							   double time,
							   IP_SUBEVENT eve,
							   NETSIM_IPAddress groupAddress);
	void configure_PIM();

	//PIM Route
	void pim_route_add(NETSIM_ID d,
					   NETSIM_ID i,
					   UINT metric,
					   NETSIM_IPAddress dest);
	NETSIM_IPAddress pimroute_find_nexthop(NETSIM_ID d, NETSIM_IPAddress dest);
	int pim_route_msg();

	//PIM Neighbor
	ptrPIM_NEIGHBOR find_neighbor(NETSIM_ID d, NETSIM_IPAddress ip);
	ptrPIM_NEIGHBOR create_and_add_neighbor(NETSIM_ID d,
											NETSIM_ID ifId,
											NETSIM_IPAddress address);
	void elect_DR(NETSIM_ID d, NETSIM_ID ifid);

	//PIM Group
	ptrPIM_GROUP create_group(NETSIM_ID d, NETSIM_IPAddress addr, NETSIM_IPAddress RP);
	ptrPIM_GROUP pim_find_group(NETSIM_ID d, NETSIM_IPAddress addr);
	void pim_add_interface_to_group(NETSIM_ID d, NETSIM_ID i, ptrPIM_GROUP g);

	//PIM MSG
	void send_hello_msg(NETSIM_ID d, double time);
	bool process_pim_hello_packet();

	//PIM Join
	void pim_send_joinprune(NETSIM_ID d, double time, ptrPIM_GROUP group);
	bool pim_process_join();

	//Utility
	void print_pim_sm_log(char* format, ...);
	void print_RPT_Tree(NETSIM_ID rp, ptrPIM_GROUP group);

#ifdef  __cplusplus
}
#endif
#endif
