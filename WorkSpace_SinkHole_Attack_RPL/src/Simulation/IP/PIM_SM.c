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

static FILE* pim_sm_log = NULL;
static void init_pim_sm_log()
{
	if (!pim_sm_log)
	{
		char str[BUFSIZ];
		sprintf(str, "%s/%s", pszIOPath, "pim_sm_log.txt");
		pim_sm_log = fopen(str, "w");
	}
}

static void close_pim_sm_log()
{
	if(pim_sm_log)
		fclose(pim_sm_log);
}

void print_pim_sm_log(char* format, ...)
{
	if (pim_sm_log)
	{
		va_list l;
		va_start(l, format);
		vfprintf(pim_sm_log, format, l);
		fprintf(pim_sm_log, "\n");
		fflush(pim_sm_log);
	}
}

void pim_add_timeout_event(NETSIM_ID d,
						   double time,
						   IP_SUBEVENT eve,
						   NETSIM_IPAddress group)
{
	NetSim_EVENTDETAILS pevent;
	memset(&pevent, 0, sizeof pevent);
	pevent.dEventTime = time;
	pevent.nDeviceId = d;
	pevent.nDeviceType = DEVICE_TYPE(d);
	pevent.nEventType = TIMER_EVENT;
	pevent.nProtocolId = NW_PROTOCOL_IPV4;
	pevent.nSubEventType = eve;
	pevent.szOtherDetails = group;
	fnpAddEvent(&pevent);
}

void Router_PIM_Init(NETSIM_ID d)
{
	static bool isFirst = true;
	if (isFirst)
	{
		init_pim_sm_log();
		configure_PIM();
		isFirst = false;
	}
	DEVICE_NWLAYER(d)->routerFunction = pim_route_msg;
	ptrPIM_VAR var = GET_PIM_VAR(d);
	ALL_PIM_ROUTERS_ADDRESS = STR_TO_IP4("224.0.0.13");
	pim_route_add(d, 0, 330, ALL_PIM_ROUTERS_ADDRESS);
	
	print_pim_sm_log("Router %d, Time 0.0: Starting PIM", d);

	var->DR = calloc(DEVICE(d)->nNumOfInterface, sizeof* var->DR);

	var->genId = (UINT)rand();
	print_pim_sm_log("Generation Id = %d", var->genId);

	print_pim_sm_log("Adding %s to IP routing table.\n",
					 "224.0.0.13");
	
	double time = NETSIM_RAND_01()*var->triggeredHelloDelay;
	print_pim_sm_log("Router %d, Time %0.3lf: Sending hello packet", d, time / 1000);
	send_hello_msg(d, time);
}

static bool isPIMReqd(NETSIM_ID d)
{
	NETSIM_ID i;
	for (i = 0; i < DEVICE(d)->nNumOfInterface; i++)
	{
		if (DEVICE_INTERFACE(d, i + 1)->nInterfaceType == INTERFACE_WAN_ROUTER)
			return true;
	}
	return false;
}

void pim_configure(NETSIM_ID d, void* xmlNetSimNode)
{
	ptrPIM_VAR var = GET_PIM_VAR(d);
	if (!isPIMReqd(d))
	{
		fnNetSimError("PIM is configure for router %d without any WAN port\n", d);
		GET_IP_DEVVAR(d)->isPIMConfigured = false;
		return;
	}

	if (!var)
	{
		var = (ptrPIM_VAR)calloc(1, sizeof* var);
		SET_PIM_VAR(d, var);
	}

	getXmlVar(&var->helloPeriod, HELLO_PERIOD, xmlNetSimNode, 1, _DOUBLE, PIM);
	var->helloPeriod *= SECOND;

	getXmlVar(&var->triggeredHelloDelay, TRIGGERED_HELLO_DELAY, xmlNetSimNode, 1, _DOUBLE, PIM);
	var->triggeredHelloDelay *= SECOND;

	getXmlVar(&var->DRPriority, DR_PRIORITY, xmlNetSimNode, 1, _UINT, PIM);

	getXmlVar(&var->propagationDelay, PROPAGATION_DELAY, xmlNetSimNode, 1, _UINT16, PIM);

	getXmlVar(&var->overrideInterval, OVERRIDE_INTERVAL, xmlNetSimNode, 1, _UINT16, PIM);

	getXmlVar(&var->t_periodic, T_PERIODIC, xmlNetSimNode, 1, _DOUBLE, PIM);
	var->t_periodic *= SECOND;
}

IP_PROTOCOL_ACTION pim_decide_action(NetSim_PACKET* packet, NETSIM_ID d)
{
	if (packet->nControlDataType == PACKET_PIM_JOINPRUNE)
		return ACTION_MOVEUP;
	else if (packet->nControlDataType == PACKET_PIM_HELLO)
		return ACTION_MOVEUP;
	else
		return ACTION_MOVEUP;
}

void process_pim_packet()
{
	bool isFree = false;

	if (!GET_IP_DEVVAR(pstruEventDetails->nDeviceId)->isPIMConfigured)
		goto FREE_PACKET; // PIM is not configured for this device

	NetSim_PACKET* packet = pstruEventDetails->pPacket;

	print_pim_sm_log("Router %d, Time %0.3lf: %s packet is received on %d interface",
					 pstruEventDetails->nDeviceId,
					 pstruEventDetails->dEventTime / 1000,
					 packet->szPacketType,
					 pstruEventDetails->nInterfaceId);

	switch (packet->nControlDataType)
	{
	case PACKET_PIM_HELLO:
		isFree = process_pim_hello_packet();
		break;
	case PACKET_PIM_JOINPRUNE:
		isFree = pim_process_join();
		break;
	default:
		fnNetSimError("Unknown packet %s in %s\n",
					  packet->szPacketType,
					  __FUNCTION__);
		break;
	}
	print_pim_sm_log("\n");
	if (isFree)
	{
		FREE_PACKET:
		fn_NetSim_Packet_FreePacket(packet);
		pstruEventDetails->pPacket = NULL;
	}
}

void pim_handle_timer_event()
{
	NETSIM_ID d = pstruEventDetails->nDeviceId;
	double time = pstruEventDetails->dEventTime;
	NETSIM_IPAddress gAddr = pstruEventDetails->szOtherDetails;
	ptrPIM_VAR var = GET_PIM_VAR(d);

	switch (pstruEventDetails->nSubEventType)
	{
	case EVENT_PIM_SEND_HELLO:
	{
		double t = time + var->helloPeriod;
		print_pim_sm_log("Router %d, Time %0.3lf: Sending hello packet", d, t / 1000);
		send_hello_msg(d, t);
	}
	break;
	case EVENT_PIM_JT:
		ptrPIM_GROUP group = pim_find_group(d, gAddr);
		pim_send_joinprune(d, time, group);
		break;
	case EVENT_PIM_ET:
		//Needs to implemented after node or link failure.
		break;
	case EVENT_PIM_NEIGHBOR_TIMEOUT:
		//Needs to implemented after node or link failure.
		break;
	default:
		fnNetSimError("Unknown subevent %d for PIM.", pstruEventDetails->nSubEventType);
		break;
	}
}

static bool isReservedGroup(NETSIM_IPAddress addr)
{
	if (!IP_COMPARE(addr, STR_TO_IP4("224.0.0.0")) ||
		!IP_COMPARE(addr, STR_TO_IP4("224.0.0.1")))
		return true;
	return false;
}

//Called from IGMP
void pim_join_group(NETSIM_ID d, NETSIM_IPAddress group)
{
	if (!GET_IP_DEVVAR(d)->isPIMConfigured)
		return; //PIM is not configured

	if (isReservedGroup(group))
		return; //Reserved address

	ptrPIM_GROUP gr = pim_find_group(d, group);
	if (!gr)
	{
		fnNetSimError("PIM Configuration is wrong. RP is not configured for group address %s\n",
					  group->str_ip);
		return;
	}

	if (d == gr->RPId)
	{
		fnNetSimError("PIM Configuration is wrong. %s can't be RP of group %s.\n",
					  gr->RP->str_ip,
					  group->str_ip);
		return;
	}

	print_pim_sm_log("Router %d, Time %0.3lf: Joining %s group",
					 d,
					 pstruEventDetails->dEventTime / 1000,
					 group->str_ip);
	
	//Call join function to send join msg to RP
	pim_send_joinprune(d, pstruEventDetails->dEventTime, gr);
}
