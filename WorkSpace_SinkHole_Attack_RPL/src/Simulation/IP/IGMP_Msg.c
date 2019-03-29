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


static ptrIGMP_MSG get_IGMP_MSG(NetSim_PACKET* packet)
{
	return (ptrIGMP_MSG)(packet->pstruNetworkData->Packet_NetworkProtocol);
}

static void set_IGMP_MSG(NetSim_PACKET* packet, ptrIGMP_MSG msg)
{
	packet->pstruNetworkData->Packet_NetworkProtocol = msg;
}

static int get_ctrlpackettype_basedon_igmptype(IGMPMSG_TYPE type, char* stype)
{
	switch (type)
	{
	case IGMPMSG_LeaveGroup:
		strcpy(stype, "IGMP_LEAVE_GROUP");
		return PACKET_IGMP_LEAVE;

	case IGMPMSG_V2MembershipReport:
		strcpy(stype, "IGMP_V2_Membership_Report");
		return PACKET_IGMP_REPORT;

	case IGMPMSG_MembershipQuery:
		strcpy(stype, "IGMP_Membership_Query");
		return PACKET_IGMP_QUERY;

	default:
		fnNetSimError("Unknown igmp msg type %d\n", type);
		return 0;
	}
}

static ptrIGMP_MSG create_igmp_hdr(IGMPMSG_TYPE type,
								   UINT8 maxRespTime,
								   NETSIM_IPAddress group)
{
	ptrIGMP_MSG msg = (ptrIGMP_MSG)calloc(1, sizeof* msg);
	msg->GroupAddress = IP_COPY(group);
	msg->Type = type;
	msg->MaxRespTime = maxRespTime;

	return msg;
}

static void free_igmp_hdr(ptrIGMP_MSG msg)
{
	free(msg);
}

static ptrIGMP_MSG copy_igmp_hdr(ptrIGMP_MSG msg)
{
	ptrIGMP_MSG ret = (ptrIGMP_MSG)calloc(1, sizeof* msg);
	memcpy(ret, msg, sizeof* ret);
	return ret;
}

void copy_igmp_packet(NetSim_PACKET* d, NetSim_PACKET* s)
{
	set_IGMP_MSG(d, copy_igmp_hdr(get_IGMP_MSG(s)));
}
void IGMP_FreePacket(NetSim_PACKET* packet)
{
	free_igmp_hdr(packet->pstruNetworkData->Packet_NetworkProtocol);
	packet->pstruNetworkData->Packet_NetworkProtocol = NULL;
	packet->pstruNetworkData->IPProtocol = 0;
}

static UINT8 make_resp_time(UINT T)
{
	return (UINT8)(T);
}

static NetSim_PACKET* create_igmp_packet(NETSIM_ID src,
										 NETSIM_ID ifId,
										 NETSIM_ID dest,
										 IGMPMSG_TYPE type,
										 NETSIM_IPAddress group,
										 UINT maxRespTime,
										 UINT8 ttl)
{
	UINT8 RespTime = make_resp_time(maxRespTime);
	ptrIGMP_MSG msg = create_igmp_hdr(type,
									  RespTime,
									  group);

	NetSim_PACKET* packet = fn_NetSim_Packet_CreatePacket(NETWORK_LAYER);

	set_IGMP_MSG(packet, msg);

	packet->dEventTime = pstruEventDetails->dEventTime;
	packet->nControlDataType = get_ctrlpackettype_basedon_igmptype(type, packet->szPacketType);
	packet->nPacketPriority = Priority_Low;
	packet->nPacketType = PacketType_Control;
	packet->nQOS = QOS_BE;
	packet->nReceiverId = 0;
	packet->nSourceId = src;
	packet->nTransmitterId = src;
	add_dest_to_packet(packet, dest);
	packet->pstruNetworkData->nTTL = ttl;
	packet->pstruNetworkData->nNetworkProtocol = NW_PROTOCOL_IPV4;
	packet->pstruNetworkData->dArrivalTime = pstruEventDetails->dEventTime;
	packet->pstruNetworkData->dStartTime = pstruEventDetails->dEventTime;
	packet->pstruNetworkData->dEndTime = pstruEventDetails->dEventTime;
	packet->pstruNetworkData->dOverhead = IGMP_HDR_SIZE;
	packet->pstruNetworkData->dPacketSize = packet->pstruNetworkData->dPayload +
		packet->pstruNetworkData->dOverhead;

	packet->pstruNetworkData->szSourceIP = DEVICE_NWADDRESS(src, ifId);
	packet->pstruNetworkData->szDestIP = IP_COPY(group);
	packet->pstruNetworkData->IPProtocol = IPPROTOCOL_IGMP;

	return packet;
}

static void send_igmp_packet(NETSIM_ID d,
							 double time,
							 NetSim_PACKET* packet)
{
	NetSim_EVENTDETAILS pevent;
	memset(&pevent, 0, sizeof pevent);
	pevent.dEventTime = time;
	pevent.dPacketSize = packet->pstruNetworkData->dPacketSize;
	pevent.nDeviceId = d;
	pevent.nDeviceType = DEVICE_TYPE(d);
	pevent.nEventType = NETWORK_OUT_EVENT;
	pevent.nPacketId = packet->nPacketId;
	pevent.nProtocolId = NW_PROTOCOL_IPV4;
	pevent.pPacket = packet;
	fnpAddEvent(&pevent);
}

void send_membership_report(NETSIM_ID d, NETSIM_IPAddress group)
{
	NetSim_PACKET* packet = create_igmp_packet(d,
											   1,
											   0,
											   IGMPMSG_V2MembershipReport,
											   group,
											   0,
											   1);

	send_igmp_packet(d, pstruEventDetails->dEventTime, packet);
}

static bool igmp_process_report(NetSim_PACKET* packet,
								ptrIGMP_MSG msg,
								NETSIM_ID d)
{
	if (isHost(d))
	{
		return host_process_report(packet, msg, d);
	}

	else if (isRouter(d))
	{
		return router_process_report(packet, msg, d);
	}
	return false;
}

bool igmp_process_query(NetSim_PACKET* packet,
						ptrIGMP_MSG msg,
						NETSIM_ID d)
{
	if (isIPRouter(d))
		return router_process_query(packet, msg, d);
	else if (isIPHOST(d))
		return host_process_query(packet, msg, d);
	else
		fnNetSimError("Device %d is neither host nor router", d);

	return true;
}

void process_igmp_packet()
{
	bool isContinue = true;
	NETSIM_ID d = pstruEventDetails->nDeviceId;
	NetSim_PACKET* packet = pstruEventDetails->pPacket;
	ptrIGMP_MSG msg = get_IGMP_MSG(packet);

	ptrIGMP_VAR igmp = GET_IGMP_VAR(d);
	if (!igmp)
	{
		//IGMP is not configured
		fn_NetSim_Packet_FreePacket(pstruEventDetails->pPacket);
		pstruEventDetails->pPacket = NULL;
		return;
	}

	switch (msg->Type)
	{
	case IGMPMSG_MembershipQuery:
		isContinue = igmp_process_query(packet, msg, d);
		break;
	case IGMPMSG_V2MembershipReport:
		isContinue = igmp_process_report(packet, msg, d);
		break;
	default:
		fnNetSimError("Unknown IGMP packet %d in %s.\n",
					  msg->Type,
					  __FUNCTION__);
		break;
	}

	if (!isContinue)
	{
		fn_NetSim_Packet_FreePacket(pstruEventDetails->pPacket);
		pstruEventDetails->pPacket = NULL;
	}
}

void send_query_msg(NETSIM_ID d, NETSIM_IPAddress group, double time)
{
	bool isStartup = true;
	ptrIGMP_VAR var = GET_IGMP_VAR(d);
	ptrIGMP_ROUTER router = GET_IGMP_ROUTER(d);
	ptrIGMP_ROUTER_DB db = router_get_multicast_db(d,
												   group);

	if (db->sentCount >= var->RobustnessVar)
		isStartup = false;

	if (db->state == RouterState_NonQuerier)
		return;

	NETSIM_ID i;
	for (i = 0; i < DEVICE(d)->nNumOfInterface; i++)
	{
		if (!isBroadcastInterface(d, i + 1))
			continue;
		NetSim_PACKET* packet = create_igmp_packet(d,
												   i+1,
												   0,
												   IGMPMSG_MembershipQuery,
												   group,
												   var->QueryResponseInterval,
												   1);
		send_igmp_packet(d, time, packet);
	}

	db->sentCount++;

	start_timer(d,
				isStartup ? EVENT_IGMP_SendStartupQuery : EVENT_IGMP_SendQuery,
				group,
				time);
}
