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

void* get_PIM_MSG(NetSim_PACKET* packet)
{
	return (packet->pstruNetworkData->Packet_NetworkProtocol);
}

void set_PIM_MSG(NetSim_PACKET* packet, void* msg)
{
	packet->pstruNetworkData->Packet_NetworkProtocol = msg;
}

static int pimtype_to_ctrltype(PIMMSG type, char* stype)
{
	switch (type)
	{
	case PIMMSG_Assert:
		strcpy(stype, "PIMMSG_Asset");
		return PACKET_PIM_ASSERT;

	case PIMMSG_Bootstrap:
		strcpy(stype, "PIMMSG_Bootstrap");
		return PACKET_PIM_BOOTSTRAP;

	case PIMMSG_CandidateRPAdvertisement:
		strcpy(stype, "PIMMSG_CandidateRPAdvertisement");
		return PACKET_PIM_CANDRPADVER;

	case PIMMSG_Graft:
		strcpy(stype, "PIMMSG_Graft");
		return PACKET_PIM_GRAFT;

	case PIMMSG_GraftAck:
		strcpy(stype, "PIMMSG_GraftAck");
		return PACKET_PIM_GRAFTACK;

	case PIMMSG_Hello:
		strcpy(stype, "PIMMSG_Hello");
		return PACKET_PIM_HELLO;

	case PIMMSG_JoinPrune:
		strcpy(stype, "PIMMSG_JoinPrune");
		return PACKET_PIM_JOINPRUNE;

	case PIMMSG_Register:
		strcpy(stype, "PIMMSG_Register");
		return PACKET_PIM_REGISTER;

	case PIMMSG_RegisterStop:
		strcpy(stype, "PIMMSG_RegisterStop");
		return PACKET_PIM_REGISTERSTOP;

	default:
		fnNetSimError("Unknown pim msg type %d\n", type);
		return 0;
	}
}

static double get_pim_size(PIMMSG type)
{
	switch (type)
	{
	case PIMMSG_Hello:
		return PIM_HDR_LEN + PIM_HELLO_LEN;
	case PIMMSG_JoinPrune:
		return PIM_HDR_LEN + PIM_JP_MSG_LEN;
	default:
		fnNetSimError("Unknown PIM MSG %d in %s", type, __FUNCTION__);
		return 0;
	}
}

NetSim_PACKET* create_pim_packet(PIMMSG type,
								 void* opt,
								 double time,
								 NETSIM_ID source,
								 NETSIM_IPAddress sourceAddrss,
								 UINT destCount,
								 NETSIM_ID* destList,
								 NETSIM_IPAddress group,
								 UINT ttl)
{
	NetSim_PACKET* packet = fn_NetSim_Packet_CreatePacket(NETWORK_LAYER);
	set_PIM_MSG(packet, opt);
	packet->nControlDataType = pimtype_to_ctrltype(type, packet->szPacketType);

	packet->dEventTime = time;
	packet->nPacketType = PacketType_Control;
	packet->nSourceId = source;
	packet->pstruNetworkData->dArrivalTime = time;
	packet->pstruNetworkData->dEndTime = time;
	packet->pstruNetworkData->dOverhead = get_pim_size(type);
	packet->pstruNetworkData->dPacketSize = packet->pstruNetworkData->dOverhead +
		packet->pstruNetworkData->dPayload;
	packet->pstruNetworkData->dStartTime = time;
	packet->pstruNetworkData->IPProtocol = IPPROTOCOL_PIM;
	packet->pstruNetworkData->nNetworkProtocol = NW_PROTOCOL_IPV4;
	packet->pstruNetworkData->nTTL = ttl;
	packet->pstruNetworkData->szDestIP = group;
	packet->pstruNetworkData->szSourceIP = sourceAddrss;
	UINT i;
	for (i = 0; i < destCount; i++)
		add_dest_to_packet(packet, destList[i]);
	return packet;
}

void send_pim_msg(NETSIM_ID d, double time, NetSim_PACKET* packet)
{
	NetSim_EVENTDETAILS pevent;
	memset(&pevent, 0, sizeof pevent);
	pevent.dEventTime = time;
	pevent.dPacketSize = packet->pstruNetworkData->dPacketSize;
	if (packet->pstruAppData)
	{
		pevent.nApplicationId = packet->pstruAppData->nApplicationId;
		pevent.nSegmentId = packet->pstruAppData->nSegmentId;
	}
	pevent.nDeviceId = d;
	pevent.nDeviceType = DEVICE_TYPE(d);
	pevent.nEventType = NETWORK_OUT_EVENT;
	pevent.nPacketId = packet->nPacketId;
	pevent.nProtocolId = NW_PROTOCOL_IPV4;
	pevent.pPacket = packet;
	fnpAddEvent(&pevent);
}

void set_pim_hdr(ptrPIM_HDR hdr, PIMMSG type)
{
	hdr->PIM_Ver = PIM_VER;
	hdr->Type = type;
}

ptrENCODED_UNICAST_ADDR encode_unicast_addr(NETSIM_IPAddress ip)
{
	ptrENCODED_UNICAST_ADDR addr = calloc(1, sizeof* addr);
	addr->addrFamily = ip->IP.IPV4.byte1;
	addr->encodingType = 1; //IPv4
	addr->unicastAddr = ip;
	return addr;
}

static UINT8 get_masklen(NETSIM_IPAddress subnet)
{
	char* bin = subnet->bin_ip;
	UINT8 ret = 0;
	while (*bin && *bin != 0)
	{
		bin++;
		ret++;
	}
	return ret;
}
 
ptrENCODED_SOURCE_ADDR encode_source_addr(NETSIM_IPAddress ip, NETSIM_IPAddress subnet)
{
	ptrENCODED_SOURCE_ADDR addr = calloc(1, sizeof* addr);
	addr->addrFamily = ip->IP.IPV4.byte1;
	addr->encodingType = 1; //IPv4
	addr->SourceAddr = ip;
	addr->maskLen = get_masklen(subnet);
	return addr;
}

ptrENCODED_GROUP_ADDR encode_group_addr(NETSIM_IPAddress ip)
{
	ptrENCODED_GROUP_ADDR addr = calloc(1, sizeof* addr);
	addr->addrFamily = ip->IP.IPV4.byte1;
	addr->EncodingType = 1;
	addr->GroupMulticastAddr = ip;
	addr->MaskLen = 32;
	return addr;
}