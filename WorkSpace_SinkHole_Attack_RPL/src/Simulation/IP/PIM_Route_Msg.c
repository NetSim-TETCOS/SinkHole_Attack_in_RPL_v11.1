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

static bool isInPresentInRoute(NETSIM_ID d, NETSIM_ID in, ptrIP_FORWARD_ROUTE route)
{
	UINT i;
	for (i = 0; i < route->count; i++)
	{
		if (!IP_COMPARE(DEVICE_NWADDRESS(d, in), route->gateway[i]))
			return true;
	}
	return false;
}

static bool isIamSrc(NetSim_PACKET* packet, NETSIM_ID d)
{
	NETSIM_ID i;
	for (i = 0; i < DEVICE(d)->nNumOfInterface; i++)
	{
		if (!IP_COMPARE(DEVICE_NWADDRESS(d, i + 1), packet->pstruNetworkData->szSourceIP))
			return true;
	}
	return false;
}

#define isBroadcastInterface(d,i) (DEVICE_INTERFACE(d,i)->nInterfaceType != INTERFACE_WAN_ROUTER)
static bool isIamDR(NETSIM_ID d, NETSIM_ID in)
{
	ptrPIM_VAR pim = GET_PIM_VAR(d);

	if (isBroadcastInterface(d, in))
	{
		if (!pim->DR[in - 1] || !IP_COMPARE(pim->DR[in - 1],
											DEVICE_NWADDRESS(d, in)))
			return true;
		else
			return false;
	}
	return true;
}

int pim_route_msg()
{
	int ret = -1;
	NETSIM_ID d = pstruEventDetails->nDeviceId;
	NetSim_PACKET* packet = pstruEventDetails->pPacket;
	NETSIM_IPAddress gip = packet->pstruNetworkData->szDestIP;

	if (!isMulticastIP(gip))
		return ret--; //Not a multicast packet

	NETSIM_IPAddress src = packet->pstruNetworkData->szSourceIP;
	ptrPIM_GROUP gr = pim_find_group(d, gip);
	ptrPIM_VAR pim = GET_PIM_VAR(d);
	NETSIM_ID in = pstruEventDetails->nInterfaceId;

	
	if (!gr)
		return ret--; //Group is not register.

	if (isIamSrc(packet, d))
		return ret--; // Let normal routing work

	NetSim_PACKET* dummy = fn_NetSim_Packet_CreatePacket(NETWORK_LAYER);
	dummy->pstruNetworkData->szDestIP = src;
	dummy->pstruNetworkData->szSourceIP = DEVICE_NWADDRESS(d, 1);

	ptrIP_FORWARD_ROUTE route = fn_NetSim_IP_RoutePacket(dummy, d);

	fn_NetSim_Packet_FreePacket(dummy);
	
	if (!route)
		fnNetSimError("Packet is reached to router without valid route to source\n");

	if (!isInPresentInRoute(d, in, route))
		goto DROP; //Packet is arrived from non source interface.

	NETSIM_ID i;
	for (i = 0; i < DEVICE(d)->nNumOfInterface; i++)
	{
		if (i + 1 == in)
			continue; //Incoming interface

		if (isBroadcastInterface(d, i + 1))
		{
			NETSIM_IPAddress subnet = DEVICE_INTERFACE(d, i + 1)->szSubnetMask;
			if (IP_IS_IN_SAME_NETWORK_IPV4(src, DEVICE_NWADDRESS(d, i + 1), subnet))
				continue;
		}

		if (isInPresentInRoute(d, i+1, route))
			continue;

		if (!isIamDR(d, i + 1))
			continue;


		NetSim_PACKET* fpacket = fn_NetSim_Packet_CopyPacket(packet);
		if (isBroadcastInterface(d, i + 1))
		{
			fpacket->pstruNetworkData->szNextHopIp = gip;
		}
		fpacket->pstruNetworkData->szGatewayIP = DEVICE_NWADDRESS(d, i + 1);
		NETSIM_ID c, ci;
		NETSIM_ID l = fn_NetSim_Stack_GetConnectedDevice(d, i + 1, &c, &ci);
		if (DEVICE_NWADDRESS(c, ci))
			fpacket->pstruNetworkData->szNextHopIp = DEVICE_NWADDRESS(c, ci);

		NetSim_EVENTDETAILS pevent;
		memcpy(&pevent, pstruEventDetails, sizeof pevent);
		pevent.dPacketSize = fpacket->pstruNetworkData->dPacketSize;
		pevent.nEventType = NETWORK_OUT_EVENT;
		pevent.nInterfaceId = i + 1;
		pevent.pPacket = fpacket;
		fnpAddEvent(&pevent);
	}
	DROP:
	fn_NetSim_Packet_FreePacket(packet);
	pstruEventDetails->pPacket = NULL;
	return 0;
}