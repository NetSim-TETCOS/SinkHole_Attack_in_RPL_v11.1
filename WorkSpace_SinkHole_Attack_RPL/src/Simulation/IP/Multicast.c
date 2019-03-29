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
#include "IP.h"
#include "List.h"
#include "IGMP.h"

static NETSIM_IPAddress ALL_IN_SUBNET;
static NETSIM_IPAddress ALL_ROUTER_IN_SUBNET;
static NETSIM_IPAddress ALL_PIM_ROUTER;
static NETSIM_IPAddress ALL_SPF_ROUTERS;
static NETSIM_IPAddress ALL_D_ROUTERS;

void multicast_join_group()
{
	NETSIM_IPAddress ip = pstruEventDetails->szOtherDetails;

	IP_DEVVAR* dev = GET_IP_DEVVAR(pstruEventDetails->nDeviceId);
	if (!dev->isIGMPConfigured)
	{
		fnNetSimError("%s is called for device %d without IGMP enable. Please enable IGMP to run multicast\n",
					  __FUNCTION__,
					  pstruEventDetails->nDeviceId);
		return;
	}
	//Call IPGMP to join group
	igmp_host_join_group(pstruEventDetails->nDeviceId, ip);
}

static bool isOSPFPacket(NetSim_PACKET* packet)
{
	if (!ALL_SPF_ROUTERS)
	{
		ALL_SPF_ROUTERS = STR_TO_IP4("224.0.0.5");
		ALL_D_ROUTERS = STR_TO_IP4("224.0.0.6");
	}

	NETSIM_IPAddress ip = packet->pstruNetworkData->szDestIP;
	if (!IP_COMPARE(ip, ALL_SPF_ROUTERS))
		return true;

	if (!IP_COMPARE(ip, ALL_D_ROUTERS))
		return true;

	return false;
}

IP_PROTOCOL_ACTION check_ip_in_multicastgroup(NETSIM_IPAddress ip, NETSIM_ID d, NetSim_PACKET* packet)
{
	if (isRouter(d) && isOSPFPacket(packet))
		return ACTION_MOVEUP;

	if (isIGMPPacket(packet))
		return ACTION_MOVEUP;

	if (isPIMPacket(packet))
	{
		if (isHost(d))
			return ACTION_DROP;
		else if (isRouter(d))
			return ACTION_MOVEUP;
	}

	if (isRouter(d))
		return ACTION_REROUTE;
	//return router_is_ip_present_in_db(d, ip, packet);
	else if (isHost(d))
		return host_is_ip_present_in_db(d, ip, packet);
	else if (isL3Device(d))
		return ACTION_REROUTE;
	else
		return ACTION_DROP; //Unknown type of device.
}

bool is_reserved_multicast_address(NETSIM_IPAddress ip)
{
	static bool init = false;
	if (!init)
	{
		init = true;
		ALL_PIM_ROUTER = STR_TO_IP4("224.0.0.13");
		ALL_IN_SUBNET = STR_TO_IP4("224.0.0.1");
		ALL_ROUTER_IN_SUBNET = STR_TO_IP4("224.0.0.2");
		ALL_SPF_ROUTERS = STR_TO_IP4("224.0.0.5");
		ALL_D_ROUTERS = STR_TO_IP4("224.0.0.6");
	}

	if (!IP_COMPARE(ip, ALL_IN_SUBNET ))
		return true;
	
	if (!IP_COMPARE(ip, ALL_PIM_ROUTER))
		return true;

	if (!IP_COMPARE(ip, ALL_ROUTER_IN_SUBNET))
		return true;

	if (!IP_COMPARE(ip, ALL_SPF_ROUTERS))
		return true;
	
	if (!IP_COMPARE(ip, ALL_D_ROUTERS))
		return true;
	
	return false;
}

IP_ROUTINGTABLE* tab = NULL;
static bool isCorrectRouteForSubnet(IP_ROUTINGTABLE** table, NETSIM_IPAddress dest, NETSIM_IPAddress src)
{
	if (!tab)
		tab = IPROUTINGTABLE_ALLOC();
	
	if (IP_COMPARE((*table)->networkDestination, dest))
		return false;

	memcpy(tab, *table, sizeof* tab);
	tab->interfaceCount = 0;

	UINT k = 0;
	UINT i;
	for (i = 0; i < (*table)->interfaceCount; i++)
	{
		if (IP_IS_IN_SAME_NETWORK_IPV4(src, (*table)->Interface[i], (*table)->netMask))
		{
			tab->interfaceCount++;
			tab->Interface[k] = (*table)->Interface[i];
			tab->nInterfaceId[k] = (*table)->nInterfaceId[i];
			k++;
		}
	}
	if (k)
	{
		*table = tab;
		return true;
	}
	else
	{
		*table = NULL;
		return false;
	}
}

bool isCorrectRoute(pptrIP_ROUTINGTABLE table, NETSIM_IPAddress dest, NETSIM_IPAddress src)
{
	if (!IP_COMPARE(dest, ALL_IN_SUBNET))
		return isCorrectRouteForSubnet(table, dest, src);

	if (!IP_COMPARE(dest, ALL_PIM_ROUTER))
		return true;

	return true;
}

