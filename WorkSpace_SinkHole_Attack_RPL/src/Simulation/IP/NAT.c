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

static void add_new_dest(NetSim_PACKET* packet, NETSIM_IPAddress ip)
{
	NetSim_PACKET_NETWORKLAYER* nw = calloc(1, sizeof* nw);
	
	memcpy(nw, packet->pstruNetworkData, sizeof* nw);
	nw->next = packet->pstruNetworkData;
	packet->pstruNetworkData = nw;

	nw->szDestIP = ip;
}

static void remove_dest(NetSim_PACKET* packet)
{
	NetSim_PACKET_NETWORKLAYER* nw = packet->pstruNetworkData;
	NetSim_PACKET_NETWORKLAYER* nnw = nw->next;
	if (nnw)
	{
		void* n = nnw->next;
		void* i = nnw->szDestIP;

		memcpy(nnw, nw, sizeof* nnw);
		nnw->next = n;
		nnw->szDestIP = i;
		packet->pstruNetworkData = nnw;
		nw->next = NULL;
		free(nw);
	}
}

int fn_NetSim_NAT_NetworkOut(NETSIM_ID ndev,NetSim_PACKET* packet)
{
	NETSIM_IPAddress dest = packet->pstruNetworkData->szDestIP;
	NETSIM_ID i;
	NETSIM_IPAddress newDest = NULL;

	UINT destCount;
	NETSIM_ID* destList = get_dest_from_packet(packet, &destCount);

	if(destCount>1)
		return 1; //Broadcast or Multicast

	if (destList[0] == 0)
		return 1; //Broadcast

	if (isMulticastIP(dest))
		return 1;

	for(i=0;i<DEVICE(ndev)->nNumOfInterface;i++)
	{
		if(DEVICE_INTERFACE(ndev,i+1) && DEVICE_INTERFACE(ndev,i+1)->szAddress)
		{
			NETSIM_IPAddress ip = DEVICE_INTERFACE(ndev,i+1)->szAddress;
			NETSIM_IPAddress mask = DEVICE_INTERFACE(ndev,i+1)->szSubnetMask;
			unsigned int prefix = DEVICE_INTERFACE(ndev,i+1)->prefix_len;
			NETSIM_IPAddress n1,n2;
			if(dest->type != ip->type)
				continue;
			n1=IP_NETWORK_ADDRESS(ip,mask,prefix);
			n2=IP_NETWORK_ADDRESS(dest,mask,prefix);
			if(!IP_COMPARE(n1,n2))
				return 2;
		}
	}
	for(i=0;i<DEVICE(ndev)->nNumOfInterface;i++)
	{
		if(DEVICE_INTERFACE(ndev,i+1) && DEVICE_INTERFACE(ndev,i+1)->szAddress && DEVICE_INTERFACE(ndev,i+1)->szDefaultGateWay)
		{
			newDest = DEVICE_INTERFACE(ndev,i+1)->szDefaultGateWay;
			break;
		}
	}

	if (newDest)
	{
		//Set me to default
		add_new_dest(packet, newDest);
	}
	else if (DEVICE_FIRST_PUBLICIP(destList[0]))
	{
		NETSIM_IPAddress pub = DEVICE_FIRST_PUBLICIP(destList[0]);
		if (!IP_COMPARE(pub, dest))
			return -1; // Already public ip is set

		for (i = 0; i < DEVICE(ndev)->nNumOfInterface; i++)
		{
			if (DEVICE_INTERFACE(ndev, i + 1) && DEVICE_INTERFACE(ndev, i + 1)->szAddress)
			{
				if (!IP_COMPARE(DEVICE_NWADDRESS(ndev, i + 1), pub))
					return -1; // I am public ip of dest
			}
		}

		//set me to public ip
		add_new_dest(packet, DEVICE_FIRST_PUBLICIP(destList[0]));
	}
	return 0;
}

int fn_NetSim_NAT_NetworkIn(NETSIM_ID ndev,NetSim_PACKET* packet)
{
	UINT destCount;
	NETSIM_ID* dest = get_dest_from_packet(packet, &destCount);
	if (destCount > 1)
		return -1; //Broadcast or Multicast

	if (ndev == dest[0])
	{
		remove_dest(packet);
		return -2;
	}

	if (isBroadcastIP(packet->pstruNetworkData->szDestIP))
		return -3;

	if (isMulticastIP(packet->pstruNetworkData->szDestIP))
		return -4;

	NETSIM_ID i;
	NETSIM_IPAddress ip = packet->pstruNetworkData->szDestIP;
	bool flag = false;
	for (i = 0; i < DEVICE(ndev)->nNumOfInterface; i++)
	{
		if (DEVICE_INTERFACE(ndev, i + 1) &&
			DEVICE_INTERFACE(ndev, i + 1)->szAddress &&
			!IP_COMPARE(ip, DEVICE_NWADDRESS(ndev, i + 1)))
		{
			flag = true;
			break;
		}
	}

	if (flag)
		remove_dest(packet);

	return 0;
}
