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

typedef struct stru_pim_route
{
	NETSIM_ID d;
	UINT interfaceCount;
	NETSIM_ID* ifList;
	NETSIM_IPAddress dest;
	ptrIP_ROUTINGTABLE table;
	_ele* ele;
}PIM_ROUTE, *ptrPIM_ROUTE;
#define PIM_ROUTE_ALLOC() (ptrPIM_ROUTE)list_alloc(sizeof(PIM_ROUTE),offsetof(PIM_ROUTE,ele))
#define PIM_ROUTE_ADD(ls,m) LIST_ADD_LAST((void**)ls,m)
#define PIM_ROUTE_NEXT(m) (m = LIST_NEXT(m))
static ptrPIM_ROUTE pimRoute = NULL;

static ptrPIM_ROUTE find_route(NETSIM_ID d, NETSIM_ID i, NETSIM_IPAddress dest)
{
	ptrPIM_ROUTE r = pimRoute;
	while (r)
	{
		bool fd = false;
		bool fi = false;
		if (r->d == d &&
			!IP_COMPARE(r->dest, dest))
		{
			//Continue further check
		}
		else
		{
			PIM_ROUTE_NEXT(r);
			continue;
		}
		if (i)
		{
			UINT k;
			for (k = 0; k < r->interfaceCount; k++)
			{
				if (r->ifList[k] == i)
				{
					return r;
				}
			}
		}
		else
		{
			return r;
		}

		PIM_ROUTE_NEXT(r);
	}
	return NULL;
}

void pim_route_add(NETSIM_ID d,
				   NETSIM_ID i,
				   UINT metric,
				   NETSIM_IPAddress dest)
{
	ptrPIM_ROUTE r = find_route(d, i, dest);
	if (r)
	{
		r->table->Metric = metric;
	}
	else
	{
		if (i)
			r = find_route(d, 0, dest);
		if (r)
		{
			//Add new interface only
			UINT c = r->table->interfaceCount;
			NETSIM_IPAddress* addr = r->table->Interface;
			NETSIM_ID* id = r->table->nInterfaceId;
			NETSIM_ID* rid = r->ifList;

			addr = realloc(addr, (c + 1) * sizeof* addr);
			addr[c] = IP_COPY(DEVICE_NWADDRESS(d, i));
			r->table->Interface = addr;

			id = realloc(id, (c + 1) * sizeof* id);
			id[c] = i;
			r->table->nInterfaceId = id;

			rid = realloc(rid, (c + 1) * sizeof* rid);
			rid[c] = i;
			r->ifList = rid;

			r->interfaceCount++;

			r->table->interfaceCount++;

			r->table->Metric = metric;
		}
		else
		{
			//Add new route
			NETSIM_IPAddress* addr;
			NETSIM_ID* id;
			UINT c;

			r = PIM_ROUTE_ALLOC();
			PIM_ROUTE_ADD(&pimRoute, r);
			r->d = d;
			r->dest = dest;

			if (i)
			{
				c = 1;
				id = calloc(1, sizeof* id);
				addr = calloc(1, sizeof* addr);
				id[0] = i;
				addr[0] = IP_COPY(DEVICE_NWADDRESS(d, i));
				r->interfaceCount = 1;
				r->ifList = calloc(1, sizeof* r->ifList);
				r->ifList[0] = i;
			}
			else
			{
				c = DEVICE(d)->nNumOfInterface;
				id = calloc(c, sizeof* id);
				addr = calloc(c, sizeof* addr);
				r->interfaceCount = c;
				r->ifList = calloc(c, sizeof* r->ifList);
				UINT k;
				for (k = 0; k < c; k++)
				{
					id[k] = k + 1;
					addr[k] = IP_COPY(DEVICE_NWADDRESS(d, k + 1));
					r->ifList[k] = k + 1;
				}
			}

			r->table = iptable_add(IP_WRAPPER_GET(d),
								   dest,
								   STR_TO_IP4("255.255.255.255"),
								   0,
								   NULL,
								   c,
								   addr,
								   id,
								   metric,
								   "PIM-MULTICAST");
		}
	}
}

NETSIM_IPAddress pimroute_find_nexthop(NETSIM_ID d, NETSIM_IPAddress dest)
{
	//Create dummy packet
	NetSim_PACKET* packet = fn_NetSim_Packet_CreatePacket(NETWORK_LAYER);
	packet->pstruNetworkData->szDestIP = dest;
	packet->pstruNetworkData->szSourceIP = DEVICE_NWADDRESS(d, 1);

	ptrIP_FORWARD_ROUTE route = fn_NetSim_IP_RoutePacket(packet, d);
	NETSIM_IPAddress next = NULL;
	if (!route->nextHop)
	{
		fnNetSimError("Unicast route is not found for dest %s from %s. Please check/enable routing protocol.",
					  dest->str_ip,
					  packet->pstruNetworkData->szSourceIP->str_ip);
	}
	else
	{
		next = route->nextHop[0];
	}
	free(route);
	fn_NetSim_Packet_FreePacket(packet);
	return next;
}