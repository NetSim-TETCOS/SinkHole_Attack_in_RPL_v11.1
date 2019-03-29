/************************************************************************************
 * Copyright (C) 2014                                                               *
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
/** This function is to find the gateway */
NETSIM_ID fnFindGateway(NETSIM_ID nDeviceId)
{
	NETSIM_ID i,j;
	for(i=0;i<NETWORK->ppstruDeviceList[nDeviceId-1]->nNumOfInterface;i++)
	{
		if(NETWORK->ppstruDeviceList[nDeviceId-1]->ppstruInterfaceList[i]->szDefaultGateWay)
		{
			return fn_NetSim_Stack_GetDeviceId_asIP(NETWORK->ppstruDeviceList[nDeviceId-1]->ppstruInterfaceList[i]->szDefaultGateWay,&j);
		}
	}
	return nDeviceId;
}
/**
The DOMAIN NAME SPACE and RESOURCE RECORDS, which are
specifications for a tree structured name space and data
associated with the names. Conceptually, each node and leaf
of the domain name space tree names a set of information, and
query operations are attempts to extract specific types of
information from a particular set. A query names the domain
name of interest and describes the type of resource
information that is desired. For example, the Internet
uses some of its domain names to identify hosts; queries for
address resources return Internet host addresses.
*/
_declspec(dllexport) NETSIM_IPAddress dns_query(NETSIM_ID nDeviceId,NETSIM_ID id)
{
	DNS* dns;
	IP_DEVVAR* devVar;
	NETSIM_ID ngatewayId=fnFindGateway(nDeviceId);
	if(!ngatewayId)
	{
		fnNetSimError("Gateway is not configured for device %d",nDeviceId);
		assert(false);
	}
	if(!DEVICE_NWLAYER(ngatewayId))
		fnNetSimError("DNS-- Netwok layer is not configured for device %d",ngatewayId);
	devVar=DEVICE_NWLAYER(ngatewayId)->ipVar;
	dns=devVar->dnsList;
	while(dns)
	{
		if(dns->deviceId==id)
			return dns->ip;
		dns=LIST_NEXT(dns);
	}
	dns=DNS_ALLOC();
	dns->deviceId=id;
	dns->ip=fn_NetSim_Stack_GetFirstIPAddressAsId(id,0);
	LIST_ADD_LAST(&(devVar->dnsList),dns);
	return dns->ip;
}
/** This function is free the memory allocated for DNS */
int freeDNS(DNS* dns)
{
	while(dns)
		LIST_FREE(&dns,dns);
	return 1;
}