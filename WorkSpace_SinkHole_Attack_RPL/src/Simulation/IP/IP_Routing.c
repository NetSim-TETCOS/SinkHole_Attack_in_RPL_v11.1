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
#include "NetSim_utility.h"
#include "Protocol.h"
#include "../Firewall/Firewall.h"

/** This function is used to route the packet */
typedef struct stru_match
{
	ptrIP_ROUTINGTABLE table;
	UINT bitsCount;
	UINT metric;
	_ele* ele;
}MATCH, *ptrMATCH;
#define MATCH_ALLOC() (ptrMATCH)list_alloc(sizeof(MATCH),offsetof(MATCH,ele))

static void print_match_table(ptrMATCH match, NETSIM_ID d, NETSIM_IPAddress dest, NETSIM_IPAddress src)
{
	static FILE* fp = NULL;
#ifdef PRINT_MATCH_TABLE
	if (!fp)
	{
		fp = fopen("MatchTable.csv", "w");
		fprintf(fp, "Dest,Gateway,Ifcount,Iflist,\n");
		fflush(fp);
	}
#endif
	if (fp)
	{
		fprintf(fp, " Device %d, dest = %s, Src = %s\n", d, dest->str_ip, src->str_ip);
		while (match)
		{
			UINT i;
			fprintf(fp, "%s,%s,%d,",
					match->table->networkDestination->str_ip,
					match->table->gateway?match->table->gateway->str_ip:"EMPTY",
					match->table->interfaceCount);
			for (i = 0; i < match->table->interfaceCount; i++)
				fprintf(fp, "%s,", match->table->Interface[i]->str_ip);
			fprintf(fp, "\n");
			match = LIST_NEXT(match);
		}
		fprintf(fp, "\n\n");
		fflush(fp);
	}
}

static void free_match_table(ptrMATCH l)
{
	while (l)
		LIST_FREE(&l, l);
}

static int match_check(ptrMATCH m1, ptrMATCH m2)
{
	if (m2->bitsCount > m1->bitsCount)
		return 2;
	if (m2->bitsCount == m1->bitsCount)
	{
		if (m2->metric < m1->metric)
			return 2;
	}
	return 0;
}

static void add_to_match_list(ptrMATCH* l, ptrMATCH c)
{
	LIST_ADD(l, c, match_check);
}

static UINT get_bit_match_count(NETSIM_IPAddress ip1)
{
	char b1[40];

	IP_TO_BINARY(ip1, b1);

	UINT l = (UINT)strlen(b1);
	UINT i;
	for (i = 0; i < l; i++)
	{
		if (b1[i] == '0')
			break;
	}
	return i;
}

static ptrMATCH get_match_table(ptrIP_ROUTINGTABLE table, NETSIM_IPAddress dest, bool isStatic)
{
	ptrMATCH l = NULL;
	ptrMATCH c = NULL;
	NETSIM_IPAddress network1;
	NETSIM_IPAddress network2;

	while (table)
	{
		bool isC = (isStatic && table->type == RoutingType_STATIC) || (!isStatic);
		if (!isC)
		{
			table = LIST_NEXT(table);
			continue;
		}

		if (!IP_COMPARE(dest, table->networkDestination) && ICMP_CHECKSTATE(dest))
		{
			c = MATCH_ALLOC();
			c->table = table;
			c->bitsCount = dest->type == 4 ? 32 : 128;
			c->metric = 999;
			add_to_match_list(&l, c);
		}
		else if (dest->type == table->networkDestination->type)
		{
			network1 = IP_NETWORK_ADDRESS(dest, table->netMask, table->prefix_len);
			network2 = IP_NETWORK_ADDRESS(table->networkDestination, table->netMask, table->prefix_len);
			if (!IP_COMPARE(network1, network2))
			{
				if (ICMP_CHECKSTATE(table->gateway))
				{
					c = MATCH_ALLOC();
					c->table = table;
					c->bitsCount = dest->type == 4 ? get_bit_match_count(table->netMask) : table->prefix_len;
					c->metric = table->Metric;
					add_to_match_list(&l, c);
				}
			}
		}
		table = LIST_NEXT(table);
	}

	return l;
}

static void update_route_entry(ptrMATCH match, ptrIP_FORWARD_ROUTE route,NETSIM_IPAddress dest)
{
	NETSIM_ID i;
	NETSIM_ID in;
	if (match)
	{
		ptrIP_ROUTINGTABLE table = match->table;

		route->count = table->interfaceCount;

		route->nextHop = calloc(table->interfaceCount, sizeof* route->nextHop);
		route->gateway = calloc(table->interfaceCount, sizeof* route->gateway);
		route->interfaceId = calloc(table->interfaceCount, sizeof* route->interfaceId);
		route->nextHopId = calloc(table->interfaceCount, sizeof* route->nextHopId);

		for (i = 0; i < table->interfaceCount; i++)
		{
			if (table->gateway)
				route->nextHop[i] = table->gateway;
			else
				route->nextHop[i] = dest;

			route->gateway[i] = table->Interface[i];

			route->interfaceId[i] = table->nInterfaceId[i];

			if (!table->nGatewayId && table->gateway)
				table->nGatewayId = fn_NetSim_Stack_GetDeviceId_asIP(table->gateway, &in);

			if (table->nGatewayId)
				route->nextHopId[i] = table->nGatewayId;
			else
				route->nextHopId[i] = 0; //MAC layer will decide
		}
	}
}

static ptrMATCH choose_match_for_reserved_address(ptrMATCH match,
												 NETSIM_IPAddress dest,
												 NETSIM_IPAddress src)
{
	bool isResevedAddr = is_reserved_multicast_address(dest);
	if (!isResevedAddr)
		return match;

	while (match)
	{
		if (isCorrectRoute(&match->table, dest, src))
			return match;
		match = LIST_NEXT(match);
	}
	return NULL;
}

static void multicast_update_route_entry(ptrMATCH match,
										 ptrIP_FORWARD_ROUTE route,
										 NETSIM_IPAddress dest,
										 NETSIM_IPAddress src)
{
	NETSIM_ID i;
	NETSIM_ID c;
	NETSIM_ID in;

	match = choose_match_for_reserved_address(match, dest, src);
	if (match)
	{
		ptrIP_ROUTINGTABLE table = match->table;

		route->count = table->interfaceCount;

		route->nextHop = calloc(table->interfaceCount, sizeof* route->nextHop);
		route->gateway = calloc(table->interfaceCount, sizeof* route->gateway);
		route->interfaceId = calloc(table->interfaceCount, sizeof* route->interfaceId);
		route->nextHopId = calloc(table->interfaceCount, sizeof* route->nextHopId);

		for (i = 0, c = 0; i < table->interfaceCount; i++, c++)
		{
			if (table->nInterfaceId[i] == pstruEventDetails->nInterfaceId)
			{
				c--;
				route->count--;
				continue;
			}

			if (table->gateway)
				route->nextHop[c] = table->gateway;
			else
				route->nextHop[c] = dest;

			route->gateway[c] = table->Interface[i];

			route->interfaceId[c] = table->nInterfaceId[i];

			if (!table->nGatewayId && table->gateway)
				table->nGatewayId = fn_NetSim_Stack_GetDeviceId_asIP(table->gateway, &in);

			if (table->nGatewayId)
				route->nextHopId[c] = table->nGatewayId;
			else
				route->nextHopId[c] = 0; //MAC layer will decide
		}
	}
}

static void route_onlink(NETSIM_ID d,
						NETSIM_IPAddress src,
						NETSIM_IPAddress dest,
						ptrIP_FORWARD_ROUTE route)
{
	NETSIM_ID i;
	UINT c = 0;
	for (i = 0; i < DEVICE(d)->nNumOfInterface; i++)
	{
		if (IP_IS_IN_SAME_NETWORK(src,
								  DEVICE_NWADDRESS(d, i + 1),
								  DEVICE_INTERFACE(d, i + 1)->szSubnetMask,
								  DEVICE_INTERFACE(d, i + 1)->prefix_len))
		{
			route->count++;
			if (route->gateway)
			{
				route->gateway = realloc(route->gateway, route->count * sizeof* route->gateway);
				route->interfaceId = realloc(route->interfaceId, route->count * sizeof* route->interfaceId);
				route->nextHop = realloc(route->nextHop, route->count * sizeof* route->nextHop);
				route->nextHopId = realloc(route->nextHopId, route->count * sizeof* route->nextHopId);
			}
			else
			{
				route->gateway = calloc(1, route->count * sizeof* route->gateway);
				route->interfaceId = calloc(1, route->count * sizeof* route->interfaceId);
				route->nextHop = calloc(1, route->count * sizeof* route->nextHop);
				route->nextHopId = calloc(1, route->count * sizeof* route->nextHopId);
			}
			route->gateway[c] = DEVICE_NWADDRESS(d, i + 1);
			route->interfaceId[c] = i + 1;
			route->nextHop[c] = dest;
			route->nextHopId[c] = 0;
			c++;
		}
	}
}

static bool check_my_ip(NETSIM_ID d, NETSIM_IPAddress ip)
{
	NETSIM_ID i;
	for (i = 0; i < DEVICE(d)->nNumOfInterface; i++)
		if (!IP_COMPARE(DEVICE_NWADDRESS(d, i + 1), ip))
			return true;
	return false;
}

static ptrIP_FORWARD_ROUTE route_unicast(NetSim_PACKET* packet,
										 NETSIM_ID dev)
{
	ptrIP_ROUTINGTABLE routingTable = IP_TABLE_GET(dev);
	NETSIM_IPAddress dest = packet->pstruNetworkData->szDestIP;

	ptrMATCH match = get_match_table(routingTable, dest, false);

	ptrMATCH store = match;

	ptrIP_FORWARD_ROUTE route = (ptrIP_FORWARD_ROUTE)calloc(1, sizeof* route);

	update_route_entry(match, route, dest);
	
	free_match_table(store);

	if (!route->count)
	{
		free(route);
		route = NULL;
	}

	return route;
}

static ptrIP_FORWARD_ROUTE route_multicast(NetSim_PACKET* packet,
										   NETSIM_ID dev)
{
	ptrIP_ROUTINGTABLE routingTable = IP_TABLE_GET(dev);
	NETSIM_IPAddress dest = packet->pstruNetworkData->szDestIP;
	NETSIM_IPAddress src = packet->pstruNetworkData->szSourceIP;

	ptrMATCH match = get_match_table(routingTable, dest, false);
#ifdef PRINT_MATCH_TABLE
	print_match_table(match, dev, dest, src);
#endif
	ptrMATCH store = match;

	ptrIP_FORWARD_ROUTE route = (ptrIP_FORWARD_ROUTE)calloc(1, sizeof* route);

	multicast_update_route_entry(match, route, dest, src);

	free_match_table(store);

	if (!route->count)
	{
		free(route);
		route = NULL;
	}

	return route;
}

ptrIP_FORWARD_ROUTE fn_NetSim_IP_RoutePacket(NetSim_PACKET* packet,
											 NETSIM_ID dev)
{
	NETSIM_IPAddress dest = packet->pstruNetworkData->szDestIP;

	if (isMulticastIP(dest))
		return route_multicast(packet, dev);
	else
		return route_unicast(packet, dev);
}

static void change_table(NETSIM_ID d, ptrIP_ROUTINGTABLE table,
						 NETSIM_IPAddress gateway, NETSIM_ID in, UINT metric)
{
	UINT i;
	bool isfound = false;
	for (i = 0; i < table->interfaceCount; i++)
	{
		if (in == table->nInterfaceId[i])
		{
			isfound = true;
			break;
		}
	}
	if (isfound)
	{
		table->gateway = gateway;
		table->Metric = metric;
	}
	else
	{
		table->Interface = realloc(table->Interface, (table->interfaceCount + 1) * sizeof* table->Interface);
		table->nInterfaceId = realloc(table->nInterfaceId, (table->interfaceCount + 1) * sizeof* table->Interface);
		table->nInterfaceId[table->interfaceCount] = in;
		table->Interface[table->interfaceCount] = DEVICE_NWADDRESS(d, in);
		table->gateway = gateway;
		table->Metric = metric;
		table->interfaceCount++;
	}
}

static void add_table(NETSIM_ID d, NETSIM_IPAddress dest, NETSIM_IPAddress mask,
					  NETSIM_IPAddress gateway, NETSIM_ID in, UINT metric)
{
	iptable_add(IP_WRAPPER_GET(d), dest, mask, 0, gateway, 1, &DEVICE_NWADDRESS(d, in), &in, metric, "STATIC");
}

#define display_error(error, line, file) fnNetSimError("Invalid line in route file %s at line %d: %s", file, line, error)
/** This function is to configure static ip table */
void configure_static_ip_route(NETSIM_ID d, char* file)
{
	UINT line = 0;
	NETSIM_ID nDevId = 0;
	char* temp;
	int metric = 0;
	
	char input[BUFSIZ];
	sprintf(input, "%s%s%s", pszIOPath, pathSeperator, file);
	FILE* fp = fopen(input, "r");
	if (fp == NULL)
	{
		perror(input);
		fnNetSimError("Unable to open routing file %s", input);
		return;
	}

	while (fgets(input, BUFSIZ, fp))
	{
		line++;
		temp = input;
		temp = lskip(temp);
		if (*temp == '#' || !*temp)
			continue; //Comment or empty line
			
		char* f = find_word(&temp);
		if (_stricmp(f, "route"))
		{
			display_error("Not start with route", file, line);
			continue;
		}

		f = find_word(&temp);
		if (_stricmp(f, "add"))
		{
			display_error("Second word is not add", file, line);
			continue;
		}

		f = find_word(&temp);
		NETSIM_IPAddress dest = STR_TO_IP4(f);

		f = find_word(&temp);
		if (_stricmp(f, "mask"))
		{
			display_error("Fourth word is not mask", file, line);
			continue;
		}

		f = find_word(&temp);
		NETSIM_IPAddress mask = STR_TO_IP4(f);

		f = find_word(&temp);
		NETSIM_IPAddress gateway = STR_TO_IP4(f);

		f = find_word(&temp);
		if (_stricmp(f, "metric"))
		{
			display_error("Seventh word is not metric", file, line);
			continue;
		}

		f = find_word(&temp);
		UINT metric = atoi(f);

		f = find_word(&temp);
		if (_stricmp(f, "IF"))
		{
			display_error("Ninth word is not if", file, line);
			continue;
		}

		f = find_word(&temp);
		NETSIM_ID in = atoi(f);
		in = fn_NetSim_GetInterfaceIdByConfigId(d, in);

		ptrIP_ROUTINGTABLE table = iptable_check(PIP_TABLE_GET(d), dest, mask);
		if (table)
			change_table(d, table, gateway, in, metric);
		else
			add_table(d, dest, mask, gateway, in, metric);
		
	}
}

static ptrIP_FORWARD_ROUTE static_route_unicast(NetSim_PACKET* packet,
												NETSIM_ID dev)
{
	ptrIP_ROUTINGTABLE routingTable = IP_TABLE_GET(dev);
	NETSIM_IPAddress dest = packet->pstruNetworkData->szDestIP;

	ptrMATCH match = get_match_table(routingTable, dest, true);

	ptrMATCH store = match;

	ptrIP_FORWARD_ROUTE route = (ptrIP_FORWARD_ROUTE)calloc(1, sizeof* route);

	update_route_entry(match, route, dest);

	free_match_table(store);

	if (!route->count)
	{
		free(route);
		route = NULL;
	}

	return route;
}

static ptrIP_FORWARD_ROUTE static_route_multicast(NetSim_PACKET* packet,
												  NETSIM_ID dev)
{
	ptrIP_ROUTINGTABLE routingTable = IP_TABLE_GET(dev);
	NETSIM_IPAddress dest = packet->pstruNetworkData->szDestIP;
	NETSIM_IPAddress src = packet->pstruNetworkData->szSourceIP;

	ptrMATCH match = get_match_table(routingTable, dest, true);
#ifdef PRINT_MATCH_TABLE
	print_match_table(match, dev, dest, src);
#endif
	ptrMATCH store = match;

	ptrIP_FORWARD_ROUTE route = (ptrIP_FORWARD_ROUTE)calloc(1, sizeof* route);

	multicast_update_route_entry(match, route, dest, src);

	free_match_table(store);

	if (!route->count)
	{
		free(route);
		route = NULL;
	}

	return route;
}

ptrIP_FORWARD_ROUTE fn_NetSim_IP_RoutePacketViaStaticEntry(NetSim_PACKET* packet, NETSIM_ID dev)
{
	NETSIM_IPAddress dest = packet->pstruNetworkData->szDestIP;

	if (isMulticastIP(dest))
		return static_route_multicast(packet, dev);
	else
		return static_route_unicast(packet, dev);
}

void pass_to_lower_layer(NetSim_PACKET* packet, ptrIP_FORWARD_ROUTE route, UINT c)
{
	NetSim_EVENTDETAILS pevent;
	memset(&pevent, 0, sizeof pevent);

	NETSIM_ID d, n, i;
	
	d = pstruEventDetails->nDeviceId;
	if (route)
	{
		packet->pstruNetworkData->szNextHopIp = route->nextHop[c];
		packet->pstruNetworkData->szGatewayIP = route->gateway[c];
		n = route->nextHopId[c];
		i = route->interfaceId[c];
	}
	else
	{
		if (!packet->pstruNetworkData->szGatewayIP)
			packet->pstruNetworkData->szGatewayIP = fn_NetSim_Stack_GetFirstIPAddressAsId(d, 4);

		if (!pstruEventDetails->nInterfaceId)
			i = fn_NetSim_Stack_GetInterfaceIdFromIP(d,
													 packet->pstruNetworkData->szGatewayIP);
		else
			i = pstruEventDetails->nInterfaceId;

		NETSIM_ID k; //Not used
		n = fn_NetSim_Stack_GetDeviceId_asIP(packet->pstruNetworkData->szNextHopIp,
											 &k);

	}

	//check for firewall
	if (fn_NetSim_NETWORK_Firewall(d, i, packet, ACLTYPE_OUTBOUND) == ACLACTION_DENY)
	{
		ipMetrics[d - 1]->nFirewallBlocked++;
		fn_NetSim_Packet_FreePacket(packet);
		pstruEventDetails->pPacket = NULL;
		return;
	}

	if (!IP_COMPARE(packet->pstruNetworkData->szGatewayIP, packet->pstruNetworkData->szNextHopIp))
	{
		fnNetSimError("Gateway IP and next hop IP are same. IP address=%s\n",
					  packet->pstruNetworkData->szGatewayIP->str_ip);
	}

	packet->pstruNetworkData->dOverhead += IPV4_HEADER_SIZE;
	packet->pstruNetworkData->dPacketSize = packet->pstruNetworkData->dOverhead +
		packet->pstruNetworkData->dPayload;


	//Set the end time
	packet->pstruNetworkData->dEndTime = pstruEventDetails->dEventTime;
	packet->pstruNetworkData->nNetworkProtocol = DEVICE_INTERFACE(d,i)->nProtocolId;
	packet->nTransmitterId = d;
	packet->nReceiverId = n;

	if (DEVICE_INTERFACE(d,i)->nLocalNetworkProtocol == PROTOCOL_VPN)
		fn_NetSim_IP_VPN_Run();

	if (pstruEventDetails->pPacket == NULL)
		return;

	//Increment the count
	ipMetrics[d - 1]->nPacketSent++;

	ip_write_to_pcap(packet, d, i, pstruEventDetails->dEventTime);


	if (DEVICE_INTERFACE(d,i)->nLocalNetworkProtocol)
	{
		memcpy(&pevent, pstruEventDetails, sizeof pevent);
		pstruEventDetails->nDeviceId = d;
		pstruEventDetails->nDeviceType = DEVICE_TYPE(d);
		pstruEventDetails->dPacketSize = packet->pstruNetworkData->dPacketSize;
		if (packet->pstruAppData)
		{
			pstruEventDetails->nApplicationId = packet->pstruAppData->nApplicationId;
			pstruEventDetails->nSegmentId = packet->pstruAppData->nSegmentId;
		}
		pstruEventDetails->nEventType = NETWORK_OUT_EVENT;
		pstruEventDetails->nInterfaceId = i;
		pstruEventDetails->nPacketId = packet->nPacketId;
		pstruEventDetails->nProtocolId = DEVICE_INTERFACE(d, i)->nLocalNetworkProtocol;
		pstruEventDetails->nSubEventType = 0;
		pstruEventDetails->pPacket = packet;
		pstruEventDetails->szOtherDetails = NULL;
		//Call the local network protocol
		fnCallProtocol(DEVICE_INTERFACE(d, i)->nLocalNetworkProtocol);
		memcpy(pstruEventDetails, &pevent, sizeof* pstruEventDetails);
	}
	else
	{
		NetSim_BUFFER* buffer = DEVICE_INTERFACE(d, i)->pstruAccessInterface->pstruAccessBuffer;
		packet->pstruMacData->szSourceMac = (fn_NetSim_Stack_GetMacAddressFromIP(packet->pstruNetworkData->szGatewayIP));
		NETSIM_IPAddress szDestIPaddr = packet->pstruNetworkData->szNextHopIp;
		if (isBroadcastIP(szDestIPaddr))
			packet->pstruMacData->szDestMac = BROADCAST_MAC;
		else if (isMulticastIP(szDestIPaddr))
			packet->pstruMacData->szDestMac = multicastIP_to_Mac(szDestIPaddr);
		else
			packet->pstruMacData->szDestMac = fn_NetSim_Stack_GetMacAddressFromIP(szDestIPaddr);

		if (!fn_NetSim_GetBufferStatus(buffer))
		{
			pevent.dEventTime = pstruEventDetails->dEventTime;
			pevent.nDeviceId = d;
			pevent.nDeviceType = DEVICE_TYPE(d);
			pevent.nInterfaceId = i;
			//Add the MAC out event
			pevent.dPacketSize = packet->pstruNetworkData->dPacketSize;
			if (packet->pstruAppData)
			{
				pevent.nApplicationId = packet->pstruAppData->nApplicationId;
				pevent.nSegmentId = packet->pstruAppData->nSegmentId;
			}
			pevent.nEventType = MAC_OUT_EVENT;
			pevent.nPacketId = packet->nPacketId;
			pevent.nProtocolId = fn_NetSim_Stack_GetMacProtocol(d,i);
			fnpAddEvent(&pevent);
		}
		fn_NetSim_Packet_AddPacketToList(buffer, packet, 0);
	}
}
