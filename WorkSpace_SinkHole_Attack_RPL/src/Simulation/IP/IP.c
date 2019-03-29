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
#include "Protocol.h"
#include "NetSim_utility.h"
#include "../Firewall/Firewall.h"
#include "Animation.h"

_declspec(dllexport) int fn_NetSim_IP_VPN_Init();
NETWORK_LAYER_PROTOCOL fnGetLocalNetworkProtocol(NetSim_EVENTDETAILS* pstruEventDetails);
int freeVPN(void* vpn);
int freeDNS(void* dns);
int freeVPNPacket(void* vpnPacket);
void* copyVPNPacket(void* vpnPacket);
static void add_default_ip_table_entry(NETSIM_ID d);
void set_public_ip(NETSIM_ID d);
void configure_static_ip_route(NETSIM_ID d, char* file);
static void init_ip_anim();


//ICMP function
_declspec(dllexport) int fn_NetSim_IP_ICMP_GenerateDstUnreachableMsg();
_declspec(dllexport) int fn_NetSim_IP_ICMP_EchoRequest();
_declspec(dllexport) int fn_NetSim_IP_ICMP_EchoReply();
_declspec(dllexport) int fn_NetSim_IP_ICMP_ProcessRouterAdvertisement();
_declspec(dllexport) int fn_NetSim_IP_ICMP_ProcessDestUnreachableMsg();
_declspec(dllexport) int fn_NetSim_IP_ICMP_Init();
_declspec(dllexport) int fn_NetSim_IP_ICMP_POLL();
_declspec(dllexport) int fn_NetSim_IP_ICMP_AdvertiseRouter();

int fn_NetSim_IP_ConfigStaticIPTable(char* szVal);

static IP_PROTOCOL_ACTION decide_action_for_packet(NetSim_PACKET* packet, NETSIM_ID dev)
{
	NETSIM_IPAddress dest = packet->pstruNetworkData->szDestIP;
	NETSIM_IPAddress recv = packet->pstruNetworkData->szNextHopIp;

	if (isBroadcastIP(dest))
	{
		if (isHost(dev))
			return ACTION_MOVEUP;
		else
			return ACTION_DROP;
	}

	if (isMulticastIP(dest))
	{
		return check_ip_in_multicastgroup(dest, dev, packet);
	}
	switch (packet->pstruNetworkData->IPProtocol)
	{
	case IPPROTOCOL_PIM:
		return pim_decide_action(packet, dev);
		break;
	}

	if (isDestFoundinPacket(packet, dev))
		return ACTION_MOVEUP;
	else
		return ACTION_REROUTE;
}

/**
This function initializes the IP parameters.
*/
_declspec(dllexport) int fn_NetSim_IP_Init(struct stru_NetSim_Network *NETWORK_Formal,
										   NetSim_EVENTDETAILS *pstruEventDetails_Formal,
										   char *pszAppPath_Formal,
										   char *pszWritePath_Formal,
										   int nVersion_Type,
										   void **fnPointer)
{
	NETSIM_ID loop;
	if (nVersion_Type / 10 != VERSION)
	{
		printf("IP---Version number mismatch\nDll Version=%d\nNetSim Version=%d\nFileName=%s\nLine=%d\n", VERSION, nVersion_Type / 10, __FILE__, __LINE__);
		exit(0);
	}
	pstruEventDetails->dEventTime = 0;
	init_ip_anim();
	fnDNS = dns_query;
	ipMetrics = calloc(NETWORK->nDeviceCount, sizeof* ipMetrics);
	for (loop = 0; loop < NETWORK->nDeviceCount; loop++)
	{
		if (!DEVICE_NWLAYER(loop + 1))
			continue;

		NETSIM_ID nInterface;
		unsigned int i;

		set_public_ip(loop + 1);

		add_default_ip_table_entry(loop + 1);

		IP_DEVVAR* devVar = NETWORK->ppstruDeviceList[loop]->pstruNetworkLayer->ipVar;

		if (devVar->staticIPTableFile && *devVar->staticIPTableFile)
			configure_static_ip_route(loop + 1, devVar->staticIPTableFile);

		if (devVar->nGatewayCount)
			devVar->nGatewayId = calloc(devVar->nGatewayCount, sizeof* devVar->nGatewayId);
		for (i = 0; i < devVar->nGatewayCount; i++)
			devVar->nGatewayId[i] = fn_NetSim_Stack_GetDeviceId_asIP(devVar->GatewayIPAddress[i], &nInterface);
		if (devVar && devVar->isFirewallConfigured)
		{
			//read the firewall info
			fn_NetSim_FirewallConfig(loop + 1);
		}
		ipMetrics[loop] = calloc(1, sizeof* ipMetrics[loop]);
		ipMetrics[loop]->nDeviceId = fn_NetSim_Stack_GetConfigIdOfDeviceById(loop + 1);

		//Init the IGMP
		if (devVar->isIGMPConfigured)
			igmp_init(loop + 1);

		//Init the PIM
		if (devVar->isPIMConfigured)
			Router_PIM_Init(loop + 1);
	}

	//Initialize the ICMP
	fn_NetSim_IP_ICMP_Init();

	//Initialize the VPN
	fn_NetSim_IP_VPN_Init();
	return 1;
}

static ptrIP_FORWARD_ROUTE build_route(NetSim_PACKET* packet)
{
	NETSIM_ID d = pstruEventDetails->nDeviceId;
	NETSIM_ID in = pstruEventDetails->nInterfaceId;

	if (!packet)
		return NULL;
	if (!packet->pstruNetworkData->szNextHopIp)
		return NULL;

	ptrIP_FORWARD_ROUTE route = calloc(1, sizeof* route);
	route->count = 1;
	
	route->nextHop = calloc(1, sizeof* route->nextHop);
	route->nextHop[0] = packet->pstruNetworkData->szNextHopIp;

	route->gateway = calloc(1, sizeof* route->gateway);
	route->gateway[0] = DEVICE_NWADDRESS(d, in);

	route->interfaceId = calloc(1, sizeof* route->interfaceId);
	route->interfaceId[0] = in;

	route->nextHopId = calloc(1, sizeof* route->nextHopId);
	route->nextHopId[0] = fn_NetSim_Stack_GetDeviceId_asIP(route->nextHop[0], &in);

	return route;
}

/**
This function is called by NetworkStack.dll, whenever the event gets triggered
inside the NetworkStack.dll for IP.It includes NETWORK_OUT,NETWORK_IN and TIMER_EVENT.
*/
_declspec(dllexport) int fn_NetSim_IP_Run()
{
	switch (pstruEventDetails->nEventType)
	{
		case NETWORK_OUT_EVENT:
		{
			ptrIP_FORWARD_ROUTE route = NULL;
			NetSim_PACKET* packet = pstruEventDetails->pPacket;
			NETWORK_LAYER_PROTOCOL nLocalNetworkProtcol;
			nLocalNetworkProtcol = fnGetLocalNetworkProtocol(pstruEventDetails);
			if (nLocalNetworkProtcol)
			{
				fnCallProtocol(nLocalNetworkProtcol);
				return 0;
			}
			if (packet->pstruNetworkData->nTTL == 0)
			{
				//TTL expire drop the packet
				packet->nPacketStatus = PacketStatus_TTL_Expired;
				fn_NetSim_WritePacketTrace(packet);
				fn_NetSim_Packet_FreePacket(packet);
				pstruEventDetails->pPacket = NULL;
				ipMetrics[pstruEventDetails->nDeviceId - 1]->nTTLDrop++;
				return 0;
			}
			//set the time
			packet->pstruNetworkData->dStartTime = pstruEventDetails->dEventTime;
			packet->pstruNetworkData->dArrivalTime = pstruEventDetails->dEventTime;
			//Set the payload
			if (packet->pstruTransportData)
				packet->pstruNetworkData->dPayload = packet->pstruTransportData->dPacketSize;

			//Already got routed
			if (packet->pstruNetworkData->szNextHopIp)
			{
				route = build_route(packet);
				goto PACKET_ROUTED;
			}

			if (packet->pstruNetworkData->szNextHopIp == NULL)
			{
				//First route via static ip route table
				route = fn_NetSim_IP_RoutePacketViaStaticEntry(packet,
															   pstruEventDetails->nDeviceId);
			}

			packet = pstruEventDetails->pPacket;

			if (!packet)
				return -1; //Routing fails

			if (route && route->count)
				goto PACKET_ROUTED;

			//Call NAT
			fn_NetSim_NAT_NetworkOut(pstruEventDetails->nDeviceId, packet);

			// Recall static route
			if (packet->pstruNetworkData->szNextHopIp == NULL)
			{
				//First route via static ip route table
				route = fn_NetSim_IP_RoutePacketViaStaticEntry(packet,
															   pstruEventDetails->nDeviceId);
			}

			packet = pstruEventDetails->pPacket;

			if (!packet)
				return -1; //Routing fails

			if (route && route->count)
				goto PACKET_ROUTED;

			//routing function
			//First route via routing function
			if (DEVICE_NWLAYER(pstruEventDetails->nDeviceId)->routerFunction)
				DEVICE_NWLAYER(pstruEventDetails->nDeviceId)->routerFunction();

			packet = pstruEventDetails->pPacket;
			if (!packet)
				return -1; //Routing fails

			if (packet->pstruNetworkData->szNextHopIp)
			{
				route = build_route(packet);
				goto PACKET_ROUTED;
			}

			//Route via routing protocol
			if (DEVICE_NWLAYER(pstruEventDetails->nDeviceId)->nRoutingProtocolId)
			{
				fnCallProtocol(DEVICE_NWLAYER(pstruEventDetails->nDeviceId)->nRoutingProtocolId);
			}

			packet = pstruEventDetails->pPacket;
			if (!packet)
				return -1; //Routing fails

			if (packet->pstruNetworkData->szNextHopIp)
			{
				route = build_route(packet);
				goto PACKET_ROUTED;
			}

			//IP Routing
			packet = pstruEventDetails->pPacket;
			route = fn_NetSim_IP_RoutePacket(packet,
											 pstruEventDetails->nDeviceId);

			if (!route || !route->count)
				goto ROUTING_FAILS;
			else
				goto PACKET_ROUTED;

		ROUTING_FAILS:
			{
				ipMetrics[pstruEventDetails->nDeviceId - 1]->nPacketDiscarded++;
				//Generate ICMP dst unreachable message
				if (GET_IP_DEVVAR(pstruEventDetails->nDeviceId)->isICMP)
					fn_NetSim_IP_ICMP_GenerateDstUnreachableMsg();
				packet = NULL;
				return -2;
			}

		PACKET_ROUTED:
			if (route)
			{
				NetSim_PACKET* p;
				UINT i;
				//Packet is routed via ip table
				for (i = 0; i < route->count; i++)
				{
					if (i != route->count - 1)
						p = fn_NetSim_Packet_CopyPacket(packet);
					else
						p = packet;

					p->pstruNetworkData->szNextHopIp = route->nextHop[i];
					pass_to_lower_layer(p, route, i);
				}
			}
			else
			{
				//Packet is routed via other protocol
				pass_to_lower_layer(packet, NULL, 0);
			}


		}
		break;
		case NETWORK_IN_EVENT:
		{
			NetSim_PACKET* packet = pstruEventDetails->pPacket;
			if (pstruEventDetails->nInterfaceId && NETWORK->ppstruDeviceList[pstruEventDetails->nDeviceId - 1]->ppstruInterfaceList[pstruEventDetails->nInterfaceId - 1]->nLocalNetworkProtocol)
			{
				//Call the local network protocol
				fnCallProtocol(NETWORK->ppstruDeviceList[pstruEventDetails->nDeviceId - 1]->ppstruInterfaceList[pstruEventDetails->nInterfaceId - 1]->nLocalNetworkProtocol);
			}
			if (pstruEventDetails->pPacket == NULL)
				return 0;
			packet = pstruEventDetails->pPacket;

			NETSIM_IPAddress gateway = packet->pstruNetworkData->szGatewayIP;
			NETSIM_IPAddress my = DEVICE_NWADDRESS(pstruEventDetails->nDeviceId, pstruEventDetails->nInterfaceId);
			NETSIM_IPAddress sub = DEVICE_INTERFACE(pstruEventDetails->nDeviceId, pstruEventDetails->nInterfaceId)->szSubnetMask;
			UINT prefix = DEVICE_INTERFACE(pstruEventDetails->nDeviceId, pstruEventDetails->nInterfaceId)->prefix_len;
			if (!IP_IS_IN_SAME_NETWORK(gateway, my, sub, prefix))
			{
				fn_NetSim_Packet_FreePacket(packet);
				return 0;
			}

			if (wireshark_trace.convert_sim_to_real_packet &&
				!DEVICE_MACLAYER(pstruEventDetails->nDeviceId, pstruEventDetails->nInterfaceId)->isWiresharkWriter)
			{
				wireshark_trace.convert_sim_to_real_packet(packet,
														   wireshark_trace.pcapWriterlist[pstruEventDetails->nDeviceId - 1][pstruEventDetails->nInterfaceId - 1],
														   pstruEventDetails->dEventTime);
			}

			//Decrease the TTL
			packet->pstruNetworkData->nTTL--;

			//Reduce the IP overhead
			packet->pstruNetworkData->dOverhead -= IPV4_HEADER_SIZE;
			packet->pstruNetworkData->dPacketSize -= IPV4_HEADER_SIZE;
			if ((((IP_DEVVAR*)DEVICE_NWLAYER(pstruEventDetails->nDeviceId)->ipVar)->nVPNStatus == VPN_SERVER ||
				((IP_DEVVAR*)DEVICE_NWLAYER(pstruEventDetails->nDeviceId)->ipVar)->nVPNStatus == VPN_CLIENT) &&
				packet->pstruNetworkData->nPacketFlag == PACKET_VPN)
				fn_NetSim_IP_VPN_Run();
			packet = pstruEventDetails->pPacket;
			if (!packet)
				return 0;

			//check for firewall
			if (fn_NetSim_NETWORK_Firewall(pstruEventDetails->nDeviceId,
										   pstruEventDetails->nInterfaceId,
										   pstruEventDetails->pPacket,
										   ACLTYPE_INBOUND) == ACLACTION_DENY)
			{
				ipMetrics[pstruEventDetails->nDeviceId - 1]->nFirewallBlocked++;
				fn_NetSim_Packet_FreePacket(pstruEventDetails->pPacket);
				pstruEventDetails->pPacket = NULL;
				return 0;
			}

			//call routing protocol
			if (DEVICE_NWLAYER(pstruEventDetails->nDeviceId)->nRoutingProtocolId)
				fnCallProtocol(DEVICE_NWLAYER(pstruEventDetails->nDeviceId)->nRoutingProtocolId);
			packet = pstruEventDetails->pPacket;
			if (!packet)
				return 0;

			//Call NAT
			fn_NetSim_NAT_NetworkIn(pstruEventDetails->nDeviceId, packet);

			IP_PROTOCOL_ACTION action = decide_action_for_packet(packet, pstruEventDetails->nDeviceId);

			if (action == ACTION_DROP)
			{
				//Drop packet
				fn_NetSim_Packet_FreePacket(packet);
				pstruEventDetails->pPacket = NULL;
				return 0;
			}

			if (action == ACTION_MOVEUP)
			{
				IP_PROTOCOL_NUMBER num = packet->pstruNetworkData->IPProtocol;
				switch (num)
				{
					case IPPROTOCOL_ICMP:
						process_icmp_packet();
						break;
					case IPPROTOCOL_IGMP:
						process_igmp_packet();
						break;
					case IPPROTOCOL_PIM:
						process_pim_packet();
						break;
					case IPPROTOCOL_DSR:
						//Already processed by routing protocol call. 
						break;
					case IPPROTOCOL_TCP:
					case IPPROTOCOL_UDP:
					default:
						//For legacy code

						//Add transport in event
						pstruEventDetails->dPacketSize = packet->pstruNetworkData->dPacketSize;
						pstruEventDetails->nEventType = TRANSPORT_IN_EVENT;
						pstruEventDetails->nProtocolId = fn_NetSim_Stack_GetTrnspProtocol(pstruEventDetails->nDeviceId, packet);
						pstruEventDetails->nSubEventType = 0;
						pstruEventDetails->szOtherDetails = NULL;
						fnpAddEvent(pstruEventDetails);

						//Increment the received count
						ipMetrics[pstruEventDetails->nDeviceId - 1]->nPacketReceived++;
						break;
				}
			}
			else if (action == ACTION_REROUTE)
			{
				//Add network out event to reroute the packet
				packet->pstruNetworkData->szNextHopIp = NULL;
				packet->pstruNetworkData->szGatewayIP = NULL;

				pstruEventDetails->dPacketSize = packet->pstruNetworkData->dPacketSize;
				pstruEventDetails->nEventType = NETWORK_OUT_EVENT;
				pstruEventDetails->nProtocolId = NW_PROTOCOL_IPV4;
				pstruEventDetails->nSubEventType = 0;
				pstruEventDetails->szOtherDetails = NULL;
				fnpAddEvent(pstruEventDetails);

				//Increment the forwarded count
				ipMetrics[pstruEventDetails->nDeviceId - 1]->nPacketForwarded++;
			}
		}
		break;
		case TIMER_EVENT:
		{
			switch (pstruEventDetails->nSubEventType)
			{
				case EVENT_ICMP_POLL:
					fn_NetSim_IP_ICMP_POLL();
					break;
				case EVENT_ADVERTISE_ROUTER:
					fn_NetSim_IP_ICMP_AdvertiseRouter();
					break;
				case SUBEVENT_JOIN_MULTICAST_GROUP:
					multicast_join_group();
					break;
				case EVENT_IGMP_SendStartupQuery:
				case EVENT_IGMP_SendQuery:
					send_query_msg(pstruEventDetails->nDeviceId,
								   pstruEventDetails->szOtherDetails,
								   pstruEventDetails->dEventTime);
					break;
				case EVENT_IGMP_OtherQuerierPresentTimer:
					igmp_router_processOtherQuerierPresentTime();
					break;
				case EVENT_IGMP_DelayTimer:
					host_send_report();
					break;
				case EVENT_IGMP_GroupMembershipTimer:
					igmp_router_ProcessGroupMembershipTimer();
					break;
				case EVENT_IGMP_Unsolicited_report:
					host_handle_unsolicited_report_timer();
					break;
				case EVENT_PIM_SEND_HELLO:
				case EVENT_PIM_NEIGHBOR_TIMEOUT:
				case EVENT_PIM_ET:
				case EVENT_PIM_JT:
					pim_handle_timer_event();
					break;
				case EVENT_IP_INIT_TABLE:
					iptable_add(IP_WRAPPER_GET(pstruEventDetails->nDeviceId),
								NULL, NULL, 0, NULL, 0, NULL, NULL, 0, NULL);
					break;
				case EVENT_ICMP_SEND_ECHO:
					icmp_send_echo_request();
					break;
				default:
				{
					char error[BUFSIZ];
					sprintf(error, "Unknown sub event %d for IP", pstruEventDetails->nSubEventType);
					fnNetSimError(error);
				}
				break;
			}
		}
		break;
		default:
		{
			char error[BUFSIZ];
			sprintf(error, "Unknown event %d for IP", pstruEventDetails->nEventType);
			fnNetSimError(error);
		}
		break;
	}
	return 0;
}

/**
This function is called by NetworkStack.dll, once simulation end to free the
allocated memory for the network.
*/
_declspec(dllexport) int fn_NetSim_IP_Finish()
{
	NETSIM_ID i;
	for (i = 0; i < NETWORK->nDeviceCount; i++)
	{
		if (DEVICE_NWLAYER(i + 1))
		{
			ptrIP_ROUTINGTABLE table = IP_TABLE_GET(i+1);
			IP_DEVVAR* devVar = NETWORK->ppstruDeviceList[i]->pstruNetworkLayer->ipVar;
			if (devVar)
			{
				fn_NetSim_Firewall_Free(i + 1);
				free(devVar->firewallConfig);
				free(devVar->GatewayIPAddress);
				free(devVar->nGatewayId);
				free(devVar->nGatewayState);
				free(devVar->nInterfaceId);
				freeVPN(devVar->vpn);
				freeDNS(devVar->dnsList);
				igmp_free(i + 1);
				free(devVar);
			}
			while (table)
			{
				LIST_FREE(&table, table);
			}
		}
		free(ipMetrics[i]);
	}
	free(ipMetrics);
	return 1;
}

/**
This function is called by NetworkStack.dll, while writing the event trace
to get the sub event as a string.
*/
_declspec(dllexport) char* fn_NetSim_IP_Trace(NETSIM_ID nSubeventid)
{
	switch (nSubeventid)
	{
	case EVENT_ICMP_POLL:
		return "ICMP_POLL";
	case EVENT_ADVERTISE_ROUTER:
		return "ICMP_Advertise_Router";
	case EVENT_IGMP_DelayTimer:
		return "IGMP_DelayTimer";
	case EVENT_IGMP_GroupMembershipTimer:
		return "IGMP_GroupMembershipTimer";
	case EVENT_IGMP_OtherQuerierPresentTimer:
		return "IGMP_OtherQueierPresentTimer";
	case EVENT_IGMP_SendQuery:
		return "IGMP_SendQuery";
	case EVENT_IGMP_SendStartupQuery:
		return "IGMP_SendStartupQuery";
	case EVENT_IGMP_Unsolicited_report:
		return "IGMP_UnsolicitedReportTimer";
	case EVENT_IP_INIT_TABLE:
		return "IP_INIT_TABLE";
	default:
		return "IP_UNKNOWN_SUBEVENT";
	}
}
/**
This function is called by NetworkStack.dll, while configuring the device
NETWORK layer for IP protocol.
*/
_declspec(dllexport) int fn_NetSim_IP_Configure(void** var)
{
	FILE* fpConfigLog;
	void* xmlNetSimNode;
	NETSIM_ID nDeviceId = 0;
	NETSIM_ID nInterfaceId = 0;
	LAYER_TYPE nLayerType = 0;
	char* szVal;
	IP_DEVVAR* devVar;
	fpConfigLog = var[0];
	xmlNetSimNode = var[2];
	if (var[3])
		nDeviceId = *((NETSIM_ID*)var[3]);
	if (var[4])
		nInterfaceId = *((NETSIM_ID*)var[4]);
	if (var[5])
		nLayerType = *((LAYER_TYPE*)var[5]);
	if (nDeviceId)
	{
		devVar = NETWORK->ppstruDeviceList[nDeviceId - 1]->pstruNetworkLayer->ipVar;
		if (devVar == NULL)
		{
			devVar = calloc(1, sizeof* devVar);
			NETWORK->ppstruDeviceList[nDeviceId - 1]->pstruNetworkLayer->ipVar = devVar;
		}
	}

	if (nDeviceId && nInterfaceId)
	{
		int iptype = 0;
		NetSim_BUFFER* pstruBuffer;
		int nDeviceType;
		nDeviceType = DEVICE_TYPE(nDeviceId);
		if (nDeviceType == ROUTER)
		{
			pstruBuffer = NETWORK->ppstruDeviceList[nDeviceId - 1]->ppstruInterfaceList[nInterfaceId - 1]->pstruAccessInterface->pstruAccessBuffer;
			//Configure the Buffer size
			szVal = fn_NetSim_xmlConfig_GetVal(xmlNetSimNode, "BUFFER_SIZE", 0);
			if (szVal)
				pstruBuffer->dMaxBufferSize = atoi(szVal);
			else
				pstruBuffer->dMaxBufferSize = 8;//8 MB
			free(szVal);

			//Configure the Scheduling type
			szVal = fn_NetSim_xmlConfig_GetVal(xmlNetSimNode, "SCHEDULING_TYPE", 0);
			if (szVal)
			{
				_strupr(szVal);
				if (strcmp(szVal, "FIFO") == 0)
					pstruBuffer->nSchedulingType = SCHEDULING_FIFO;
				else if (strcmp(szVal, "PRIORITY") == 0)
					pstruBuffer->nSchedulingType = SCHEDULING_PRIORITY;
				else if (strcmp(szVal, "ROUND ROBIN") == 0)
					pstruBuffer->nSchedulingType = SCHEDULING_ROUNDROBIN;
				else if (strcmp(szVal, "WFQ") == 0)
					pstruBuffer->nSchedulingType = SCHEDULING_WFQ;
				else
					pstruBuffer->nSchedulingType = SCHEDULING_FIFO;
			}
			else
				pstruBuffer->nSchedulingType = SCHEDULING_FIFO;
			free(szVal);
		}
		if (NETWORK->ppstruDeviceList[nDeviceId - 1]->ppstruInterfaceList[nInterfaceId - 1]->nProtocolId == NW_PROTOCOL_IPV4)
			iptype = 4;
		else if (NETWORK->ppstruDeviceList[nDeviceId - 1]->ppstruInterfaceList[nInterfaceId - 1]->nProtocolId == NW_PROTOCOL_IPV6)
			iptype = 6;
		//Configure the IP address
		szVal = fn_NetSim_xmlConfig_GetVal(xmlNetSimNode, "IP_ADDRESS", 1);
		NETWORK->ppstruDeviceList[nDeviceId - 1]->ppstruInterfaceList[nInterfaceId - 1]->szAddress = STR_TO_IP(szVal, iptype);
		free(szVal);

		if (iptype == 4)
		{
			//Configure the subnet mask
			szVal = fn_NetSim_xmlConfig_GetVal(xmlNetSimNode, "SUBNET_MASK", 1);
			NETWORK->ppstruDeviceList[nDeviceId - 1]->ppstruInterfaceList[nInterfaceId - 1]->szSubnetMask = STR_TO_IP4(szVal);
			free(szVal);
		}
		else if (iptype == 6)
		{
			//Configure the subnet mask
			szVal = fn_NetSim_xmlConfig_GetVal(xmlNetSimNode, "PREFIX_LENGTH", 1);
			NETWORK->ppstruDeviceList[nDeviceId - 1]->ppstruInterfaceList[nInterfaceId - 1]->prefix_len = atoi(szVal);
			free(szVal);
		}
		else
			return -1;

		//Configure the default gateway
		szVal = fn_NetSim_xmlConfig_GetVal(xmlNetSimNode, "DEFAULT_GATEWAY", 0);
		if (szVal)
			NETWORK->ppstruDeviceList[nDeviceId - 1]->ppstruInterfaceList[nInterfaceId - 1]->szDefaultGateWay = STR_TO_IP(szVal, iptype);
		free(szVal);
	}
	else if (nDeviceId)
	{
		getXmlVar(&devVar->isIGMPConfigured, IGMP_STATUS, xmlNetSimNode, 0, _BOOL, IP);

		getXmlVar(&devVar->staticIPTableFile, STATIC_IP_ROUTE, xmlNetSimNode, 0, _STRING, IP);

		if (devVar->isIGMPConfigured)
			igmp_configure(nDeviceId, xmlNetSimNode);

		getXmlVar(&devVar->isPIMConfigured, PIM_STATUS, xmlNetSimNode, 0, _BOOL, IP);
		if (devVar->isPIMConfigured)
			pim_configure(nDeviceId, xmlNetSimNode);

		//Configure the firewall status
		szVal = fn_NetSim_xmlConfig_GetVal(xmlNetSimNode, "ACL_STATUS", 0);
		if (szVal && _strupr(szVal) && !strcmp(szVal, "ENABLE"))
		{
			devVar->isFirewallConfigured = true;
			free(szVal);
			szVal = fn_NetSim_xmlConfig_GetVal(xmlNetSimNode, "ACL_CONFIG_FILE", 1);
			if (szVal)
				devVar->firewallConfig = szVal;
			else
				devVar->isFirewallConfigured = false;
		}
		else
			free(szVal);

		getXmlVar(&devVar->isICMP, ICMP_STATUS, xmlNetSimNode, 0, _BOOL, IP);

		if (devVar->isICMP)
		{
			//Configure the ICMP property
			szVal = fn_NetSim_xmlConfig_GetVal(xmlNetSimNode, "ICMP_CONTINUOUS_POLLING_TIME", 0);
			if (szVal)
			{
				devVar->nICMPPollingTime = atoi(szVal);
				free(szVal);
			}
			szVal = fn_NetSim_xmlConfig_GetVal(xmlNetSimNode, "ROUTER_ADVERTISEMENT", 0);
			if (szVal)
			{
				_strupr(szVal);
				if (!strcmp(szVal, "TRUE"))
					devVar->nRouterAdvertisementFlag = 1;
				free(szVal);
			}
			if (devVar->nRouterAdvertisementFlag)
			{
				szVal = fn_NetSim_xmlConfig_GetVal(xmlNetSimNode, "ROUTER_ADVERTISEMENT_MIN_INTERVAL", 0);
				if (szVal)
				{
					devVar->nRouterAdverMinInterval = atoi(szVal);
					free(szVal);
				}
				szVal = fn_NetSim_xmlConfig_GetVal(xmlNetSimNode, "ROUTER_ADVERTISEMENT_MAX_INTERVAL", 0);
				if (szVal)
				{
					devVar->nRouterAdverMaxInterval = atoi(szVal);
					free(szVal);
				}
				szVal = fn_NetSim_xmlConfig_GetVal(xmlNetSimNode, "ROUTER_ADVERTISEMENT_LIFE_TIME", 0);
				if (szVal)
				{
					devVar->nRouterAdverLifeTime = atoi(szVal);
					free(szVal);
				}
			}
		}

		//Configure the VPN
		szVal = fn_NetSim_xmlConfig_GetVal(xmlNetSimNode, "VPN_STATUS", 0);
		if (szVal)
		{
			_strupr(szVal);
			if (!strcmp(szVal, "SERVER"))
			{
				devVar->nVPNStatus = VPN_SERVER;
				free(szVal);
				szVal = fn_NetSim_xmlConfig_GetVal(xmlNetSimNode, "IP_POOL_START", 1);
				if (szVal)
				{
					devVar->ipPoolStart = STR_TO_IP4(szVal);
				}
				else
					devVar->nVPNStatus = VPN_DISABLE;
				free(szVal);
				szVal = fn_NetSim_xmlConfig_GetVal(xmlNetSimNode, "IP_POOL_END", 1);
				if (szVal)
				{
					devVar->ipPoolEnd = STR_TO_IP4(szVal);
				}
				else
					devVar->nVPNStatus = VPN_DISABLE;
				free(szVal);
				szVal = fn_NetSim_xmlConfig_GetVal(xmlNetSimNode, "IP_POOL_MASK", 1);
				if (szVal)
				{
					devVar->ipPoolMask = STR_TO_IP4(szVal);
				}
				else
					devVar->nVPNStatus = VPN_DISABLE;
				free(szVal);
			}
			else if (!strcmp(szVal, "CLIENT"))
			{
				devVar->nVPNStatus = VPN_CLIENT;
				free(szVal);
				szVal = fn_NetSim_xmlConfig_GetVal(xmlNetSimNode, "SERVER_IP", 1);
				if (szVal)
				{
					devVar->serverIP = STR_TO_IP4(szVal);
				}
				else
					devVar->nVPNStatus = VPN_DISABLE;
				free(szVal);
			}
			else
				free(szVal);
		}
	}
	return 1;
}

/**
This function is to free the memory allocated for packets of this protocol.
*/
_declspec(dllexport) int fn_NetSim_IP_FreePacket(NetSim_PACKET* pstruPacket)
{
	if (pstruPacket->pstruNetworkData->nPacketFlag == PACKET_VPN)
	{
		freeVPNPacket(pstruPacket->pstruNetworkData->Packet_NetworkProtocol);
	}
	switch (pstruPacket->pstruNetworkData->IPProtocol)
	{
	case IPPROTOCOL_IGMP:
		IGMP_FreePacket(pstruPacket);
		break;
	}
	return 1;
}
/**
This function is to copy the IP information from source to the destination.
*/
_declspec(dllexport) int fn_NetSim_IP_CopyPacket(NetSim_PACKET* pstruDestPacket, NetSim_PACKET* pstruSrcPacket)
{
	if (pstruSrcPacket->pstruNetworkData->nPacketFlag == PACKET_VPN)
		pstruDestPacket->pstruNetworkData->Packet_NetworkProtocol = copyVPNPacket(pstruSrcPacket->pstruNetworkData->Packet_NetworkProtocol);
	switch (pstruSrcPacket->pstruNetworkData->IPProtocol)
	{
	case IPPROTOCOL_ICMP:
		ICMP_copyPacket(pstruDestPacket, pstruSrcPacket);
		break;
	case IPPROTOCOL_IGMP:
		copy_igmp_packet(pstruDestPacket, pstruSrcPacket);
		break;
	}
	return 1;
}
/**
This function write the Metrics in Metrics.txt
*/
_declspec(dllexport) int fn_NetSim_IP_Metrics(PMETRICSWRITER metricsWriter)
{
	NETSIM_ID loop;
	PMETRICSNODE menu = init_metrics_node(MetricsNode_Menu, "IP_Metrics", NULL);
	PMETRICSNODE table = init_metrics_node(MetricsNode_Table, "IP_Metrics", NULL);
	add_node_to_menu(menu, table);

	add_table_heading(table, "Device Id", true, 0);
	add_table_heading(table, "Packet sent", true, 0);
	add_table_heading(table, "Packet forwarded", true, 0);
	add_table_heading(table, "Packet received", true, 0);
	add_table_heading(table, "Packet discarded", false, 0);
	add_table_heading(table, "TTL expired", false, 0);
	add_table_heading(table, "Firewall blocked", false, 0);

	for (loop = 0; loop < NETWORK->nDeviceCount; loop++)
	{
		if (ipMetrics[loop])
		{
			add_table_row_formatted(false, table, "%d,%d,%d,%d,%d,%d,%d,",
									ipMetrics[loop]->nDeviceId,
									ipMetrics[loop]->nPacketSent,
									ipMetrics[loop]->nPacketForwarded,
									ipMetrics[loop]->nPacketReceived,
									ipMetrics[loop]->nPacketDiscarded,
									ipMetrics[loop]->nTTLDrop,
									ipMetrics[loop]->nFirewallBlocked);
		}
	}
	write_metrics_node(metricsWriter, WriterPosition_Current, NULL, menu);

	menu = init_metrics_node(MetricsNode_Menu, "IP_Forwarding_Table", NULL);
	for (loop = 0; loop < NETWORK->nDeviceCount; loop++)
	{
		if (NETWORK->ppstruDeviceList[loop]->pstruNetworkLayer &&
			IP_TABLE_GET(loop+1))
		{
			ptrIP_ROUTINGTABLE routeTable = IP_TABLE_GET(loop + 1);

			PMETRICSNODE submenu = init_metrics_node(MetricsNode_Menu, NETWORK->ppstruDeviceList[loop]->szDeviceName, NULL);
			add_node_to_menu(menu, submenu);
			table = init_metrics_node(MetricsNode_Table, NETWORK->ppstruDeviceList[loop]->szDeviceName, NULL);
			add_node_to_menu(submenu, table);

			add_table_heading(table, "Network Destination", true, 0);
			add_table_heading(table, "Netmask/Prefix len", true, 0);
			add_table_heading(table, "Gateway", true, 0);
			add_table_heading(table, "Interface", true, 0);
			add_table_heading(table, "Metrics", false, 0);
			add_table_heading(table, "Type", false, 0);

			while (routeTable)
			{
				char ipStr[_NETSIM_IP_LEN];
				IP_TO_STR(routeTable->networkDestination, ipStr);
				add_table_row_formatted(false, table, "%s,", ipStr);
				if (routeTable->networkDestination->type == 4)
				{
					IP_TO_STR(routeTable->netMask, ipStr);
					add_table_row_formatted(true, table, "%s,", ipStr);
				}
				else if (routeTable->networkDestination->type == 6)
				{
					add_table_row_formatted(true, table, "%d,", routeTable->prefix_len);
				}
				if (routeTable->gateway)
				{
					IP_TO_STR(routeTable->gateway, ipStr);
					add_table_row_formatted(true, table, "%s,", ipStr);
				}
				else
					add_table_row_formatted(true, table, "on-link,");
				
				UINT i;
				char str[BUFSIZ] = "";
				for (i = 0; i < routeTable->interfaceCount; i++)
				{
					strcat(str, routeTable->Interface[i]->str_ip);
					strcat(str, " ");
				}
				add_table_row_formatted(true, table, "%s,", str);

				add_table_row_formatted(true, table, "%d,", routeTable->Metric);

				if (routeTable->szType && *routeTable->szType)
				{
					add_table_row_formatted(true, table, "%s,", routeTable->szType);
				}
				else
				{
					switch (routeTable->type)
					{
					case RoutingType_DEFAULT:
						add_table_row_formatted(true, table, "Default,");
						break;
					case RoutingType_STATIC:
						add_table_row_formatted(true, table, "Static,");
						break;
					default:
						add_table_row_formatted(true, table, "-,");
						break;
					}
				}
				routeTable = LIST_NEXT(routeTable);
			}
		}
	}
	write_metrics_node(metricsWriter, WriterPosition_Current, NULL, menu);
	return 1;
}
int IP_packetTraceFiledFlag[4] = { 0,0,0,0 };
char pszTrace[BUFSIZ];
/**
This function will return the string to write packet trace heading.
*/
_declspec(dllexport) char* fn_NetSim_IP_ConfigPacketTrace(const void* xmlNetSimNode)
{
	char* szStatus;
	*pszTrace = 0;
	szStatus = fn_NetSim_xmlConfigPacketTraceField(xmlNetSimNode, "SOURCE_IP");
	_strupr(szStatus);
	if (!strcmp(szStatus, "ENABLE"))
	{
		IP_packetTraceFiledFlag[0] = 1;
		strcat(pszTrace, "SOURCE_IP,");
	}
	else
		IP_packetTraceFiledFlag[0] = 0;
	free(szStatus);
	szStatus = fn_NetSim_xmlConfigPacketTraceField(xmlNetSimNode, "DESTINATION_IP");
	_strupr(szStatus);
	if (!strcmp(szStatus, "ENABLE"))
	{
		IP_packetTraceFiledFlag[1] = 1;
		strcat(pszTrace, "DESTINATION_IP,");
	}
	else
		IP_packetTraceFiledFlag[1] = 0;
	free(szStatus);
	szStatus = fn_NetSim_xmlConfigPacketTraceField(xmlNetSimNode, "GATEWAY_IP");
	_strupr(szStatus);
	if (!strcmp(szStatus, "ENABLE"))
	{
		IP_packetTraceFiledFlag[2] = 1;
		strcat(pszTrace, "GATEWAY_IP,");
	}
	else
		IP_packetTraceFiledFlag[2] = 0;
	free(szStatus);
	szStatus = fn_NetSim_xmlConfigPacketTraceField(xmlNetSimNode, "NEXT_HOP_IP");
	_strupr(szStatus);
	if (!strcmp(szStatus, "ENABLE"))
	{
		IP_packetTraceFiledFlag[3] = 1;
		strcat(pszTrace, "NEXT_HOP_IP,");
	}
	else
		IP_packetTraceFiledFlag[3] = 0;
	free(szStatus);
	return pszTrace;
}
/**
This function will return the string to write packet trace.
*/
_declspec(dllexport) int fn_NetSim_IP_WritePacketTrace(NetSim_PACKET* pstruPacket, char** ppszTrace)
{
	int i = 0;
	char ip[_NETSIM_IP_LEN];
	if (pstruPacket->pstruNetworkData == NULL)
		return 0;
	*pszTrace = 0;
	*ppszTrace = calloc(BUFSIZ, sizeof(char));
	if (IP_packetTraceFiledFlag[i++] == 1)
	{
		if (pstruPacket->pstruNetworkData->szSourceIP)
			IP_TO_STR(pstruPacket->pstruNetworkData->szSourceIP, ip);
		else
			strcpy(ip, "-");
		sprintf(pszTrace, "%s%s,", pszTrace, ip);
	}
	if (IP_packetTraceFiledFlag[i++] == 1)
	{
		if (pstruPacket->pstruNetworkData->szDestIP)
			IP_TO_STR(pstruPacket->pstruNetworkData->szDestIP, ip);
		else
			strcpy(ip, "-");
		sprintf(pszTrace, "%s%s,", pszTrace, ip);
	}
	if (IP_packetTraceFiledFlag[i++] == 1)
	{
		if (pstruPacket->pstruNetworkData->szGatewayIP)
			IP_TO_STR(pstruPacket->pstruNetworkData->szGatewayIP, ip);
		else
			strcpy(ip, "-");
		sprintf(pszTrace, "%s%s,", pszTrace, ip);
	}
	if (IP_packetTraceFiledFlag[i++] == 1)
	{
		if (pstruPacket->pstruNetworkData->szNextHopIp)
			IP_TO_STR(pstruPacket->pstruNetworkData->szNextHopIp, ip);
		else
			strcpy(ip, "-");
		sprintf(pszTrace, "%s%s,", pszTrace, ip);
	}
	strcpy(*ppszTrace, pszTrace);
	return 1;
}


/** This function is to get the local network protocol */
NETWORK_LAYER_PROTOCOL fnGetLocalNetworkProtocol(NetSim_EVENTDETAILS* pstruEventDetails)
{
	switch (pstruEventDetails->nSubEventType / 100)
	{
	case NW_PROTOCOL_ARP:
		return NW_PROTOCOL_ARP;
	}
	switch (pstruEventDetails->pPacket->nControlDataType / 100)
	{
	case NW_PROTOCOL_ARP:
		return NW_PROTOCOL_ARP;
	}
	return 0;
}

static bool isSameIPForOtherInterface(NETSIM_ID d, NETSIM_ID in)
{
	NETSIM_ID i;
	bool isDefault = false;
	bool isFound = false;
	
	if (DEVICE_INTERFACE(d, in)->szDefaultGateWay)
		isDefault = true;

	for (i = 0; i < DEVICE(d)->nNumOfInterface; i++)
	{
		if (!IP_COMPARE(DEVICE_NWADDRESS(d, i + 1), DEVICE_NWADDRESS(d, in)))
		{
			if (in > i + 1)
				isFound = true;
			
			if (DEVICE_INTERFACE(d, i + 1)->szDefaultGateWay)
			{
				if (!isDefault)
					return true;
				else if (in <= i + 1)
					return false;
				else
					return true;
			}
		}
	}
	return isFound;
}

static void add_default_ip_table_entry(NETSIM_ID d)
{
	NETSIM_ID i;

	if (!DEVICE_NWLAYER(d))
		return; //Why i am called.

	for (i = 1; i <= DEVICE(d)->nNumOfInterface; i++)
	{
		NETSIM_IPAddress dest;
		NETSIM_IPAddress mask = NULL;
		NETSIM_IPAddress gate;
		UINT pre = 0;

		IP_DEVVAR* devVar = DEVICE_NWLAYER(d)->ipVar;
		NETSIM_IPAddress ip = DEVICE_NWADDRESS(d, i);
		NETSIM_IPAddress subnet = DEVICE_INTERFACE(d, i)->szSubnetMask;
		NETSIM_IPAddress gateway = DEVICE_INTERFACE(d, i)->szDefaultGateWay;
		UINT prefix = DEVICE_INTERFACE(d, i)->prefix_len;

		if (isSameIPForOtherInterface(d, i))
			continue;

		iptable_add(IP_WRAPPER_GET(d),
					IP_NETWORK_ADDRESS(ip, subnet, prefix),
					subnet,
					prefix,
					on_link,
					1,
					&ip,
					&i,
					ONLINK_METRIC,
					"LOCAL");

		if (gateway && IP_COMPARE(ip, gateway))
		{
			if (ip->type == 4)
			{
				mask = STR_TO_IP4("0.0.0.0");
				dest = STR_TO_IP4("0.0.0.0");
			}
			else if (ip->type == 6)
			{
				pre = 0;
				dest = STR_TO_IP6("0:0:0:0:0:0:0:0");
			}
			iptable_add(IP_WRAPPER_GET(d),
						dest,
						mask,
						pre,
						gateway,
						1,
						&ip,
						&i,
						DEFAULT_METRIC,
						"DEFAULT");
			devVar->nGatewayCount++;
			devVar->GatewayIPAddress = realloc(devVar->GatewayIPAddress, devVar->nGatewayCount*(sizeof* devVar->GatewayIPAddress));
			devVar->GatewayIPAddress[devVar->nGatewayCount - 1] = gateway;
			devVar->nGatewayState = realloc(devVar->nGatewayState, devVar->nGatewayCount*(sizeof* devVar->nGatewayState));
			devVar->nGatewayState[devVar->nGatewayCount - 1] = GATEWAYSTATE_UP;
			devVar->nInterfaceId = realloc(devVar->nInterfaceId, devVar->nGatewayCount*(sizeof* devVar->nInterfaceId));
			devVar->nInterfaceId[devVar->nGatewayCount - 1] = i;
		}
		if (DEVICE_INTERFACE(d, i)->nInterfaceType != INTERFACE_WAN_ROUTER)
		{
			if (ip->type == 4)
			{
				mask = STR_TO_IP4("255.255.255.255");
				dest = STR_TO_IP4("255.255.255.255");
				pre = 0;
			}
			else if (ip->type == 6)
			{
				dest = STR_TO_IP6("FF00:0:0:0:0:0:0:0");
				mask = NULL;
				pre = 8;
			}
			gate = on_link;
			iptable_add(IP_WRAPPER_GET(d),
						dest,
						mask,
						pre,
						gate,
						1,
						&ip,
						&i,
						DEFAULT_METRIC,
						"BROADCAST");
		}

		//Add entry for Multicast
		if (ip->type == 4)
		{
			mask = STR_TO_IP4("240.0.0.0");
			dest = STR_TO_IP4("224.0.0.0");
			pre = 0;
		}
		else if (ip->type == 6)
		{
			dest = STR_TO_IP6("FFX2:0:0:0:0:0:0:0");
			mask = NULL;
			pre = 16;
		}
		gate = on_link;
		iptable_add(IP_WRAPPER_GET(d),
					dest,
					mask,
					pre,
					gate,
					1,
					&ip,
					&i,
					MULTICAST_METRIC,
					"MULTICAST");

		if (ip->type == 4)
		{
			mask = STR_TO_IP4("255.255.255.255");
			dest = STR_TO_IP4("224.0.0.1");
			pre = 0;
		}
		else if (ip->type == 6)
		{
			dest = STR_TO_IP6("FFX2:0:0:0:0:0:0:1");
			mask = NULL;
			pre = 128;
		}
		gate = on_link;
		iptable_add(IP_WRAPPER_GET(d),
					dest,
					mask,
					pre,
					gate,
					1,
					&ip,
					&i,
					MULTICAST_METRIC,
					"MULTICAST");
	}
}

void ip_write_to_pcap(NetSim_PACKET* packet,
					  NETSIM_ID d,
					  NETSIM_ID i,
					  double time)
{
	if (!wireshark_trace.convert_sim_to_real_packet)
		return; //PCAP writer is not available

	if (DEVICE_MACLAYER(d, i)->isWiresharkWriter)
		return; //PCAP writer is handled by mac layer

	wireshark_trace.convert_sim_to_real_packet(packet,
											   wireshark_trace.pcapWriterlist[d - 1][i - 1],
											   time);
}

static void init_event_to_write(NETSIM_ID d)
{
	NetSim_EVENTDETAILS pe;

	memset(&pe, 0, sizeof pe);
	pe.nDeviceId = d;
	pe.nDeviceType = DEVICE_TYPE(d);
	pe.nEventType = TIMER_EVENT;
	pe.nSubEventType = EVENT_IP_INIT_TABLE;
	pe.nProtocolId = NW_PROTOCOL_IPV4;
	fnpAddEvent(&pe);
}

static void init_ip_anim()
{
	ANIM_HANDLE handle;
	ANIM_HANDLE chandle;
	handle = anim_add_new_menu(NULL, "IP Table", false, false, false, 0, ANIMFILETYPE_TABLE);
	NETSIM_ID i;
	for (i = 0; i < NETWORK->nDeviceCount; i++)
	{
		if (DEVICE_NWLAYER(i + 1))
		{
			chandle = anim_add_new_menu(handle,
										DEVICE_NAME(i + 1),
										false,
										true,
										true,
										0,
										ANIMFILETYPE_TABLE);
			DEVICE_NWLAYER(i + 1)->ipWrapper->handle = chandle;
			init_event_to_write(i + 1);
		}
	}
}
