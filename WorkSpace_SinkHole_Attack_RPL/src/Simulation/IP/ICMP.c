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

/***********************************************************************

Network Working Group                                          J. Postel
Request for Comments:  792                                           ISI
														  September 1981
Updates:  RFCs 777, 760
Updates:  IENs 109, 128

				   INTERNET CONTROL MESSAGE PROTOCOL

						 DARPA INTERNET PROGRAM
						 PROTOCOL SPECIFICATION

*************************************************************************/
#include "main.h"
#include "List.h"
#include "IP.h"
#include "ICMP.h"

typedef struct stru_ICMP_Data
{
	void(*callBack)(NetSim_PACKET*);
	void* payload;
}ICMPDATA, *ptrICMPDATA;
_declspec(dllexport) NetSim_PACKET* fn_NetSim_IP_ICMP_GenerateEchoRequest(NETSIM_ID source,
																		  NETSIM_ID dest,
																		  NETSIM_IPAddress srcIP,
																		  NETSIM_IPAddress destIP,
																		  double time,
																		  void* data,
																		  unsigned int size,
																		  unsigned int ttl,
																		  void(*callback)(NetSim_PACKET*));
/** This function is to initialize the ICMP parameters */
_declspec(dllexport) int fn_NetSim_IP_ICMP_Init()
{
	NETSIM_ID i;
	for(i=0;i<NETWORK->nDeviceCount;i++)
	{
		if(NETWORK->ppstruDeviceList[i]->pstruNetworkLayer)
		{
			IP_DEVVAR* devVar=NETWORK->ppstruDeviceList[i]->pstruNetworkLayer->ipVar;
			
			if (!devVar->isICMP)
				continue; //ICMP is not configured

			if(devVar && devVar->nICMPPollingTime)
			{
				//Create timer event for poll
				memset(pstruEventDetails,0,sizeof* pstruEventDetails);
				pstruEventDetails->dEventTime = devVar->nICMPPollingTime*SECOND;
				pstruEventDetails->nDeviceId = NETWORK->ppstruDeviceList[i]->nDeviceId;
				pstruEventDetails->nDeviceType = NETWORK->ppstruDeviceList[i]->nDeviceType;
				pstruEventDetails->nEventType = TIMER_EVENT;
				pstruEventDetails->nProtocolId = NW_PROTOCOL_IPV4;
				pstruEventDetails->nSubEventType = EVENT_ICMP_POLL;
				fnpAddEvent(pstruEventDetails);
			}
			if(devVar->nRouterAdvertisementFlag)
			{
				//Create timer event for router advertisement
				memset(pstruEventDetails,0,sizeof* pstruEventDetails);
				pstruEventDetails->dEventTime = 0;
				pstruEventDetails->nDeviceId = NETWORK->ppstruDeviceList[i]->nDeviceId;
				pstruEventDetails->nDeviceType = NETWORK->ppstruDeviceList[i]->nDeviceType;
				pstruEventDetails->nEventType = TIMER_EVENT;
				pstruEventDetails->nProtocolId = NW_PROTOCOL_IPV4;
				pstruEventDetails->nSubEventType = EVENT_ADVERTISE_ROUTER;
				fnpAddEvent(pstruEventDetails);
			}
		}
	}
	return 1;
}
/**
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	Operations Manager uses a high-performance, asynchronous ICMP poller. 
	The ICMP poller performs at a consistent rate that is independent of poll response times.
	Operations Manager achieves this using two asynchronous threads: 
	one that sends polls and one that receives polls. Because the send and receive threads 
	operate asynchronously, slow response times or excessive timeouts do not affect the polling rate.
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
*/
_declspec(dllexport) int fn_NetSim_IP_ICMP_POLL()
{
	unsigned int i;
	double time=pstruEventDetails->dEventTime;
	IP_DEVVAR* devVar=NETWORK->ppstruDeviceList[pstruEventDetails->nDeviceId-1]->pstruNetworkLayer->ipVar;
	//Add the next ICMP poll event
	pstruEventDetails->dEventTime += devVar->nICMPPollingTime*SECOND;
	fnpAddEvent(pstruEventDetails);
	for(i=0;i<devVar->nGatewayCount;i++)
	{
		NetSim_PACKET* packet;
		if(devVar->nGatewayState[i] == GATEWAYSTATE_NOTIFICATION_PENDING)
			devVar->nGatewayState[i] = GATEWAYSTATE_DOWN;
		else if(devVar->nGatewayState[i] == GATEWAYSTATE_UP)
			devVar->nGatewayState[i] = GATEWAYSTATE_NOTIFICATION_PENDING;
		//Send ICMP echo request to gateway
		packet = fn_NetSim_IP_ICMP_GenerateEchoRequest(pstruEventDetails->nDeviceId,
													   devVar->nGatewayId[i],
													   NETWORK->ppstruDeviceList[pstruEventDetails->nDeviceId - 1]->ppstruInterfaceList[devVar->nInterfaceId[i] - 1]->szAddress,
													   devVar->GatewayIPAddress[i],
													   pstruEventDetails->dEventTime,
													   NULL,
													   0,
													   1,
													   NULL);
		//Generate Network out event to transmit
		pstruEventDetails->dEventTime=time;
		pstruEventDetails->dPacketSize = fnGetPacketSize(packet);
		pstruEventDetails->nEventType = NETWORK_OUT_EVENT;
		pstruEventDetails->nSubEventType = 0;
		pstruEventDetails->pPacket = packet;
		fnpAddEvent(pstruEventDetails);
	}
	
	return 1;
}
/** This function is used to generate echo request */
_declspec(dllexport) NetSim_PACKET* fn_NetSim_IP_ICMP_GenerateEchoRequest(NETSIM_ID source,
																		  NETSIM_ID dest,
																		  NETSIM_IPAddress srcIP,
																		  NETSIM_IPAddress destIP,
																		  double time,
																		  void* data,
																		  unsigned int size,
																		  unsigned int ttl,
																		  void(*callback)(NetSim_PACKET*))
{
	static UINT64 seqNumber = 1;
	ICMP_ECHO* echo = calloc(1, sizeof* echo);
	NetSim_PACKET* packet = fn_NetSim_Packet_CreatePacket(NETWORK_LAYER);
	add_dest_to_packet(packet, dest);
	packet->nControlDataType = PACKET_ICMP_ECHORequest;
	strcpy(packet->szPacketType, "ICMP_EchoRequest");
	packet->nPacketId = 0;
	packet->nPacketPriority = Priority_Low;
	packet->nPacketType = PacketType_Control;
	packet->nSourceId = source;
	packet->pstruNetworkData->dArrivalTime = time;
	packet->pstruNetworkData->dStartTime = time;
	packet->pstruNetworkData->dEndTime = time;
	packet->pstruNetworkData->dOverhead = 8;
	packet->pstruNetworkData->dPayload = size;
	packet->pstruNetworkData->dPacketSize = 8 + size;
	packet->pstruNetworkData->nNetworkProtocol = NW_PROTOCOL_IPV4;
	packet->pstruNetworkData->nTTL = ttl + 1;
	packet->pstruNetworkData->szDestIP = IP_COPY(destIP);
	packet->pstruNetworkData->szSourceIP = IP_COPY(srcIP);
	packet->pstruNetworkData->Packet_NetworkProtocol = echo;
	packet->pstruNetworkData->IPProtocol = IPPROTOCOL_ICMP;
	echo->Type = 8;
	echo->SequenceNumber = (UINT16)(seqNumber);
	seqNumber++;
	if (data)
	{
		ptrICMPDATA ic = calloc(1, sizeof* ic);
		ic->callBack = callback;
		ic->payload = data;
		echo->Data = ic;
	}
	return packet;
}

/// This function is to process the echo request.
_declspec(dllexport) int fn_NetSim_IP_ICMP_EchoRequest()
{
	//generate echo reply packet
	NetSim_PACKET* request = pstruEventDetails->pPacket;
	NetSim_PACKET* reply = fn_NetSim_Packet_CreatePacket(NETWORK_LAYER);
	ICMP_ECHO* echo = calloc(1,sizeof* echo);
	reply->nControlDataType = PACKET_ICMP_ECHOReply;
	strcpy(reply->szPacketType, "ICMP_EchoReply");
	add_dest_to_packet(reply, request->nSourceId);
	reply->nPacketType = PacketType_Control;
	reply->nSourceId = pstruEventDetails->nDeviceId;
	reply->pstruNetworkData->dArrivalTime = pstruEventDetails->dEventTime;
	reply->pstruNetworkData->dEndTime = pstruEventDetails->dEventTime;
	reply->pstruNetworkData->dOverhead = 8;
	reply->pstruNetworkData->dPayload = request->pstruNetworkData->dPayload;
	reply->pstruNetworkData->dPacketSize = 8+request->pstruNetworkData->dPayload;
	reply->pstruNetworkData->dStartTime = pstruEventDetails->dEventTime;
	reply->pstruNetworkData->nNetworkProtocol = NW_PROTOCOL_IPV4;
	reply->pstruNetworkData->nTTL = 255;
	reply->pstruNetworkData->Packet_NetworkProtocol = echo;
	reply->pstruNetworkData->szDestIP=IP_COPY(request->pstruNetworkData->szSourceIP);
	reply->pstruNetworkData->szSourceIP=IP_COPY(request->pstruNetworkData->szDestIP);
	reply->pstruNetworkData->IPProtocol = IPPROTOCOL_ICMP;
	echo->Type=0;
	echo->Data = ((ICMP_ECHO*)request->pstruNetworkData->Packet_NetworkProtocol)->Data;
	echo->SequenceNumber = ((ICMP_ECHO*)request->pstruNetworkData->Packet_NetworkProtocol)->SequenceNumber;
	pstruEventDetails->pPacket=reply;
	pstruEventDetails->nEventType = NETWORK_OUT_EVENT;
	fnpAddEvent(pstruEventDetails);
	//Free the request packet
	fn_NetSim_Packet_FreePacket(request);
	return 1;
}

/// The data received in the echo message must be returned in the echo reply message.
_declspec(dllexport) int fn_NetSim_IP_ICMP_EchoReply()
{
	IP_DEVVAR* devVar = DEVICE_NWLAYER(pstruEventDetails->nDeviceId)->ipVar;
	unsigned int i;
	for(i=0;i<devVar->nGatewayCount;i++)
	{
		if(!IP_COMPARE(devVar->GatewayIPAddress[i],pstruEventDetails->pPacket->pstruNetworkData->szSourceIP))
		{
			devVar->nGatewayState[i] = GATEWAYSTATE_UP;
			break;
		}
	}
	ICMP_ECHO* echo = pstruEventDetails->pPacket->pstruNetworkData->Packet_NetworkProtocol;
	if (echo->Data)
	{
		ptrICMPDATA ic = echo->Data;
		if (ic->callBack)
			ic->callBack(pstruEventDetails->pPacket);
	}
	//free the reply packet
	fn_NetSim_Packet_FreePacket(pstruEventDetails->pPacket);
	pstruEventDetails->pPacket = NULL;
	return 1;
}
/** This function is to check the gateway state */
_declspec(dllexport) int ICMP_CHECKSTATE(NETSIM_IPAddress ip)
{
	IP_DEVVAR* devVar = DEVICE_NWLAYER(pstruEventDetails->nDeviceId)->ipVar;
	unsigned int i;
	for(i=0;ip && i<devVar->nGatewayCount;i++)
		if(!IP_COMPARE(devVar->GatewayIPAddress[i],ip))
		{
			if(devVar->nGatewayState[i] == GATEWAYSTATE_DOWN)
				return 0;
			break;
		}
		return 1;
}
unsigned long advertiseseed1=12345678;
unsigned long advertiseseed2=23456789;
/**
   The ICMP router discovery messages are called "Router Advertisements"
   and "Router Solicitations".  Each router periodically multicasts a
   Router Advertisement from each of its multicast interfaces,
   announcing the IP address(es) of that interface.  Hosts discover the
   addresses of their neighboring routers simply by listening for
   advertisements.  When a host attached to a multicast link starts up,
   it may multicast a Router Solicitation to ask for immediate
   advertisements, rather than waiting for the next periodic ones to
   arrive; if (and only if) no advertisements are forthcoming, the host
   may retransmit the solicitation a small number of times, but then
   must desist from sending any more solicitations.  Any routers that
   subsequently start up, or that were not discovered because of packet
   loss or temporary link partitioning, are eventually discovered by
   reception of their periodic (unsolicited) advertisements.  (Links
   that suffer high packet loss rates or frequent partitioning are
   accommodated by increasing the rate of advertisements, rather than
   increasing the number of solicitations that hosts are permitted to
   send.)
 */
_declspec(dllexport) int fn_NetSim_IP_ICMP_AdvertiseRouter()
{
	ICMP_RouterAdvertisement* adver=calloc(1,sizeof* adver);
	double time=pstruEventDetails->dEventTime;
	NetSim_PACKET* packet;
	NETSIM_ID nDeviceId=pstruEventDetails->nDeviceId;
	NETSIM_ID i;
	IP_DEVVAR* devVar = DEVICE_NWLAYER(nDeviceId)->ipVar;
	//Add next event for router advertisement
	pstruEventDetails->dEventTime += (fn_NetSim_Utilities_GenerateRandomNo(&advertiseseed1,&advertiseseed2)/NETSIM_RAND_MAX*(devVar->nRouterAdverMaxInterval-devVar->nRouterAdverMinInterval)+devVar->nRouterAdverMinInterval)*SECOND;
	fnpAddEvent(pstruEventDetails);
	//Generate router advertisement
	packet = fn_NetSim_Packet_CreatePacket(NETWORK_LAYER);
	packet->dEventTime = time;
	packet->nControlDataType = PACKET_ROUTER_ADVERTISEMENT;
	strcpy(packet->szPacketType, "ICMP_RouterAdvertisement");
	add_dest_to_packet(packet, 0);
	packet->nPacketType = PacketType_Control;
	packet->nReceiverId=0;
	packet->nSourceId=pstruEventDetails->nDeviceId;
	packet->nTransmitterId=pstruEventDetails->nDeviceId;
	packet->pstruNetworkData->dArrivalTime =time;
	packet->pstruNetworkData->dEndTime=time;
	packet->pstruNetworkData->dStartTime=time;
	packet->pstruNetworkData->dOverhead=16;
	packet->pstruNetworkData->dPacketSize=16;
	packet->pstruNetworkData->dPayload=0;
	packet->pstruNetworkData->nNetworkProtocol=NW_PROTOCOL_IPV4;
	packet->pstruNetworkData->nTTL=2;
	packet->pstruNetworkData->szDestIP=STR_TO_IP4("255.255.255.255");
	packet->pstruNetworkData->Packet_NetworkProtocol=adver;
	packet->pstruNetworkData->IPProtocol = IPPROTOCOL_ICMP;
	adver->Type=9;
	adver->AddrEntrySize=2;
	adver->Lifetime = devVar->nRouterAdverLifeTime;
	//count the num of address
	for(i=0;i<NETWORK->ppstruDeviceList[nDeviceId-1]->nNumOfInterface;i++)
	{
		if(NETWORK->ppstruDeviceList[nDeviceId-1]->ppstruInterfaceList[i])
		{
			if(NETWORK->ppstruDeviceList[nDeviceId-1]->ppstruInterfaceList[i]->nInterfaceType && (NETWORK->ppstruDeviceList[nDeviceId-1]->ppstruInterfaceList[i]->nInterfaceType != INTERFACE_WAN_ROUTER && NETWORK->ppstruDeviceList[nDeviceId-1]->ppstruInterfaceList[i]->nInterfaceType != INTERFACE_VIRTUAL))
			{
				adver->NumAddrs++;
				adver->RouterAddress = realloc(adver->RouterAddress,(sizeof* adver->RouterAddress)*adver->NumAddrs);
				adver->RouterAddress[adver->NumAddrs-1] = IP_COPY(DEVICE_NWADDRESS(nDeviceId,i+1));
			}
		}
	}
	for(i=0;i<NETWORK->ppstruDeviceList[nDeviceId-1]->nNumOfInterface;i++)
	{
		if(NETWORK->ppstruDeviceList[nDeviceId-1]->ppstruInterfaceList[i])
		{
			if(NETWORK->ppstruDeviceList[nDeviceId-1]->ppstruInterfaceList[i]->nInterfaceType && (NETWORK->ppstruDeviceList[nDeviceId-1]->ppstruInterfaceList[i]->nInterfaceType != INTERFACE_WAN_ROUTER && NETWORK->ppstruDeviceList[nDeviceId-1]->ppstruInterfaceList[i]->nInterfaceType != INTERFACE_VIRTUAL))
			{
				NetSim_PACKET* temp=fn_NetSim_Packet_CopyPacket(packet);
				//Create network out event to transmit
				temp->pstruNetworkData->szGatewayIP = IP_COPY(DEVICE_NWADDRESS(nDeviceId,i+1));
				temp->pstruNetworkData->szSourceIP =  IP_COPY(DEVICE_NWADDRESS(nDeviceId,i+1));
				temp->pstruNetworkData->szNextHopIp = temp->pstruNetworkData->szDestIP;
				pstruEventDetails->dEventTime=time;
				pstruEventDetails->nInterfaceId=i+1;
				pstruEventDetails->dPacketSize=16;
				pstruEventDetails->nEventType=NETWORK_OUT_EVENT;
				pstruEventDetails->nSubEventType=0;
				pstruEventDetails->pPacket=temp;
				fnpAddEvent(pstruEventDetails);
			}
		}
	}
	return 1;
}
/**
   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   The router discovery messages do not constitute a routing protocol:
   they enable hosts to discover the existence of neighboring routers,
   but not which router is best to reach a particular destination.  If a
   host chooses a poor first-hop router for a particular destination, it
   should receive an ICMP Redirect from that router, identifying a
   better one.
   A Router Advertisement includes a "preference level" for each
   advertised router address.  When a host must choose a default router
   address (i.e., when, for a particular destination, the host has not
   been redirected or configured to use a specific router address), it
   is expected to choose from those router addresses that have the
   highest preference level.
   A Router Advertisement also includes a "lifetime" field, specifying
   the maximum length of time that the advertised addresses are to be
   considered as valid router addresses by hosts, in the absence of
   further advertisements.  This is used to ensure that hosts eventually
   forget about routers that fail, become unreachable, or stop acting as
   routers.
   The default advertising rate is once every 7 to 10 minutes, and the
   default lifetime is 30 minutes.
   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
*/
_declspec(dllexport) int fn_NetSim_IP_ICMP_ProcessRouterAdvertisement()
{
	int flag=0;
	NETSIM_ID nDeviceId=pstruEventDetails->nDeviceId;
	ptrIP_ROUTINGTABLE table = IP_TABLE_GET(nDeviceId);
	NetSim_PACKET* packet = pstruEventDetails->pPacket;
	ICMP_RouterAdvertisement* adver=PACKET_NWPROTOCOLDATA(packet);
	//Get the source IP
	NETSIM_IPAddress src=PACKET_NWDATA(packet)->szSourceIP;	
	NETSIM_IPAddress ip=STR_TO_IP4("0.0.0.0");
	while(table)
	{
		if(table->gateway)
		if(!IP_COMPARE(src,table->gateway) && !IP_COMPARE(table->networkDestination,ip) && !IP_COMPARE(table->netMask,ip))
		{
			//entry found
			flag=1;
			break;
		}
		table=LIST_NEXT(table);
	}
	if(!table)
	{
		//Create new entry
		iptable_add(IP_WRAPPER_GET(nDeviceId),
					ip, ip, 0, src, 1, &DEVICE_NWADDRESS(nDeviceId, pstruEventDetails->nInterfaceId),
					&pstruEventDetails->nInterfaceId, DEFAULT_METRIC, "ICMP");

	}
	fn_NetSim_Packet_FreePacket(packet);
	pstruEventDetails->pPacket = NULL;
	return 1;
}
/**
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	If, according to the information in the gateway's routing tables,
	  the network specified in the internet destination field of a
	  datagram is unreachable, e.g., the distance to the network is
	  infinity, the gateway sends a destination unreachable message to
	  the internet source host of the datagram.  In addition, in some
	  networks, the gateway may be able to determine if the internet
	  destination host is unreachable.  Gateways in these networks may
	  send destination unreachable messages to the source host when the
	  destination host is unreachable.

	  If, in the destination host, the IP module cannot deliver the
	  datagram  because the indicated protocol module or process port is
	  not active, the destination host may send a destination
	  unreachable message to the source host.

	  Another case is when a datagram must be fragmented to be forwarded
	  by a gateway yet the Don't Fragment flag is on.  In this case the
	  gateway must discard the datagram and return a destination
	  unreachable message.
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
*/
_declspec(dllexport) int fn_NetSim_IP_ICMP_GenerateDstUnreachableMsg()
{
	NetSim_PACKET* orgPacket=pstruEventDetails->pPacket;
	if (isMulticastPacket(orgPacket))
		return -1;

	NetSim_PACKET* packet = fn_NetSim_Packet_CreatePacket(NETWORK_LAYER);
	ICMP_DestinationUnreachableMessage* message=calloc(1,sizeof* message);
	message->Type=3;
	message->code=1;//host unreachable
	message->InternetHeader=orgPacket;
	packet->pstruNetworkData->szDestIP = IP_COPY(orgPacket->pstruNetworkData->szSourceIP);
	packet->nControlDataType = PACKET_ICMP_DstUnreachableMsg;
	strcpy(packet->szPacketType, "ICMP_DstUnreachableMsg");
	add_dest_to_packet(packet, orgPacket->nSourceId);
	packet->nPacketType=PacketType_Control;
	packet->nSourceId=pstruEventDetails->nDeviceId;
	packet->nTransmitterId=pstruEventDetails->nDeviceId;
	packet->pstruNetworkData->dArrivalTime=pstruEventDetails->dEventTime;
	packet->pstruNetworkData->dEndTime=pstruEventDetails->dEventTime;
	packet->pstruNetworkData->dStartTime=pstruEventDetails->dEventTime;
	packet->pstruNetworkData->dOverhead=24+IPV4_HEADER_SIZE;
	packet->pstruNetworkData->dPacketSize=24+IPV4_HEADER_SIZE;
	packet->pstruNetworkData->dPayload=0;
	packet->pstruNetworkData->nNetworkProtocol=NW_PROTOCOL_IPV4;
	packet->pstruNetworkData->nTTL=255;
	packet->pstruNetworkData->Packet_NetworkProtocol=message;
	packet->pstruNetworkData->szSourceIP=fn_NetSim_Stack_GetFirstIPAddressAsId(pstruEventDetails->nDeviceId,0);
	packet->pstruNetworkData->IPProtocol = IPPROTOCOL_ICMP;
	//Add the network in event
	pstruEventDetails->dPacketSize=24+IPV4_HEADER_SIZE;
	pstruEventDetails->nApplicationId=0;
	pstruEventDetails->nEventType=NETWORK_IN_EVENT;
	pstruEventDetails->nInterfaceId=1;
	pstruEventDetails->nPacketId=0;
	pstruEventDetails->nProtocolId=NW_PROTOCOL_IPV4;
	pstruEventDetails->nSegmentId=0;
	pstruEventDetails->nSubEventType=0;
	pstruEventDetails->pPacket=packet;
	fnpAddEvent(pstruEventDetails);
	return 1;
}
/**
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	If, according to the information in the gateway's routing tables,
	  the network specified in the internet destination field of a
	  datagram is unreachable, e.g., the distance to the network is
	  infinity, the gateway sends a destination unreachable message to
	  the internet source host of the datagram.  In addition, in some
	  networks, the gateway may be able to determine if the internet
	  destination host is unreachable.  Gateways in these networks may
	  send destination unreachable messages to the source host when the
	  destination host is unreachable.

	  If, in the destination host, the IP module cannot deliver the
	  datagram  because the indicated protocol module or process port is
	  not active, the destination host may send a destination
	  unreachable message to the source host.

	  Another case is when a datagram must be fragmented to be forwarded
	  by a gateway yet the Don't Fragment flag is on.  In this case the
	  gateway must discard the datagram and return a destination
	  unreachable message.
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
*/
_declspec(dllexport) int fn_NetSim_IP_ICMP_ProcessDestUnreachableMsg()
{
	NetSim_PACKET* packet = pstruEventDetails->pPacket;
	ICMP_DestinationUnreachableMessage* message=packet->pstruNetworkData->Packet_NetworkProtocol;
	
	NetSim_PACKET* p = message->InternetHeader;
	iptable_delete(IP_WRAPPER_GET(pstruEventDetails->nDeviceId),
				   p->pstruNetworkData->szDestIP, p->pstruNetworkData->szSourceIP);

	fn_NetSim_Stack_CallICMPErrorFun(message->InternetHeader,pstruEventDetails->nDeviceId,3);
	if(get_first_dest_from_packet(pstruEventDetails->pPacket) == pstruEventDetails->nDeviceId)
	{
		NetSim_PACKET* p=message->InternetHeader;
		pstruEventDetails->pPacket=NULL;
		fn_NetSim_Packet_FreePacket(p);
		free(message);
		fn_NetSim_Packet_FreePacket(packet);
	}
	return 0;
}

void ICMP_copyPacket(NetSim_PACKET* d, NetSim_PACKET* s)
{
	switch(s->nControlDataType)
	{
	case PACKET_ICMP_DstUnreachableMsg:
		{
			ICMP_DestinationUnreachableMessage* sm=(ICMP_DestinationUnreachableMessage*)s->pstruNetworkData->Packet_NetworkProtocol;
			ICMP_DestinationUnreachableMessage* dm = (ICMP_DestinationUnreachableMessage*)calloc(1,sizeof* dm);
			memcpy(dm,sm,sizeof* dm);
			d->pstruNetworkData->Packet_NetworkProtocol=dm;
		}
		break;
	}
}

void process_icmp_packet()
{
	NETSIM_ID d = pstruEventDetails->nDeviceId;
	NetSim_PACKET* packet = pstruEventDetails->pPacket;

	if (!GET_IP_DEVVAR(d)->isICMP)
	{
		fnNetSimError("ICMP packet %d is arrives to device %d from device %d.\n ICMP is not configured in this device.\n",
					  packet->nControlDataType,
					  d,
					  packet->nSourceId);
		return;
	}

	switch (packet->nControlDataType)
	{
	case PACKET_ICMP_ECHORequest:
		fn_NetSim_IP_ICMP_EchoRequest();
		break;
	case PACKET_ICMP_ECHOReply:
		fn_NetSim_IP_ICMP_EchoReply();
		break;
	case PACKET_ROUTER_ADVERTISEMENT:
		fn_NetSim_IP_ICMP_ProcessRouterAdvertisement();
		break;
	case PACKET_ICMP_DstUnreachableMsg:
		fn_NetSim_IP_ICMP_ProcessDestUnreachableMsg();
		break;
	default:
		fnNetSimError("Unknown ICMP packet %d in %s\n",
					  packet->nControlDataType,
					  __FUNCTION__);
		break;
	}
}

typedef struct stru_pingHandle
{
	NETSIM_ID src;
	NETSIM_ID dest;
	NETSIM_IPAddress srcIP;
	NETSIM_IPAddress destIP;
	UINT count;
	bool(*ResponseHandler)(void* arg, char* msg, bool isMore);
	double echoSendTime;
	UINT currentCount;
	UINT replyRecvCount;
	UINT retryCount;
	UINT16 seqNumber;
	void* arg;
}PINGHANDLER, *ptrPINGHANDLER;

void IP_find_best_IP(NETSIM_ID s, NETSIM_ID d,
					 NETSIM_IPAddress* sIP,
					 NETSIM_IPAddress* dIP)
{
	int prev = 0;
	NETSIM_ID si;
	NETSIM_ID di;
	NETSIM_ID i, j;
	*sIP = DEVICE_NWADDRESS(s, 1);
	*dIP = DEVICE_NWADDRESS(d, 1);

	for (si = 1; si <= DEVICE(s)->nNumOfInterface; si++)
	{
		NETSIM_IPAddress sip = DEVICE_NWADDRESS(s, si);
		if (DEVICE_INTERFACE(s, si)->nInterfaceType == INTERFACE_WAN_ROUTER)
			*sIP = sip;
		for (di = 1; di <= DEVICE(d)->nNumOfInterface; di++)
		{
			NETSIM_IPAddress dip = DEVICE_NWADDRESS(d, di);
			if (DEVICE_INTERFACE(d, di)->nInterfaceType == INTERFACE_WAN_ROUTER)
				*dIP = dip;
			NETSIM_IPAddress dnw = IP_NETWORK_ADDRESS_IPV4(dip, DEVICE_SUBNETMASK(d, di));
			NETSIM_IPAddress snw = IP_NETWORK_ADDRESS_IPV4(sip, DEVICE_SUBNETMASK(s, si));
			if (!IP_COMPARE4(dnw, snw))
			{
				*sIP = sip;
				*dIP = dip;
				return;
			}
		}
	}
}

void replyRecevied(NetSim_PACKET* packet)
{
	ICMP_ECHO* echo = packet->pstruNetworkData->Packet_NetworkProtocol;
	ptrICMPDATA data = echo->Data;
	ptrPINGHANDLER ping = data->payload;
	if (echo->SequenceNumber == ping->seqNumber)
	{
		ping->replyRecvCount++;
		ping->retryCount = 0;
		char msg[BUFSIZ];
		sprintf(msg, "Reply from %s: bytes %d time=%dus TTL=%d\n",
				packet->pstruNetworkData->szSourceIP->str_ip,
				(int)packet->pstruNetworkData->dPayload,
				(int)(pstruEventDetails->dEventTime - ping->echoSendTime),
				MAX_TTL);
		ping->ResponseHandler(ping->arg, msg, ping->count != ping->currentCount);
	}
}

_declspec(dllexport) void* ICMP_StartPingRequest(NETSIM_ID src,
												 NETSIM_ID dest,
												 UINT count,
												 bool(*resp)(void*, char*, bool),
												void* arg)
{
	ptrPINGHANDLER handle = calloc(1, sizeof* handle);
	handle->count = count;
	handle->dest = dest;
	handle->ResponseHandler = resp;
	handle->src = src;
	handle->arg = arg;
	IP_find_best_IP(src,
					dest,
					&handle->srcIP,
					&handle->destIP);

	//Start timer event to send ping
	NetSim_EVENTDETAILS pevent;
	memset(&pevent, 0, sizeof pevent);
	pevent.dEventTime = ldEventTime + 1000;
	pevent.nDeviceId = src;
	pevent.nDeviceType = DEVICE_TYPE(src);
	pevent.nEventType = TIMER_EVENT;
	pevent.nProtocolId = NW_PROTOCOL_IPV4;
	pevent.nSubEventType = EVENT_ICMP_SEND_ECHO;
	pevent.szOtherDetails = handle;
	fnpAddEvent(&pevent);
	return handle;
}

void icmp_send_echo_request()
{
	ptrPINGHANDLER handle = pstruEventDetails->szOtherDetails;
	if (handle->currentCount == handle->replyRecvCount)
		goto SEND_ECHO_REQUEST;
	else
	{
		if (handle->retryCount == ICMP_MAX_RETRY)
		{
			handle->seqNumber = 0;
			handle->replyRecvCount++;
			handle->ResponseHandler(handle->arg, "Request timed out!\n", handle->count != handle->currentCount);
			if (handle->currentCount != handle->count)
				goto SEND_ECHO_REQUEST;
			else
				return;
		}
		else
		{
			handle->retryCount++;
			goto ADD_NEXT_SEND_REQUEST;
		}
	}

SEND_ECHO_REQUEST:
	if (handle->currentCount != handle->count)
	{
		handle->retryCount = 0;
		handle->currentCount++;
		handle->echoSendTime = pstruEventDetails->dEventTime;
		NetSim_PACKET* packet = fn_NetSim_IP_ICMP_GenerateEchoRequest(handle->src,
																	  handle->dest,
																	  handle->srcIP,
																	  handle->destIP,
																	  pstruEventDetails->dEventTime,
																	  handle,
																	  32,
																	  MAX_TTL - 1,
																	  replyRecevied);
		handle->seqNumber = ((ICMP_ECHO*)(packet->pstruNetworkData->Packet_NetworkProtocol))->SequenceNumber;

		NetSim_EVENTDETAILS pevent;
		memset(&pevent, 0, sizeof pevent);
		pevent.dEventTime = pstruEventDetails->dEventTime;
		pevent.dPacketSize = fnGetPacketSize(packet);
		pevent.nDeviceId = pstruEventDetails->nDeviceId;
		pevent.nDeviceType = pstruEventDetails->nDeviceType;
		pevent.nEventType = NETWORK_OUT_EVENT;
		pevent.nProtocolId = NW_PROTOCOL_IPV4;
		pevent.pPacket = packet;
		fnpAddEvent(&pevent);
	}

ADD_NEXT_SEND_REQUEST:
	//Add next send event
	if (handle->currentCount != handle->count + 2)
	{
		pstruEventDetails->dEventTime += ICMP_SEND_TIME;
		fnpAddEvent(pstruEventDetails);
	}
}
