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
#include "VPN.h"
_declspec(dllexport) int fn_NetSim_IP_VPN_GetIPFromServer(NETSIM_IPAddress server,NETSIM_IPAddress* ip,NETSIM_IPAddress* mask,NETSIM_ID nCurrentDeviceId);
NETSIM_IPAddress fn_NetSim_IP_FindWANInterfaceIP(NETSIM_ID ndeviceId);
NETSIM_IPAddress vpn_getVirtualIp(NETSIM_ID ndeviceId);
int vpn_addtable(ptrIP_ROUTINGTABLE* table,NETSIM_ID serverId,NETSIM_IPAddress virtualIp,NETSIM_ID virtualInterface);
/**
	This function is to initialize the VPN(Virtual Private Network).
*/
_declspec(dllexport) int fn_NetSim_IP_VPN_Init()
{
	NETSIM_ID i;
	for(i=0;i<NETWORK->nDeviceCount;i++)
	{
		if(NETWORK->ppstruDeviceList[i]->pstruNetworkLayer)
		{
			IP_DEVVAR* devVar=DEVICE_NWLAYER(i+1)->ipVar;
			if(devVar->nVPNStatus==VPN_SERVER)
			{
				VPN* vpn=devVar->vpn;
				struct stru_NetSim_Interface* newInterface=calloc(1,sizeof* newInterface);
				NETSIM_ID nInteraceId=NETWORK->ppstruDeviceList[i]->nNumOfInterface;
				//Add new virtual interface
				NETWORK->ppstruDeviceList[i]->nNumOfInterface++;
				NETWORK->ppstruDeviceList[i]->ppstruInterfaceList = realloc(NETWORK->ppstruDeviceList[i]->ppstruInterfaceList,
					(NETWORK->ppstruDeviceList[i]->nNumOfInterface*sizeof(struct stru_NetSim_Interface*)));
				NETWORK->ppstruDeviceList[i]->ppstruInterfaceList[nInteraceId]=newInterface;
				newInterface->nInterfaceType=INTERFACE_VIRTUAL;
				newInterface->nInterfaceId=nInteraceId+1;
				newInterface->nProtocolId=NW_PROTOCOL_IPV4;
				newInterface->szAddress=devVar->ipPoolStart;
				newInterface->szSubnetMask=devVar->ipPoolMask;
				newInterface->nLocalNetworkProtocol=PROTOCOL_VPN;
				newInterface->pstruPrevInterface=NETWORK->ppstruDeviceList[i]->ppstruInterfaceList[nInteraceId-1];
				NETWORK->ppstruDeviceList[i]->ppstruInterfaceList[nInteraceId-1]->pstruNextInterface=newInterface;
				NETSIM_ID in = nInteraceId + 1;
				iptable_add(IP_WRAPPER_GET(i + 1),
							IP_NETWORK_ADDRESS_IPV4(newInterface->szAddress, newInterface->szSubnetMask),
							newInterface->szSubnetMask,
							0,
							NULL,
							1,
							&newInterface->szAddress,
							&in,
							VPN_METRIC,
							"VPN");
				if(!vpn)
				{
					vpn=calloc(1,sizeof* vpn);
					devVar->vpn=vpn;
					vpn->LocalIP=calloc(1,sizeof* vpn->LocalIP);
					vpn->LocalIP[0]=IP_COPY(devVar->ipPoolStart);//Server ip
					vpn->InternetIP=calloc(1,sizeof* vpn->InternetIP);
					vpn->InternetIP[0]=fn_NetSim_IP_FindWANInterfaceIP(i+1);
				}

			}
			else if(devVar->nVPNStatus==VPN_CLIENT)
			{
				NETSIM_ID in;
				struct stru_NetSim_Interface* newInterface=calloc(1,sizeof* newInterface);
				NETSIM_ID nInteraceId=NETWORK->ppstruDeviceList[i]->nNumOfInterface;
				//Add new virtual interface
				NETWORK->ppstruDeviceList[i]->nNumOfInterface++;
				NETWORK->ppstruDeviceList[i]->ppstruInterfaceList = realloc(NETWORK->ppstruDeviceList[i]->ppstruInterfaceList,
					(NETWORK->ppstruDeviceList[i]->nNumOfInterface*sizeof(struct stru_NetSim_Interface*)));
				NETWORK->ppstruDeviceList[i]->ppstruInterfaceList[nInteraceId]=newInterface;
				newInterface->nInterfaceType=INTERFACE_VIRTUAL;
				newInterface->nInterfaceId=nInteraceId+1;
				newInterface->nProtocolId=NW_PROTOCOL_IPV4;
				if(!fn_NetSim_IP_VPN_GetIPFromServer(devVar->serverIP,&newInterface->szAddress,&newInterface->szSubnetMask,i+1))
				{
					devVar->nVPNStatus=0;//VPN fails
					continue;
				}
				newInterface->nLocalNetworkProtocol=PROTOCOL_VPN;
				newInterface->pstruPrevInterface=NETWORK->ppstruDeviceList[i]->ppstruInterfaceList[nInteraceId-1];
				NETWORK->ppstruDeviceList[i]->ppstruInterfaceList[nInteraceId-1]->pstruNextInterface=newInterface;
				in = nInteraceId + 1;
				iptable_add(IP_WRAPPER_GET(i + 1),
							IP_NETWORK_ADDRESS_IPV4(newInterface->szAddress, newInterface->szSubnetMask),
							newInterface->szSubnetMask,
							0,
							NULL,
							1,
							&newInterface->szAddress,
							&in,
							VPN_METRIC,
							"VPN");
				iptable_add(IP_WRAPPER_GET(i + 1),
							devVar->serverIP,
							STR_TO_IP4("255.255.255.255"),
							0,
							NULL,
							1,
							&newInterface->szAddress,
							&in,
							1,
							"VPN");
				vpn_addtable(PIP_TABLE_GET(i + 1),
							 fn_NetSim_Stack_GetDeviceId_asIP(devVar->serverIP, &in),
							 newInterface->szAddress,
							 nInteraceId + 1);
			}
		}
	}
	return 1;
}
/**
	This function is to get the ip address from the server.
*/
_declspec(dllexport) int fn_NetSim_IP_VPN_GetIPFromServer(NETSIM_IPAddress server,NETSIM_IPAddress* ip,NETSIM_IPAddress* mask,NETSIM_ID nCurrentDeviceId)
{
	NETSIM_IPAddress ipStart;
	NETSIM_IPAddress ipEnd;
	IP_DEVVAR* devVar;
	NETSIM_IPAddress newip;
	VPN* vpn;
	NETSIM_ID i;
	NETSIM_ID devid=fn_NetSim_Stack_GetDeviceId_asIP(server,&i);
	if(!devid)
	{
		fnNetSimError("%s is not valid ip for any device.Check VPN server ip setting.\n",server);
	}
	devVar = DEVICE_NWLAYER(devid)->ipVar;
	ipStart=devVar->ipPoolStart;
	ipEnd=devVar->ipPoolEnd;
	vpn=devVar->vpn;
	if(!vpn)
	{
		vpn=calloc(1,sizeof* vpn);
		devVar->vpn=vpn;
		vpn->LocalIP=calloc(1,sizeof* vpn->LocalIP);
		vpn->LocalIP[0]=IP_COPY(devVar->ipPoolStart);//Server ip
		vpn->InternetIP=calloc(1,sizeof* vpn->InternetIP);
		vpn->InternetIP[0]=fn_NetSim_IP_FindWANInterfaceIP(devid);
	}
	newip=IP_COPY_FORCE(ipStart);
NEWIP_RECHECK:
	if(newip->type == 4)
	{
		while(newip->IP.IPV4.byte4<ipEnd->IP.IPV4.byte4)
		{
			int flag=0;
			unsigned int i;
			for(i=0;i<=vpn->nConnectedDeviceCount;i++)
			{
				if(!IP_COMPARE(vpn->LocalIP[i],newip))
					flag=1;
			}
			if(!flag)
			{
				DNS* dns;
				vpn->nConnectedDeviceCount++;
				vpn->LocalIP=realloc(vpn->LocalIP,(vpn->nConnectedDeviceCount+1)*(sizeof* vpn->LocalIP));
				vpn->LocalIP[vpn->nConnectedDeviceCount]=newip;
				vpn->InternetIP=realloc(vpn->InternetIP,(vpn->nConnectedDeviceCount+1)*(sizeof* vpn->InternetIP));
				vpn->InternetIP[vpn->nConnectedDeviceCount]=fn_NetSim_Stack_GetFirstIPAddressAsId(nCurrentDeviceId,0);
				*ip=newip;
				*mask=devVar->ipPoolMask;
				dns=DNS_ALLOC();
				dns->deviceId=nCurrentDeviceId;
				dns->ip=newip;
				LIST_ADD_LAST(&(devVar->dnsList),dns);
				return 1;
			}
			newip->IP.IPV4.byte4++;
		}
		newip->IP.IPV4.byte4=ipStart->IP.IPV4.byte4;
		while(newip->IP.IPV4.byte3<ipEnd->IP.IPV4.byte3)
		{
			newip->IP.IPV4.byte3++;
			goto NEWIP_RECHECK;
		}
		newip->IP.IPV4.byte3=ipStart->IP.IPV4.byte3;
		while(newip->IP.IPV4.byte2<ipEnd->IP.IPV4.byte2)
		{
			newip->IP.IPV4.byte2++;
			goto NEWIP_RECHECK;
		}
		newip->IP.IPV4.byte2=ipStart->IP.IPV4.byte2;
		while(newip->IP.IPV4.byte1<ipEnd->IP.IPV4.byte1)
		{
			newip->IP.IPV4.byte1++;
			goto NEWIP_RECHECK;
		}
	}
	else if(newip->type == 6)
	{
#pragma message(__LOC__"fn_NetSim_IP_VPN_GetIPFromServer needs to be implemented for IPV6")
	}
	return 0;
}
/**
	This function is to trigger the events of VPN, which includes NETWORK_OUT and NETWORK_IN events.
*/
_declspec(dllexport) int fn_NetSim_IP_VPN_Run()
{
	switch(pstruEventDetails->nEventType)
	{
	case NETWORK_OUT_EVENT:
		{
			IP_DEVVAR* devVar=DEVICE_NWLAYER(pstruEventDetails->nDeviceId)->ipVar;
			VPN* vpn=devVar->vpn;
			NetSim_PACKET* packet=pstruEventDetails->pPacket;
			VPN_PACKET* vpnPacket=calloc(1,sizeof* vpnPacket);
			vpnPacket->destIP=packet->pstruNetworkData->szDestIP;
			vpnPacket->ipVar=packet->pstruNetworkData->Packet_NetworkProtocol;
			vpnPacket->sourceIP=packet->pstruNetworkData->szSourceIP;
			vpnPacket->nPacketType = packet->nPacketType;
			vpnPacket->nControlPacketType = packet->nControlDataType;
			packet->nPacketType = PacketType_Control;
			packet->nControlDataType = PACKET_VPN;
			strcpy(packet->szPacketType, "VPN_Packet");
			packet->pstruNetworkData->Packet_NetworkProtocol=vpnPacket;
			packet->pstruNetworkData->nPacketFlag=PACKET_VPN;
			switch(devVar->nVPNStatus)
			{
			case VPN_SERVER:
				{
					unsigned int i;
					packet->pstruNetworkData->szSourceIP=vpn->InternetIP[0];
					for(i=0;i<=vpn->nConnectedDeviceCount;i++)
					{
						if(!IP_COMPARE(vpn->LocalIP[i],packet->pstruNetworkData->szDestIP))
						{
							packet->pstruNetworkData->szDestIP=vpn->InternetIP[i];
							break;
						}
					}
				}
				break;
			case VPN_CLIENT:
				{
					vpnPacket->sourceIP=vpn_getVirtualIp(pstruEventDetails->nDeviceId);
					packet->pstruNetworkData->szDestIP=devVar->serverIP;
					packet->pstruNetworkData->szSourceIP=fn_NetSim_Stack_GetFirstIPAddressAsId(pstruEventDetails->nDeviceId,0);
				}
				break;
			default:
				fnNetSimError("Unknown Vpn status");
				break;
			}
			packet->pstruNetworkData->szGatewayIP=packet->pstruNetworkData->szSourceIP;
			packet->pstruNetworkData->szNextHopIp=NULL;
			pstruEventDetails->nInterfaceId=0;
			fnpAddEvent(pstruEventDetails);
			pstruEventDetails->pPacket=NULL;
		}
		break;
	case NETWORK_IN_EVENT:
		{
			NetSim_PACKET* packet = pstruEventDetails->pPacket;
			VPN_PACKET* vpnPacket=packet->pstruNetworkData->Packet_NetworkProtocol;
			IP_DEVVAR* devVar=DEVICE_NWLAYER(pstruEventDetails->nDeviceId)->ipVar;
			VPN* vpn=devVar->vpn;
			if(devVar->nVPNStatus==VPN_SERVER && !IP_COMPARE(packet->pstruNetworkData->szDestIP,vpn->InternetIP[0]))
			{
				packet->nPacketType=vpnPacket->nPacketType;
				packet->nControlDataType=vpnPacket->nControlPacketType;
				packet->pstruNetworkData->szSourceIP=vpnPacket->sourceIP;
				packet->pstruNetworkData->szDestIP=vpnPacket->destIP;
				packet->pstruNetworkData->Packet_NetworkProtocol=vpnPacket->ipVar;
				packet->pstruNetworkData->nPacketFlag=0;
			}
			else if(devVar->nVPNStatus == VPN_CLIENT && !IP_COMPARE(packet->pstruNetworkData->szSourceIP,devVar->serverIP))
			{
				packet->nPacketType=vpnPacket->nPacketType;
				packet->nControlDataType=vpnPacket->nControlPacketType;
				packet->pstruNetworkData->szDestIP=getVirtualIP(pstruEventDetails->nDeviceId);
				packet->pstruNetworkData->Packet_NetworkProtocol=vpnPacket->ipVar;
				packet->pstruNetworkData->nPacketFlag=0;
			}
			free(vpnPacket);
		}
		break;
	default:
		fnNetSimError("Unknown event type for VPN");
		break;
	}
	return 1;
}
/**
	This function is to find the WLAN interface IP address.
*/
NETSIM_IPAddress fn_NetSim_IP_FindWANInterfaceIP(NETSIM_ID ndeviceId)
{
	NETSIM_ID i;
	for(i=0;i<NETWORK->ppstruDeviceList[ndeviceId-1]->nNumOfInterface;i++)
	{
		if(DEVICE_INTERFACE(ndeviceId,i+1)->nInterfaceType==INTERFACE_WAN_ROUTER)
		{
			return DEVICE_INTERFACE(ndeviceId,i+1)->szAddress;
		}
	}
	return fn_NetSim_Stack_GetFirstIPAddressAsId(ndeviceId,0);
}
NETSIM_IPAddress getVirtualIP(NETSIM_ID ndeviceId)
{
	NETSIM_ID i;
	for(i=0;i<NETWORK->ppstruDeviceList[ndeviceId-1]->nNumOfInterface;i++)
	{
		if(DEVICE_INTERFACE(ndeviceId,i+1)->nInterfaceType==INTERFACE_VIRTUAL)
		{
			return DEVICE_INTERFACE(ndeviceId,i+1)->szAddress;
		}
	}
	return NULL;
}
int vpn_addtable(ptrIP_WRAPPER wrapper,NETSIM_ID serverId,NETSIM_IPAddress virtualIp,NETSIM_ID virtualInterface)
{
	NETSIM_ID i;
	for(i=0;i<NETWORK->ppstruDeviceList[serverId-1]->nNumOfInterface;i++)
	{
		if(DEVICE_INTERFACE(serverId,i+1)->nInterfaceType!=INTERFACE_WAN_ROUTER && DEVICE_INTERFACE(serverId,i+1)->nInterfaceType!=INTERFACE_VIRTUAL && DEVICE_INTERFACE(serverId,i+1)->szAddress)
		{
			iptable_add(wrapper,
						IP_NETWORK_ADDRESS(DEVICE_INTERFACE(serverId, i + 1)->szAddress, DEVICE_INTERFACE(serverId, i + 1)->szSubnetMask, DEVICE_INTERFACE(serverId, i + 1)->prefix_len),
						DEVICE_INTERFACE(serverId, i + 1)->szSubnetMask,
						DEVICE_INTERFACE(serverId, i + 1)->prefix_len,
						NULL, 1, &virtualIp, &virtualInterface, VPN_METRIC, "VPN");
		}
	}
	return 1;
}
/**
	This function is to get the virtual ip.
*/
NETSIM_IPAddress vpn_getVirtualIp(NETSIM_ID ndeviceId)
{
	NETSIM_ID i;
	for(i=0;i<NETWORK->ppstruDeviceList[ndeviceId-1]->nNumOfInterface;i++)
	{
		if(DEVICE_INTERFACE(ndeviceId,i+1)->nInterfaceType==INTERFACE_VIRTUAL)
			return DEVICE_INTERFACE(ndeviceId,i+1)->szAddress;
	}
	return NULL;
}
/**
	 This function is to free the VPN
*/
int freeVPN(VPN* vpn)
{
	if(vpn)
	{
		free(vpn->InternetIP);
		free(vpn->LocalIP);
		free(vpn);
	}
	return 1;
}
/**
	 This function is to free the packets of VPN.
*/
int freeVPNPacket(VPN_PACKET* vpnPacket)
{
	free(vpnPacket);
	return 1;
}
/**
	This function is used to copy the vpn packet.
*/
void* copyVPNPacket(VPN_PACKET* vpnPacket)
{
	VPN_PACKET* newVpn=calloc(1,sizeof* newVpn);
	memcpy(newVpn,vpnPacket,sizeof* newVpn);
	return (void*)newVpn;
}
