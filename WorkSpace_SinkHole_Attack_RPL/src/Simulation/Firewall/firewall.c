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

#define _NETSIM_FIREWALL_CODE_
#pragma comment(lib,"NetworkStack.lib")

#include "main.h"
#include "List.h"
#include "../IP/IP.h"
#include "NetSim_utility.h"
#include "Firewall.h"

typedef struct stru_IP_ACL
{
	NETSIM_ID nDeviceId;
	NETSIM_ID nInterfaceId;
	ACL_TYPE type;
	NETSIM_IPAddress source;
	NETSIM_IPAddress dest;
	NETSIM_IPAddress srcSubnet;
	NETSIM_IPAddress destSubnet;
	UINT16 srcPort;
	UINT16 destPort;
	IP_PROTOCOL_NUMBER protocol;
	ACL_ACTION action;
	bool isMacBlock;
	_ele* ele;
}NETSIM_ACL,*ptrACL;
#define ACL_ALLOC() (ptrACL)list_alloc(sizeof(NETSIM_ACL),offsetof(NETSIM_ACL,ele))
#define ACL_NEXT(acl) acl=(ptrACL)LIST_NEXT(acl)
#define ACL_ADD(lacl,acl) LIST_ADD_LAST((void**)lacl,acl)
#define ACL_GET(d) ((ptrACL)(GET_IP_DEVVAR(d)->ACL))
#define ACL_SET(d,acl) (GET_IP_DEVVAR(d)->ACL = (void*)acl)

static ACL_ACTION action_from_str(char* s)
{
	if (!_stricmp(s, "permit"))
		return ACLACTION_PERMIT;
	if (!_stricmp(s, "deny"))
		return ACLACTION_DENY;

	fnNetSimError("Unknown acl action %s. It must be either permit or deny.", s);
	return ACLACTION_PERMIT;
}

static NETSIM_IPAddress num_to_subnet(int num)
{
	int i = 0;
	char strip[50]="";
	for (i = 0; i < 4; i++)
	{
		if (num > 8)
		{
			strcat(strip, "255");
			if (i != 3)
				strcat(strip, ".");
			num -= 8;
		}
		else
		{
			char bin[9] = "00000000";
			for (int j = 0; j < num; j++)
				bin[j] = '1';

			char s[4];
			sprintf(s,"%lld", binary_to_decimal(bin));
			strcat(strip, s);
			if (i != 3)
			{
				strcat(strip, ".");
				for (int k = i+1; k < 4; k++)
				{
					strcat(strip, "0");
					if (k != 3)
						strcat(strip, ".");
				}
			}
			break;
		}
	}
	return STR_TO_IP(strip, 4);
}

static int perfix_from_mask(NETSIM_IPAddress mask)
{
	int i = 0;
	while (mask->bin_ip[i] == '1')
		i++;
	return i;
}

static void ip_from_str(char* s, NETSIM_IPAddress* ip, NETSIM_IPAddress* subnet)
{
	if (!_stricmp(s, "any"))
	{
		*ip = NULL;
		*subnet = NULL;
		return;
	} 

	char* sip = s;
	char* ssub = NULL;
	while (*s)
	{
		if (*s == '/')
		{
			*s = 0;
			ssub = s + 1;
			break;
		}
		s++;
	}

	*ip = STR_TO_IP(sip, 4);
	*subnet = num_to_subnet(atoi(ssub));
}

static IP_PROTOCOL_NUMBER ipprotocol_from_str(char* pro)
{
	if (!_stricmp(pro, "any"))
		return IPPROTOCOL_NULL;
	else if (!_stricmp(pro, "TCP"))
		return IPPROTOCOL_TCP;
	else if (!_stricmp(pro, "UDP"))
		return IPPROTOCOL_UDP;
	else if (!_stricmp(pro, "IGMP"))
		return IPPROTOCOL_IGMP;
	else if (!_stricmp(pro, "ICMP"))
		return IPPROTOCOL_ICMP;
	else
	{
		fnNetSimError("Unknown IP protocol %s", pro);
		return IPPROTOCOL_NULL;
	}
}

static char* str_from_proto(IP_PROTOCOL_NUMBER num)
{
	switch (num)
	{
		case IPPROTOCOL_TCP:
			return _strdup("TCP");
		case IPPROTOCOL_UDP:
			return _strdup("UDP");
		default:
			return _strdup("ANY");
	}
}

static ACL_TYPE type_from_str(char* str)
{
	if (!_stricmp(str, "INBOUND"))
		return ACLTYPE_INBOUND;
	else if (!_stricmp(str, "OUTBOUND"))
		return ACLTYPE_OUTBOUND;
	else
		return ACLTYPE_BOTH;
}

static bool check_mac_block(NETSIM_ID d, NETSIM_ID in)
{
	NETSIM_IPAddress ip = DEVICE_NWADDRESS(d, in);
	NETSIM_ID i;
	for (i = 0; i < DEVICE(d)->nNumOfInterface; i++)
	{
		if (i + 1 == in)
			continue;
		if (!IP_COMPARE(DEVICE_NWADDRESS(d, i + 1), ip))
			return true;
	}
	return false;
}

_declspec(dllexport) void acl_add_new_line(NETSIM_ID d, char* s)
{
	char* act = find_word(&s);
	char* type = find_word(&s);
	char* pro = find_word(&s);
	char* src = find_word(&s);
	char* dest = find_word(&s);
	char* sport = find_word(&s);
	char* dport = find_word(&s);
	char* i = find_word(&s);

	ptrACL acl = ACL_ALLOC();
	acl->nDeviceId = d;
	acl->action = action_from_str(act);
	acl->type = type_from_str(type);
	ip_from_str(src, &acl->source, &acl->srcSubnet);
	ip_from_str(dest, &acl->dest, &acl->destSubnet);
	if (sport)
		acl->srcPort = (UINT16)atoi(sport);
	if (dport)
		acl->destPort = (UINT16)atoi(dport);
	if(pro)
		acl->protocol = ipprotocol_from_str(pro);
	if (i)
	{
		acl->nInterfaceId = atoi(i);
		if(acl->nInterfaceId)
			acl->isMacBlock = check_mac_block(d, acl->nInterfaceId);
	}
	ACL_ADD(&ACL_GET(d), acl);
}

static NETSIM_IPAddress get_dest_ip(NetSim_PACKET* packet)
{
	NETSIM_IPAddress dest = packet->pstruNetworkData->szDestIP;
	if (isMulticastIP(dest))
		return dest;
	if (isBroadcastIP(dest))
		return dest;
	UINT c;
	NETSIM_ID* d = get_dest_from_packet(packet, &c);
	if (c > 1)
		return dest;

	return fn_NetSim_Stack_GetFirstIPAddressAsId(d[0], 0);
}

/**
	This function is to configure the firewall.
*/
_declspec(dllexport) int fn_NetSim_FirewallConfig(NETSIM_ID nDeviceId)
{
	IP_DEVVAR* ip = GET_IP_DEVVAR(nDeviceId);
	if (!ip->isFirewallConfigured)
		return -1;
	char p[BUFSIZ];
	sprintf(p, "%s%s%s", pszIOPath, pathSeperator, ip->firewallConfig);
	FILE* fp = fopen(p, "r");
	if (!fp)
	{
		fnSystemError("Unable to open %s file", p);
		perror(ip->firewallConfig);
		return -2;
	}
	char buf[BUFSIZ];
	while (fgets(buf, BUFSIZ, fp))
	{
		char* s;
		s = lskip(buf);
		if (*s == '#')
			continue; //Comment line

		if (*s == '\n' || *s == 0)
			continue; //empty line

		acl_add_new_line(nDeviceId, s);
	}
	return 0;
}
/**
	This function is to check whether the particular packet is blocked or allowed by firewall
*/
static ACL_ACTION fn_NetSim_Firewall(NETSIM_ID nDeviceId, NETSIM_ID interfaceId, NetSim_PACKET* packet, ACL_TYPE type, bool isMAC)
{
	if (!GET_IP_DEVVAR(nDeviceId))
		return ACLACTION_PERMIT; // IP is not configured

	if (!GET_IP_DEVVAR(nDeviceId)->isFirewallConfigured)
		return ACLACTION_PERMIT; // Firewall is not configured

	bool ismatched = true;
	ptrACL acl = ACL_GET(nDeviceId);
	NETSIM_IPAddress src = packet->pstruNetworkData->szSourceIP;
	NETSIM_IPAddress dest = get_dest_ip(packet);
	UINT16 sport = packet->pstruTransportData ? packet->pstruTransportData->nSourcePort : 0;
	UINT16 dport = packet->pstruTransportData ? packet->pstruTransportData->nDestinationPort : 0;
	IP_PROTOCOL_NUMBER pro = packet->pstruNetworkData->IPProtocol;
	while (acl)
	{
		ismatched = true;

		if (acl->isMacBlock && !isMAC)
		{
			ACL_NEXT(acl);
			continue;
		}

		if ((acl->nInterfaceId && acl->nInterfaceId != interfaceId) ||
			(acl->type != ACLTYPE_BOTH && acl->type != type))
		{
			ACL_NEXT(acl);
			continue;
		}

		if (ismatched && acl->source)
		{
			if (IP_COMPARE(acl->source, IP_NETWORK_ADDRESS(src,acl->srcSubnet,0)))
				ismatched = false;
		}

		if (ismatched && acl->dest)
		{
			if (IP_COMPARE(acl->dest, IP_NETWORK_ADDRESS(dest,acl->destSubnet,0)))
				ismatched = false;
		}

		if(ismatched && acl->destPort && acl->destPort!=dport)
			ismatched = false;

		if(ismatched && acl->srcPort && acl->srcPort != sport)
			ismatched = false;

		if(ismatched && acl->protocol && acl->protocol != pro)
			ismatched = false;

		if (ismatched)
			return acl->action;

		ACL_NEXT(acl);
	}
	return ACLACTION_PERMIT;
}

_declspec(dllexport) ACL_ACTION fn_NetSim_MAC_Firewall(NETSIM_ID nDeviceId, NETSIM_ID interfaceId, NetSim_PACKET* packet, ACL_TYPE type)
{
	return fn_NetSim_Firewall(nDeviceId, interfaceId, packet, type, true);
}

_declspec(dllexport) ACL_ACTION fn_NetSim_NETWORK_Firewall(NETSIM_ID nDeviceId, NETSIM_ID interfaceId, NetSim_PACKET* packet, ACL_TYPE type)
{
	return fn_NetSim_Firewall(nDeviceId, interfaceId, packet, type, false);
}

_declspec(dllexport) void fn_NetSim_Firewall_Free(NETSIM_ID d)
{
	ptrACL acl = ACL_GET(d);
	while (acl)
		LIST_FREE(&acl, acl);
	ACL_SET(d, NULL);
}

_declspec(dllexport) char* acl_print(NETSIM_ID d)
{
	UINT size = 0;
	char* ret = NULL;
	char* curr;
	ptrACL acl = ACL_GET(d);
	while (acl)
	{
		char s[BUFSIZ];
		char* p = str_from_proto(acl->protocol);
		sprintf(s, "%s %s %s %s/%d %s/%d %d %d %d\n",
				acl->action == ACLACTION_PERMIT ? "PERMIT" : "DENY",
				acl->type == ACLTYPE_BOTH ? "BOTH" : (acl->type == ACLTYPE_INBOUND ? "INBOUND" : "OUTBOUND"),
				p,
				acl->source?acl->source->str_ip:"ANY",
				acl->srcSubnet?perfix_from_mask(acl->srcSubnet):0,
				acl->dest?acl->dest->str_ip:"ANY",
				acl->destSubnet?perfix_from_mask(acl->destSubnet):0,
				(int)acl->srcPort,
				(int)acl->destPort,
				(int)acl->nInterfaceId);
		free(p);
		if (size)
		{
			ret = realloc(ret, (size + strlen(s) + 1) * sizeof(char));
			curr = ret + size;
		}
		else
		{
			ret = calloc(strlen(s) + 1, sizeof(char));
			curr = ret;
		}
		strcpy(curr, s);
		size += (UINT)strlen(s);
		ACL_NEXT(acl);
	}
	return ret;
}