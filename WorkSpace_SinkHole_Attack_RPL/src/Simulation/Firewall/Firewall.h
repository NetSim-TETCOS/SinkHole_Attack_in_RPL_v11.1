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
#ifndef _NETSIM_FIREWALL_H_
#define _NETSIM_FIREWALL_H_
#ifdef  __cplusplus
extern "C" {
#endif
#ifndef _NETSIM_FIREWALL_CODE_
#pragma comment(lib,"Firewall.lib")
#endif

	//ACL
	typedef enum
	{
		ACLTYPE_BOTH,
		ACLTYPE_INBOUND,
		ACLTYPE_OUTBOUND,
	}ACL_TYPE;

	typedef enum
	{
		ACLACTION_PERMIT,
		ACLACTION_DENY,
	}ACL_ACTION;

	//Firewall
	_declspec(dllexport) int fn_NetSim_FirewallConfig(NETSIM_ID nDeviceId);
	_declspec(dllexport) void acl_add_new_line(NETSIM_ID d, char* s);
	_declspec(dllexport) ACL_ACTION fn_NetSim_MAC_Firewall(NETSIM_ID nDeviceId, NETSIM_ID interfaceId, NetSim_PACKET* packet, ACL_TYPE type);
	_declspec(dllexport) ACL_ACTION fn_NetSim_NETWORK_Firewall(NETSIM_ID nDeviceId, NETSIM_ID interfaceId, NetSim_PACKET* packet, ACL_TYPE type);
	_declspec(dllexport) void fn_NetSim_Firewall_Free(NETSIM_ID d);
	_declspec(dllexport) char* acl_print(NETSIM_ID d);

#ifdef  __cplusplus
}
#endif
#endif //_NETSIM_FIREWALL_H_