/************************************************************************************
* Copyright (C) 2016                                                               *
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
#include "RPL.h"
#include "RPL_enum.h"

char* GetStringRPL_Subevent(NETSIM_ID);
int fn_NetSim_RPL_Init_F();
int fn_NetSim_RPL_Finish_F();
int fn_NetSim_RPL_Configure_F(void** var);
int fn_NetSim_RPL_FreePacket_F(NetSim_PACKET* packet);
int fn_NetSim_RPL_CopyPacket_F(NetSim_PACKET* destPacket, NetSim_PACKET* srcPacket);

/**
RPL Init function initializes the RPL parameters.
*/
_declspec (dllexport) int fn_NetSim_RPL_Init(struct stru_NetSim_Network *NETWORK_Formal,
											 NetSim_EVENTDETAILS *pstruEventDetails_Formal,
											 char *pszAppPath_Formal,
											 char *pszWritePath_Formal,
											 int nVersion_Type,
											 void **fnPointer)
{
	return fn_NetSim_RPL_Init_F();
}

/**
This function is called by NetworkStack.dll, whenever the event gets triggered
inside the NetworkStack.dll for the RPL protocol
*/
_declspec (dllexport) int fn_NetSim_RPL_Run()
{
	switch (pstruEventDetails->nEventType)
	{
	case NETWORK_OUT_EVENT:
	{
	}
	break;
	case NETWORK_IN_EVENT:
	{
		rpl_add_to_neighbor_list();
		if (is_rpl_control_packet(pstruEventDetails->pPacket))
		{
			rpl_process_ctrl_msg();
			fn_NetSim_Packet_FreePacket(pstruEventDetails->pPacket);
			pstruEventDetails->pPacket = NULL;
		}
	}
	break;
	case TIMER_EVENT:
	{
		switch (pstruEventDetails->nSubEventType)
		{
		case RPL_TRICKLE_T_TIMEOUT:
			rpl_trickle_handle_t_timeout();
			break;
		case RPL_TRICKLE_I_TIMEOUT:
			rpl_trickle_handle_i_timeout();
			break;
		case RPL_SEND_DAO:
			rpl_send_dao();
			break;
		case RPL_NEW_PREF_PARENT:
			// Do nothing for now.
			/* This event is written for customer 
			 * who want to perform some action if
			 * new parent is selected.
			 */
			break;
		case RPL_DAO_ROUTE_TIMEOUT:
			rpl_dao_route_timeout();
			break;
		case RPL_SEND_DIS:
			rpl_dis_pdu_send();
			break;
		default:
			fnNetSimError("Unknown subevent %d for RPL.", pstruEventDetails->nSubEventType);
			break;
		}
	}
	break;
	default:
		fnNetSimError("Unknow event %d for RPL protocol", pstruEventDetails->nEventType);
		break;
	}
	return 0;
}

/**
This function is called by NetworkStack.dll, once simulation end to free the
allocated memory for the network.
*/
_declspec(dllexport) int fn_NetSim_RPL_Finish()
{
	return fn_NetSim_RPL_Finish_F();
}

/**
This function is called by NetworkStack.dll, while writing the event trace
to get the sub event as a string.
*/
_declspec (dllexport) char* fn_NetSim_RPL_Trace(NETSIM_ID nSubEvent)
{
	return GetStringRPL_Subevent(nSubEvent);
}

/**
This function is called by NetworkStack.dll, while configuring the device
for RPL protocol.
*/
_declspec(dllexport) int fn_NetSim_RPL_Configure(void** var)
{
	return fn_NetSim_RPL_Configure_F(var);
}

/**
This function is called by NetworkStack.dll, to free the RPL protocol data.
*/
_declspec(dllexport) int fn_NetSim_RPL_FreePacket(NetSim_PACKET* pstruPacket)
{
	return fn_NetSim_RPL_FreePacket_F(pstruPacket);
}

/**
This function is called by NetworkStack.dll, to copy the RPL protocol
details from source packet to destination.
*/
_declspec(dllexport) int fn_NetSim_RPL_CopyPacket(NetSim_PACKET* pstruDestPacket, NetSim_PACKET* pstruSrcPacket)
{
	return fn_NetSim_RPL_CopyPacket_F(pstruDestPacket, pstruSrcPacket);
}

/**
This function write the Metrics
*/
_declspec(dllexport) int fn_NetSim_RPL_Metrics(PMETRICSWRITER metricsWriter)
{
	return 0;
}

/**
This function will return the string to write packet trace heading.
*/
_declspec(dllexport) char* fn_NetSim_RPL_ConfigPacketTrace()
{
	return "";
}

/**
This function will return the string to write packet trace.
*/
_declspec(dllexport) char* fn_NetSim_RPL_WritePacketTrace(NetSim_PACKET* pstruPacket, char** ppszTrace)
{
	return "";
}

static PRPL_ROOT rpl_root_info_create()
{
	PRPL_ROOT root_info = calloc(1,sizeof* root_info);
	memcpy(root_info, get_global_root_info(), sizeof* root_info);
	
	root_info->dodag_id = NULL;
	root_info->configured_dodag_id = NULL;
	root_info->dodag_pref = RPL_DEFAULT_DAG_PREF;
	root_info->grounded = FALSE;
	root_info->min_hop_rank_inc = 1;
	return root_info;
}

void rpl_node_init(NETSIM_ID d)
{
	PRPL_NODE r = GET_RPL_NODE(d);
	r->root_info = rpl_root_info_create();

	//Schedule the DIS message transmission
	memset(pstruEventDetails, 0, sizeof* pstruEventDetails);
	pstruEventDetails->dEventTime = r->DISInitDelay;
	pstruEventDetails->nDeviceId = d;
	pstruEventDetails->nDeviceType = DEVICE_TYPE(d);
	pstruEventDetails->nEventType = TIMER_EVENT;
	pstruEventDetails->nProtocolId = NW_PROTOCOL_RPL;
	pstruEventDetails->nSubEventType = RPL_SEND_DIS;
	fnpAddEvent(pstruEventDetails);
}

void start_as_root(NETSIM_ID d)
{
	PRPL_NODE rpl = GET_RPL_NODE(d);

	/* forget about all previous DIO routes */
	rpl_delete_all_route(d);

	forget_neighbor_messages(rpl);

	if (rpl->joined_dodag != NULL)
	{
		rpl_dodag_destroy(rpl->joined_dodag);
		rpl->joined_dodag = NULL;
	}

	if (rpl->root_info->dodag_id == NULL)
	{
		if (rpl->root_info->configured_dodag_id == NULL)
		{
			rpl->root_info->dodag_id = IP_COPY(DEVICE_NWADDRESS(d, 1));
		}
		else
		{
			rpl->root_info->dodag_id = IP_COPY(rpl->root_info->configured_dodag_id);
		}
	}
	rpl_trickle_reset(d);
}
