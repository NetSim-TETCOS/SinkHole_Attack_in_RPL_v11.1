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
#include "RPL_Message.h"

#define check_if_dis_needed(rpl) (rpl->joined_dodag == NULL)

void rpl_dis_pdu_send()
{
	NETSIM_ID d = pstruEventDetails->nDeviceId;
	double time = pstruEventDetails->dEventTime;
	PRPL_NODE rpl = GET_RPL_NODE(d);

	//schedule the next dis
	pstruEventDetails->dEventTime += rpl->DISInterval;
	fnpAddEvent(pstruEventDetails);

	bool isdisneeded = check_if_dis_needed(rpl);

	if (isdisneeded)
	{
		NetSim_PACKET* dis_pdu = create_dis_message(d, time);

		rpl_node_send_msg(d, dis_pdu);
	}
}

void rpl_process_dis_msg()
{
	NETSIM_ID d = pstruEventDetails->nDeviceId;
	double t = pstruEventDetails->dEventTime;

	NetSim_PACKET* dio_pdu = create_current_dio_message(d, t, TRUE);

	if (dio_pdu != NULL)
		rpl_node_send_msg(d, dio_pdu);
}

void rpl_dis_msg_destroy(NetSim_PACKET* packet)
{
	PRPL_CTRL_MSG rpl = packet->pstruNetworkData->Packet_RoutingProtocol;
	PRPL_DIS_BASE b = rpl->Base;
	free(b);
	UINT i;
	for (i = 0; i < rpl->option_count; i++)
		rpl_option_destroy(rpl->options[i]);
	free(rpl);
}

void rpl_dis_msg_copy(const NetSim_PACKET* destPacket, const NetSim_PACKET* srcPacket)
{
	PRPL_CTRL_MSG srpl = srcPacket->pstruNetworkData->Packet_RoutingProtocol;
	PRPL_CTRL_MSG drpl = (PRPL_CTRL_MSG)calloc(1, sizeof* drpl);
	memcpy(drpl, srpl, sizeof* drpl);
	destPacket->pstruNetworkData->Packet_RoutingProtocol = drpl;

	PRPL_DIS_BASE b = srpl->Base;
	PRPL_DIS_BASE db = (PRPL_DIS_BASE)calloc(1, sizeof* db);
	memcpy(db, b, sizeof* db);
	drpl->Base = db;

	UINT i;
	for (i = 0; i < srpl->option_count; i++)
		drpl->options[i] = rpl_option_copy(srpl->options[i]);
}