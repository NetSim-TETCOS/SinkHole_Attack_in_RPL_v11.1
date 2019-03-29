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
#include "RPL.h"
#include "RPL_Message.h"

//Function definition
static void rpl_dodag_config_option_destroy(PRPL_DODAG_CONFIG_OPTION opt);
static PRPL_DODAG_CONFIG_OPTION rpl_dodag_config_option_copy(PRPL_DODAG_CONFIG_OPTION opt);
static PRPL_TARGET_OPTION rpl_rpl_target_option_copy(PRPL_TARGET_OPTION target);
static void rpl_rpl_target_option_destroy(PRPL_TARGET_OPTION target);

static double get_rpl_packet_size_fixed(RPL_CTRL_MSG_CODE code)
{
	switch (code)
	{
	case Destination_Advertisement_Object:
		return RPL_CTRL_MSG_SIZE_FIXED + RPL_DAO_BASE_SIZE;
		break;
	case Destination_Advertisement_Object_Acknowledgment:
		return RPL_CTRL_MSG_SIZE_FIXED + RPL_DAOACK_BASE_SIZE;
		break;
	case DODAG_Information_Object:
		return RPL_CTRL_MSG_SIZE_FIXED + RPL_DIO_BASE_SIZE;
		break;
	case DODAG_Information_Solicitation:
		return RPL_CTRL_MSG_SIZE_FIXED + RPL_DIS_BASE_SIZE;
		break;
	default:
		fnNetSimError("Unknow rpl msg code %d in %s\n", code, __FUNCTION__);
		return 0;
		break;
	}
}

static void set_option_in_msg(NetSim_PACKET* packet, RPL_OPTION_TYPE type, void* option)
{
	PRPL_CTRL_MSG msg = GET_PRPL_CTRL_MSG(packet);
	if (msg->option_count)
		msg->options = (PRPL_OPTION*)realloc(msg->options, (msg->option_count + 1) * sizeof* msg->options);
	else
		msg->options = (PRPL_OPTION*)calloc(1, sizeof* msg->options);
	msg->options[msg->option_count] = (PRPL_OPTION)calloc(1, sizeof* msg->options[msg->option_count]);
	msg->options[msg->option_count]->option = option;
	msg->options[msg->option_count]->type = type;
	msg->option_count++;
}

void* get_option_from_msg(PRPL_CTRL_MSG msg, RPL_OPTION_TYPE type)
{
	UINT i;
	if (!msg)
		return NULL;
	for (i = 0; i < msg->option_count; i++)
	{
		if (msg->options[i]->type == type)
			return msg->options[i]->option;
	}
	return NULL;
}

void** get_all_option_from_msg(PRPL_CTRL_MSG msg, RPL_OPTION_TYPE type, UINT* count)
{
	UINT i;
	UINT c=0;
	void** ret=NULL;
	if (!msg)
	{
		*count = 0;
		return NULL;
	}
	for (i = 0; i < msg->option_count; i++)
	{
		if (msg->options[i]->type == type)
		{
			ret = (void**)realloc(ret, (c + 1) * sizeof(void*));
			ret[c] = msg->options[i]->option;
			c++;
		}
	}
	*count = c;
	return ret;
}

void rpl_option_destroy(PRPL_OPTION option)
{
	switch (option->type)
	{
	case RPLOPTION_DODAGConfiguration:
		rpl_dodag_config_option_destroy(option->option);
		break;
	case RPLOPTION_RPLTARGET:
		rpl_rpl_target_option_destroy(option->option);
		break;
	default:
		fnNetSimError("Unknown option %d in %s\n",
					  option->type, __FUNCTION__);
		break;
	}
	free(option);
}

PRPL_OPTION rpl_option_copy(PRPL_OPTION option)
{
	PRPL_OPTION ret = (PRPL_OPTION)calloc(1, sizeof* ret);
	memcpy(ret, option, sizeof* ret);

	switch (option->type)
	{
	case RPLOPTION_DODAGConfiguration:
		ret->option = rpl_dodag_config_option_copy(option->option);
		break;
	case RPLOPTION_RPLTARGET:
		ret->option = rpl_rpl_target_option_copy(option->option);
		break;
	default:
		fnNetSimError("Unknown option %d in %s\n",
					  option->type, __FUNCTION__);
		break;
	}

	return ret;
}

static PRPL_CTRL_MSG get_icmp_rpl_msg(RPL_CTRL_MSG_CODE code)
{
	PRPL_CTRL_MSG msg = (PRPL_CTRL_MSG)calloc(1, sizeof* msg);
	msg->Type = ICMP_TYPE_RPL;
	msg->Code = code;
	return msg;
}

static void rpl_get_packet_type_sz(char* str, RPL_CTRL_MSG_CODE code)
{
	switch (code)
	{
	case Consistency_Check:
		strcpy(str, "Consistency_check");
		break;
	case Destination_Advertisement_Object:
		strcpy(str, "DAO");
		break;
	case Destination_Advertisement_Object_Acknowledgment:
		strcpy(str, "DAO-ACK");
		break;
	case DODAG_Information_Object:
		strcpy(str, "DIO");
		break;
	case DODAG_Information_Solicitation:
		strcpy(str, "DIS");
		break;
	}
}

static NetSim_PACKET* create_rpl_ctrl_msg(RPL_CTRL_MSG_CODE code,
										  double time,
										  NETSIM_ID src,
										  NETSIM_ID dest)
{
	NetSim_PACKET* packet = fn_NetSim_Packet_CreatePacket(NETWORK_LAYER);
	packet->nPacketType = PacketType_Control;
	packet->pstruNetworkData->dArrivalTime = time;
	packet->pstruNetworkData->dOverhead = get_rpl_packet_size_fixed(code);
	packet->pstruNetworkData->nRoutingProtocol = NW_PROTOCOL_RPL;
	packet->pstruNetworkData->szSourceIP = IP_COPY(DEVICE_NWADDRESS(src, 1));
	packet->pstruNetworkData->szGatewayIP = IP_COPY(DEVICE_NWADDRESS(src, 1));
	if (dest)
		packet->pstruNetworkData->szDestIP = IP_COPY(DEVICE_NWADDRESS(dest, 1));
	else
		packet->pstruNetworkData->szDestIP = GET_BROADCAST_IP(6);
	packet->pstruNetworkData->nTTL = MAX_TTL;
	packet->dEventTime = time;
	packet->nControlDataType = GET_RPL_CTRL_PACKET_TYPE(code);
	packet->nSourceId = src;
	add_dest_to_packet(packet, dest);
	packet->nTransmitterId = src;

	rpl_get_packet_type_sz(packet->szPacketType, code);

	packet->pstruNetworkData->Packet_RoutingProtocol = get_icmp_rpl_msg(code);
	return packet;
}

//DIO
static PRPL_DIO_BASE create_dio_base()
{
	PRPL_DIO_BASE b = (PRPL_DIO_BASE)calloc(1, sizeof* b);
	b->Prf = RPL_DEFAULT_DAG_PREF;
	b->Rank = INFINITE_RANK;
	b->MOP = RPL_DEFAULT_MOP;
	return b;
}

static PRPL_DODAG_CONFIG_OPTION create_dodag_config_option()
{
	PRPL_DODAG_CONFIG_OPTION o = (PRPL_DODAG_CONFIG_OPTION)calloc(1, sizeof* o);
	o->Type = 0x04;
	o->OptLength = 14;
	return o;
}

static void rpl_dodag_config_option_destroy(PRPL_DODAG_CONFIG_OPTION opt)
{
	free(opt);
}

static PRPL_DODAG_CONFIG_OPTION rpl_dodag_config_option_copy(PRPL_DODAG_CONFIG_OPTION opt)
{
	PRPL_DODAG_CONFIG_OPTION ret = (PRPL_DODAG_CONFIG_OPTION)calloc(1, sizeof* ret);
	memcpy(ret, opt, sizeof* ret);
	return ret;
}

NetSim_PACKET* create_root_dio_message(NETSIM_ID ndevId, double time, bool include_dodag_config, bool include_seq_num)
{
	PRPL_NODE r = GET_RPL_NODE(ndevId);

	NetSim_PACKET* packet = create_rpl_ctrl_msg(DODAG_Information_Object, time, ndevId, 0);
	PRPL_DIO_BASE diobase = create_dio_base();
	SET_BASE_IN_MSG(packet, diobase);

	if (r->root_info->dodag_id != NULL)
		diobase->DODAGID = IP_COPY(r->root_info->dodag_id);
	else
		diobase->DODAGID = IP_COPY(DEVICE_NWADDRESS(ndevId,1));

	diobase->Prf = r->root_info->dodag_pref;
	diobase->Rank = RPL_RANK_ROOT;
	diobase->G = r->root_info->grounded;

	if (include_seq_num) 
		diobase->DTSN = seq_num_mapping_get(diobase->DODAGID)->seq_num;
	else
		diobase->DTSN = 0;
	diobase->RPLInstanceID = r->RPLInstanceId;

	if (include_dodag_config)
	{
		PRPL_DODAG_CONFIG_OPTION opt = create_dodag_config_option();
		set_option_in_msg(packet, RPLOPTION_DODAGConfiguration ,opt);

		opt->DIOIntDoubl = r->root_info->dio_interval_doublings;
		opt->DIOIntMin = r->root_info->dio_interval_min;
		opt->DIORedun = r->root_info->dio_redundancy_constant;
		opt->MaxRankIncrease = r->root_info->max_rank_inc;
		opt->MinHopRankIncrease = r->root_info->min_hop_rank_inc;
	}

	return packet;
}

static NetSim_PACKET* create_joined_dio_message(NETSIM_ID ndevId, double time, bool include_dodag_config)
{
	PRPL_NODE r = GET_RPL_NODE(ndevId);

	NetSim_PACKET* packet = create_rpl_ctrl_msg(DODAG_Information_Object, time, ndevId, 0);
	PRPL_DIO_BASE diobase = create_dio_base();
	SET_BASE_IN_MSG(packet, diobase);

	diobase->DODAGID = r->joined_dodag->dodag_id;
	diobase->Prf = r->joined_dodag->dodag_pref;
	diobase->Rank = r->joined_dodag->rank;
	diobase->G = r->joined_dodag->grounded;
	diobase->DTSN = r->joined_dodag->seq_num;
	diobase->RPLInstanceID = r->RPLInstanceId;

	if (include_dodag_config)
	{
		PRPL_DODAG_CONFIG_OPTION opt = create_dodag_config_option();
		set_option_in_msg(packet, RPLOPTION_DODAGConfiguration, opt);

		opt->DIOIntDoubl = r->joined_dodag->dio_interval_doublings;
		opt->DIOIntMin = r->joined_dodag->dio_interval_min;
		opt->DIORedun = r->joined_dodag->dio_redundancy_constant;
		opt->MaxRankIncrease = r->joined_dodag->max_rank_inc;
		opt->MinHopRankIncrease = r->joined_dodag->min_hop_rank_inc;
	}

	return packet;
}

NetSim_PACKET* create_current_dio_message(NETSIM_ID ndevId, double time, bool include_dodag_config)
{
	PRPL_NODE r = GET_RPL_NODE(ndevId);
	if (rpl_node_is_joined(r))
	{
		return create_joined_dio_message(ndevId, time, include_dodag_config);
	}
	else if (rpl_node_is_root(r))
	{
		return create_root_dio_message(ndevId, time, include_dodag_config, TRUE);
	}
	else if (rpl_node_is_poisoning(r))
	{
		return create_joined_dio_message(ndevId, time, include_dodag_config);
	}
	else
	{
		return NULL;
	}
}

PRPL_CTRL_MSG rpl_dio_pdu_duplicate(PRPL_CTRL_MSG dio)
{
	PRPL_CTRL_MSG new_dio = (PRPL_CTRL_MSG)calloc(1, sizeof* new_dio);
	memcpy(new_dio, dio, sizeof* new_dio);

	PRPL_DIO_BASE new_base = (PRPL_DIO_BASE)calloc(1, sizeof* new_base);
	new_dio->Base = new_base;
	memcpy(new_base, dio->Base, sizeof* new_base);
	
	new_dio->options = (PRPL_OPTION*)calloc(dio->option_count, sizeof* new_dio->options);
	UINT i;
	for (i = 0; i < dio->option_count; i++)
	{
		new_dio->options[i] = (PRPL_OPTION)calloc(1, sizeof* new_dio->options[i]);
		new_dio->options[i]->type = dio->options[i]->type;
		switch (new_dio->options[i]->type)
		{
		case RPLOPTION_DODAGConfiguration:
			new_dio->options[i]->option = calloc(1, sizeof(RPL_DODAG_CONFIG_OPTION));
			memcpy(new_dio->options[i]->option, dio->options[i]->option, sizeof(RPL_DODAG_CONFIG_OPTION));
			break;
		default:
			fnNetSimError("Unknown option %d in %s\n", new_dio->options[i]->type, __FUNCTION__);
			break;
		}
	}
	return new_dio;
}

void rpl_dio_pdu_free(PRPL_CTRL_MSG dio)
{
	if (!dio)
		return;
	IP_FREE(((PRPL_DIO_BASE)dio->Base)->DODAGID);
	free((PRPL_DIO_BASE)dio->Base);
	UINT i;
	for (i = 0; i < dio->option_count; i++)
	{
		free((PRPL_DODAG_CONFIG_OPTION)dio->options[i]->option);
		free(dio->options[i]);
	}
	free(dio->options);
	free(dio);
}

//DAO
static PRPL_DAO_BASE create_dao_base(PRPL_NODE rpl)
{
	PRPL_DAO_BASE b = (PRPL_DAO_BASE)calloc(1, sizeof* b);
	b->RPLInstanceID = rpl->RPLInstanceId;
	b->D = false; //No local RPL Instance
	b->K = true;
	b->DAOSequence = ++rpl->DaoSequence;
	return b;
}

NetSim_PACKET* create_dao_message(NETSIM_ID ndevid, double time,NETSIM_ID parent)
{
	PRPL_NODE rpl = GET_RPL_NODE(ndevid);
	NetSim_PACKET* packet = create_rpl_ctrl_msg(Destination_Advertisement_Object, time, ndevid, parent);
	PRPL_DAO_BASE dao = create_dao_base(rpl);
	SET_BASE_IN_MSG(packet, dao);
	return packet;
}

void create_and_add_rpl_target_option(NetSim_PACKET* dao_pdu, UINT8 prefix_len, NETSIM_IPAddress dest)
{
	PRPL_TARGET_OPTION target = (PRPL_TARGET_OPTION)calloc(1, sizeof* target);
	target->Type = RPLOPTION_RPLTARGET;
	target->Option_Length = 18;
	target->Prefix_Length = prefix_len;
	target->Traget_Prefix = IP_COPY(dest);
	set_option_in_msg(dao_pdu, RPLOPTION_RPLTARGET, target);
}

static PRPL_TARGET_OPTION rpl_rpl_target_option_copy(PRPL_TARGET_OPTION target)
{
	PRPL_TARGET_OPTION ret = (PRPL_TARGET_OPTION)calloc(1, sizeof* ret);
	memcpy(ret, target, sizeof* ret);
	return ret;
}

static void rpl_rpl_target_option_destroy(PRPL_TARGET_OPTION target)
{
	free(target);
}

//DIS
static PRPL_DIS_BASE create_dis_base(PRPL_NODE rpl)
{
	PRPL_DIS_BASE b = (PRPL_DIS_BASE)calloc(1, sizeof* b);
	return b;
}

NetSim_PACKET* create_dis_message(NETSIM_ID ndevid, double time)
{
	PRPL_NODE rpl = GET_RPL_NODE(ndevid);
	NetSim_PACKET* packet = create_rpl_ctrl_msg(DODAG_Information_Solicitation, time, ndevid, 0);
	PRPL_DIS_BASE dis = create_dis_base(rpl);
	SET_BASE_IN_MSG(packet, dis);
	return packet;
}

// Message Processing
void rpl_node_send_msg(NETSIM_ID ndevid, NetSim_PACKET* packet)
{
	NetSim_EVENTDETAILS pevent;
	memset(&pevent, 0, sizeof pevent);
	pevent.dEventTime = pstruEventDetails->dEventTime;
	pevent.dPacketSize = fnGetPacketSize(packet);
	pevent.nDeviceId = ndevid;
	pevent.nDeviceType = DEVICE_TYPE(ndevid);
	pevent.nEventType = NETWORK_OUT_EVENT;
	pevent.nPacketId = packet->nPacketId;
	pevent.nProtocolId = NW_PROTOCOL_IPV6;
	pevent.pPacket = packet;
	fnpAddEvent(&pevent);
}

void rpl_process_ctrl_msg()
{
	switch (pstruEventDetails->pPacket->nControlDataType % 100)
	{
	case DODAG_Information_Object:
		rpl_process_dio_msg();
		break;
	case Destination_Advertisement_Object:
		rpl_process_dao_msg();
		break;
	case DODAG_Information_Solicitation:
		rpl_process_dis_msg();
		break;
	default:
		fnNetSimError("Unknown rpl ctrl msg %d in %s",
					  pstruEventDetails->pPacket->nControlDataType,
					  __FUNCTION__);
		break;
	}
}
