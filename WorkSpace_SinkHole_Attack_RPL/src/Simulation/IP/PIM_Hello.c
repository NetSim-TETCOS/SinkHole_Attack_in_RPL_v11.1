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
#include "PIM_SM.h"
#include "PIM_Msg.h"

static void set_option_in_hello(NetSim_PACKET* packet,
								UINT16 type,
								UINT16 len,
								void* opt)
{
	ptrPIM_HELLO hello = get_PIM_MSG(packet);
	if (hello->optCount)
	{
		hello->option = realloc(hello->option, (hello->optCount + 1) * sizeof* hello->option);
	}
	else
	{
		hello->option = calloc(1, sizeof* hello->option);
	}
	hello->option[hello->optCount] = calloc(1, sizeof* hello->option[hello->optCount]);
	hello->option[hello->optCount]->optionValue = opt;
	hello->option[hello->optCount]->optionLength = len;
	hello->option[hello->optCount]->optionType = type;
	hello->optCount++;

	packet->pstruNetworkData->dOverhead += len + PIM_HELLO_OPTION_LEN;
	packet->pstruNetworkData->dPacketSize += len + PIM_HELLO_OPTION_LEN;
}

static void* get_option_from_hello(ptrPIM_HELLO hello, UINT16 type)
{
	UINT i;
	for (i = 0; i < hello->optCount; i++)
	{
		if (hello->option[i]->optionType == type)
			return hello->option[i]->optionValue;
	}
	return NULL;
}

static void add_dr_priority_option(NETSIM_ID d, NetSim_PACKET* packet)
{
	ptrOPTION_DRPRIORITY pri = calloc(1, sizeof* pri);
	pri->DRPriority = GET_PIM_VAR(d)->DRPriority;
	set_option_in_hello(packet,
						PIM_OPTION_DRPRIORITY_TYPE,
						PIM_OPTION_DRPRIORITY_LEN,
						pri);
	print_pim_sm_log("Adding DR Priority option. DR Priority = %d", pri->DRPriority);
}

static void add_genid_option(NETSIM_ID d, NetSim_PACKET* packet)
{
	ptrOPTION_GENERATIONID gen = calloc(1, sizeof* gen);
	gen->GenerationId = GET_PIM_VAR(d)->genId;
	set_option_in_hello(packet,
						PIM_OPTION_GENERATIONID_TYPE,
						PIM_OPTION_GENERATIONID_LEN,
						gen);
	print_pim_sm_log("Adding Generation Id option. Generation Id = %d", gen->GenerationId);
}

static void add_lanprunedelay_option(NETSIM_ID d, NetSim_PACKET* packet)
{
	ptrOPTION_LANPRUNEDELAY lpd = calloc(1, sizeof* lpd);
	lpd->overrideInterval = GET_PIM_VAR(d)->overrideInterval;
	lpd->propagationDelay = GET_PIM_VAR(d)->propagationDelay;
	lpd->T = false;
	set_option_in_hello(packet,
						PIM_OPTION_LANPRUNEDELAY_TYPE,
						PIM_OPTION_LANPRUNEDELAY_LEN,
						lpd);
	print_pim_sm_log("Adding Lan prune delay option.");
}

static void add_addresslist_option(NETSIM_ID d, NetSim_PACKET* packet)
{
	ptrOPTION_ADDRLIST addrList = calloc(1, sizeof* addrList);
	UINT16 len = 0;
	NETSIM_ID c = DEVICE(d)->nNumOfInterface;
	NETSIM_ID i;
	if (c <= 1)
		return; //No secondary interface
	addrList->SeconadayAddr = calloc(c, sizeof* addrList->SeconadayAddr);
	for (i = 0; i < c; i++)
	{
		addrList->SeconadayAddr[i] = encode_unicast_addr(DEVICE_NWADDRESS(d, i + 1));
		len += ENCODED_UNICAST_ADDR_LEN;
	}

	len -= ENCODED_UNICAST_ADDR_LEN; //Remove source addr
	addrList->c = c - 1;


	set_option_in_hello(packet,
						PIM_OPTION_ADDRLIST_TYPE,
						len,
						addrList);
	print_pim_sm_log("Adding secondary address list option.");
}

static ptrPIM_HELLO alloc_pim_hello()
{
	ptrPIM_HELLO hello = (ptrPIM_HELLO)calloc(1, sizeof* hello);
	set_pim_hdr(&hello->hdr, PIMMSG_Hello);

	return hello;
}

static NetSim_PACKET* create_pim_hello(NETSIM_ID dev,
									   double time)
{
	ptrPIM_HELLO hello = alloc_pim_hello();
	NETSIM_ID d = 0;
	NetSim_PACKET* packet = create_pim_packet(PIMMSG_Hello,
											  hello,
											  time,
											  dev,
											  DEVICE_NWADDRESS(dev, 1),
											  1,
											  &d,
											  ALL_PIM_ROUTERS_ADDRESS,
											  1);
	return packet;
}

void send_hello_msg(NETSIM_ID d, double time)
{
	ptrPIM_VAR var = GET_PIM_VAR(d);
	NetSim_PACKET* packet = create_pim_hello(d, time);

	add_dr_priority_option(d, packet);

	add_genid_option(d, packet);

	add_lanprunedelay_option(d, packet);

	add_addresslist_option(d, packet);

	send_pim_msg(d, time, packet);
	print_pim_sm_log("Adding timer event %s at %0.3lf\n",
					 "PIM_SEND_HELLO",
					 (time + var->helloPeriod) / 1000);
	pim_add_timeout_event(d, time + var->helloPeriod, EVENT_PIM_SEND_HELLO, NULL);
}

bool process_pim_hello_packet()
{
	bool isNeighbor = false;
	NetSim_PACKET* packet = pstruEventDetails->pPacket;
	NETSIM_ID d = pstruEventDetails->nDeviceId;
	NETSIM_ID ifid = pstruEventDetails->nInterfaceId;
	ptrPIM_HELLO hello = get_PIM_MSG(packet);

	NETSIM_IPAddress src = packet->pstruNetworkData->szSourceIP;
	ptrPIM_NEIGHBOR neigh = find_neighbor(d, src);
	isNeighbor = neigh ? true : false;

	if (!isNeighbor)
	{
		print_pim_sm_log("New neighbor %s is found on interface %d",
						 src->str_ip, ifid);
		neigh = create_and_add_neighbor(d, ifid, src);
	}

	ptrOPTION_GENERATIONID gen = get_option_from_hello(hello, PIM_OPTION_GENERATIONID_TYPE);
	if (gen)
		neigh->gen_id = gen->GenerationId;

	ptrOPTION_DRPRIORITY pri = get_option_from_hello(hello, PIM_OPTION_DRPRIORITY_TYPE);
	if (pri)
	{
		neigh->dr_priority = pri->DRPriority;
		neigh->dr_priority_present = true;
	}

	double t;
	ptrOPTION_HOLDTIME hold = get_option_from_hello(hello, PIM_OPTION_HOLDTIME_TYPE);
	if (hold)
		t = hold->holdTime*MILLISECOND;
	else
		t = GET_PIM_VAR(d)->helloPeriod*3.5;
	if (!neigh->isTimeoutAdded)
	{
		print_pim_sm_log("Adding neighbor timeout event at %0.3lf",
			(pstruEventDetails->dEventTime + t) / 1000);
		pim_add_timeout_event(d,
							  pstruEventDetails->dEventTime + t,
							  EVENT_PIM_NEIGHBOR_TIMEOUT,
							  NULL);
	}
	neigh->timeout = pstruEventDetails->dEventTime + t;
	neigh->isTimeoutAdded = true;
	print_pim_sm_log("Neighbor details updated as DR_priority=%d, GenId=%d, Timeout=%0.3lf",
					 neigh->dr_priority,
					 neigh->gen_id,
					 neigh->timeout / 1000);

	elect_DR(d, ifid);

	ptrOPTION_LANPRUNEDELAY lpd = get_option_from_hello(hello, PIM_OPTION_LANPRUNEDELAY_TYPE);
	if (lpd)
	{
		neigh->lan_prune_delay_present = true;
		neigh->override_interval = lpd->overrideInterval;
		neigh->propagation_delay = lpd->propagationDelay;
		neigh->tracking_support = lpd->T;
	}
	else
	{
		neigh->lan_prune_delay_present = false;
	}

	ptrOPTION_ADDRLIST addrlist = get_option_from_hello(hello, PIM_OPTION_ADDRLIST_TYPE);
	if (addrlist)
	{
		neigh->secondary_address_count = addrlist->c;
		assert(addrlist->c);
		UINT i;
		UINT k;
		free(neigh->secondary_address_list);
		neigh->secondary_address_list = calloc(addrlist->c, sizeof* neigh->secondary_address_list);
		for (i = 0, k = 0; k < addrlist->c; i++,k++)
		{
			if (!IP_COMPARE(addrlist->SeconadayAddr[i]->unicastAddr, src))
			{
				k--;
				continue;
			}
			neigh->secondary_address_list[k] = addrlist->SeconadayAddr[i]->unicastAddr;
		}
	}
	else
	{
		neigh->secondary_address_count = 0;
		free(neigh->secondary_address_list);
		neigh->secondary_address_list = NULL;
	}
	return true;
}
