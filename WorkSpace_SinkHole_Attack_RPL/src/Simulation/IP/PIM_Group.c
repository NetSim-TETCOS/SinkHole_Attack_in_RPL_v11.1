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

ptrPIM_GROUP pim_find_group(NETSIM_ID d, NETSIM_IPAddress addr)
{
	ptrPIM_GROUP gr = GET_PIM_VAR(d)->groupList;
	while (gr)
	{
		if (!IP_COMPARE(gr->groupAddress, addr))
			return gr;
		PIM_GROUP_NEXT(gr);
	}
	return NULL;
}

ptrPIM_GROUP create_group(NETSIM_ID d, NETSIM_IPAddress addr, NETSIM_IPAddress RP)
{
	ptrPIM_VAR pim = GET_PIM_VAR(d);
	ptrPIM_GROUP gr = PIM_GROUP_ALLOC();
	NETSIM_ID in;
	pim->groupCount++;
	gr->groupId = pim->groupCount;
	gr->groupAddress = IP_COPY(addr);
	gr->RP = IP_COPY(RP);
	gr->RPId = fn_NetSim_Stack_GetDeviceId_asIP(RP,&in);
	PIM_GROUP_ADD(&pim->groupList, gr);
	return gr;
}


static bool is_if_already_presen(ptrPIM_GROUP g, NETSIM_ID i)
{
	UINT c;
	for (c = 0; c < g->count; c++)
		if (g->ifid[c] == i)
			return true;
	return false;
}

void pim_add_interface_to_group(NETSIM_ID d, NETSIM_ID i, ptrPIM_GROUP g)
{
	if (is_if_already_presen(g, i))
		return; //Already present

	if (g->count)
		g->ifid = realloc(g->ifid, (g->count + 1) * sizeof* g->ifid);
	else
		g->ifid = calloc(1, sizeof* g->ifid);

	g->ifid[g->count] = i;
	g->count++;
}

