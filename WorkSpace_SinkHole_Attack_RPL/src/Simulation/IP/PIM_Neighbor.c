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

ptrPIM_NEIGHBOR find_neighbor(NETSIM_ID d, NETSIM_IPAddress ip)
{
	ptrPIM_NEIGHBOR neigh = GET_PIM_VAR(d)->neighborList;
	while (neigh)
	{
		//Look for primary address
		if (!IP_COMPARE(neigh->neighborAddr, ip))
			return neigh;
		
		//Look for secondary address
		UINT i;
		for (i = 0; i < neigh->secondary_address_count; i++)
			if (!IP_COMPARE(ip, neigh->secondary_address_list[i]))
				return neigh;

		PIM_NEIGHBOR_NEXT(neigh);
	}
	return NULL;
}

static void add_neighbor(NETSIM_ID d, ptrPIM_NEIGHBOR neigh)
{
	GET_PIM_VAR(d)->neighCount++;
	PIM_NEIGHBOR_ADD(&GET_PIM_VAR(d)->neighborList, neigh);
}

ptrPIM_NEIGHBOR create_and_add_neighbor(NETSIM_ID d,
										NETSIM_ID ifId,
										NETSIM_IPAddress address)
{
	ptrPIM_NEIGHBOR neigh = PIM_NEIGHBOR_ALLOC();
	neigh->incomingInterface = ifId;
	neigh->neighborAddr = address;
	add_neighbor(d, neigh);
	return neigh;
}

static ptrPIM_NEIGHBOR* get_all_neigh_for_interface(NETSIM_ID d,
												   NETSIM_ID ifid,
												   UINT* c)
{
	UINT k = 0;
	ptrPIM_NEIGHBOR* n;
	ptrPIM_NEIGHBOR neigh = GET_PIM_VAR(d)->neighborList;
	while (neigh)
	{
		if (neigh->incomingInterface == ifid)
		{
			if (k)
				n = realloc(n, (k + 1) * sizeof* n);
			else
				n = calloc(1, sizeof* n);
			n[k] = neigh;
			k++;
		}
		PIM_NEIGHBOR_NEXT(neigh);
	}
	*c = k;
	return n;
}

static bool dr_is_better(ptrPIM_NEIGHBOR a, ptrPIM_NEIGHBOR b)
{
	if (!a->dr_priority_present || !b->dr_priority_present)
	{
		return a->neighborAddr->str_ip > b->neighborAddr->str_ip;
	}
	else 
	{
		return ((a->dr_priority > b->dr_priority) ||
			(a->dr_priority == b->dr_priority &&
			 a->neighborAddr->str_ip > b->neighborAddr->str_ip));
	}
}

void elect_DR(NETSIM_ID d, NETSIM_ID ifid)
{
	ptrPIM_VAR var = GET_PIM_VAR(d);
	UINT c = 0;
	ptrPIM_NEIGHBOR* neigh = get_all_neigh_for_interface(d, ifid, &c);
	UINT i;

	PIM_NEIGHBOR me;
	memset(&me, 0, sizeof me);
	me.neighborAddr = DEVICE_NWADDRESS(d, ifid);
	ptrPIM_NEIGHBOR dr = &me;
	for (i = 0; i < c; i++)
	{
		if (dr_is_better(neigh[i], dr))
			dr = neigh[i];
	}
	var->DR[ifid - 1] = dr->neighborAddr;
	free(neigh);
}

static bool lan_delay_enabled(NETSIM_ID d, NETSIM_ID I)
{
	UINT c = 0;
	ptrPIM_NEIGHBOR* neigh = get_all_neigh_for_interface(d, I, &c);
	UINT i;

	for (i = 0; i < c; i++)
	{
		if (neigh[i]->lan_prune_delay_present == false)
		{
			free(neigh);
			return false;
		}
	}
	free(neigh);
	return true;
}

time_interval Effective_Propagation_Delay(NETSIM_ID d,NETSIM_ID I)
{
	if (!lan_delay_enabled(d,I) == false)
		return Propagation_delay_default;

	time_interval delay = GET_PIM_VAR(d)->propagationDelay;
	UINT c;
	ptrPIM_NEIGHBOR* neigh = get_all_neigh_for_interface(d, I, &c);
	UINT i;

	for (i = 0; i < c; i++)
	{
		if (neigh[i]->propagation_delay > delay)
			delay = neigh[i]->propagation_delay;
	}
	free(neigh);
	return delay;
}

time_interval Effective_Override_Interval(NETSIM_ID d, NETSIM_ID I)
{
	if (!lan_delay_enabled(d, I) == false)
		return t_override_default;

	time_interval delay = GET_PIM_VAR(d)->overrideInterval;
	UINT c;
	ptrPIM_NEIGHBOR* neigh = get_all_neigh_for_interface(d, I, &c);
	UINT i;

	for (i = 0; i < c; i++)
	{
		if (neigh[i]->override_interval > delay)
			delay = neigh[i]->override_interval;
	}
	free(neigh);
	return delay;
}

bool Suppression_Enabled(NETSIM_ID d, NETSIM_ID I)
{
	if (lan_delay_enabled(d, I) == false)
		return true;

	UINT c;
	ptrPIM_NEIGHBOR* neigh = get_all_neigh_for_interface(d, I, &c);
	UINT i;

	for (i = 0; i < c; i++)
	{
		if (neigh[i]->tracking_support == false)
		{
			free(neigh);
			return true;
		}
	}
	free(neigh);
	return false;
}
