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

typedef struct stru_isvisited
{
	NETSIM_ID d;
	NETSIM_ID in;
	_ele* ele;
}ISVISITED, *ptrISVISITED;
ptrISVISITED isvisited = NULL;

static bool check_visited(NETSIM_ID d, NETSIM_ID in)
{
	ptrISVISITED t = isvisited;
	while (t)
	{
		if (t->d == d && t->in == in)
			return true;
		t = LIST_NEXT(t);
	}

	t = list_alloc(sizeof(ISVISITED), offsetof(ISVISITED, ele));
	t->d = d;
	t->in = in;
	LIST_ADD_LAST(&isvisited, t);
	return false;
}

static void free_visited()
{
	while (isvisited)
		LIST_FREE(&isvisited, isvisited);
}

static void find_connected_wan_router(NETSIM_ID d, NETSIM_ID in,
									  NETSIM_ID* w, NETSIM_ID* wi)
{
	NETSIM_ID i;
	NETSIM_ID c, ci;

	if (check_visited(d, in))
	{
		*w = 0;
		*wi = 0;
		return;
	}

	NETSIM_ID l = fn_NetSim_Stack_GetConnectedDevice(d, in, &c, &ci);

	if (!c || !ci)
	{
		*w = 0;
		*wi = 0;
		return;
	}

	if (isRouter(c))
	{
		for (i = 0; i < DEVICE(c)->nNumOfInterface; i++)
		{
			if (DEVICE_INTERFACE(c, i + 1)->nInterfaceType == INTERFACE_WAN_ROUTER)
			{
				*w = c;
				*wi = i + 1;
				return;
			}
		}

		*w = 0;
		*wi = 0;
		return;
	}
	else
	{
		for (i = 0; i < DEVICE(c)->nNumOfInterface; i++)
		{
			if (i + 1 == ci)
				continue;
			NETSIM_ID x = 0, xi = 0;
			find_connected_wan_router(c, i + 1, &x, &xi);
			if (x && xi)
			{
				*w = x;
				*wi = xi;
				return;
			}
		}
		*w = 0;
		*wi = 0;
		return;
	}
}

void set_public_ip(NETSIM_ID d)
{
	NETSIM_ID i;

	if (!isHost(d))
		return;

	for (i = 0; i < DEVICE(d)->nNumOfInterface; i++)
	{
		NETSIM_ID w = 0, wi = 0;
		find_connected_wan_router(d, i + 1, &w, &wi);
		free_visited();

		if (w && wi)
		{
			DEVICE_INTERFACE(d, i + 1)->publicIP = DEVICE_NWADDRESS(w, wi);
			printf("Public IP of device %d Interface %d is %s\n", d, i + 1, DEVICE_INTERFACE(d, i + 1)->publicIP->str_ip);
		}
		else
		{
			NETSIM_IPAddress defaultGateway = DEVICE_INTERFACE(d, i + 1)->szDefaultGateWay;
			if (defaultGateway)
			{
				w = fn_NetSim_Stack_GetDeviceId_asIP(defaultGateway, &wi);
				wi = 0;
				NETSIM_ID j = 0;
				for (j = 0; j < DEVICE(w)->nNumOfInterface; j++)
				{
					if (DEVICE_INTERFACE(w, j + 1) &&
						DEVICE_INTERFACE(w, j + 1)->nInterfaceType == INTERFACE_WAN_ROUTER)
					{
						wi = j + 1;
						break;
					}
				}
				if (w && wi)
				{
					DEVICE_INTERFACE(d, i + 1)->publicIP = DEVICE_NWADDRESS(w, wi);
					printf("Public IP of device %d Interface %d is %s\n", d, i + 1, DEVICE_INTERFACE(d, i + 1)->publicIP->str_ip);
				}
			}
		}
	}
}
