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
#include "NetSim_utility.h"

static void create_multicast_group_for_all(NETSIM_IPAddress g, NETSIM_IPAddress r)
{
	NETSIM_ID i;
	for (i = 0; i < NETWORK->nDeviceCount; i++)
	{
		if (isRouter(i + 1) &&
			GET_IP_DEVVAR(i + 1)->isPIMConfigured)
		{
			create_group(i + 1, g, r);
		}
	}
}

void configure_PIM()
{
	FILE* fp;
	char p[BUFSIZ];
	sprintf(p, "%s%s%s", pszIOPath, pathSeperator, "PIM_Config.txt");
	fp = fopen(p, "r");
	if (!fp)
	{
		perror(p);
		return;
	}
	char buf[BUFSIZ];
	while (fgets(buf, BUFSIZ, fp))
	{
		char* s = buf;
		s = lskip(s);

		if (*s == '#')
			continue; //Comment line
		if (*s == 0 || *s == '\n')
			continue; //Empty line

		rstrip(s);

		char* g = NULL;
		char* r = NULL;
		g = s;
		while (s)
		{
			if (*s == ',')
			{
				*s = 0;
				r = s + 1;
				s++;
				break;
			}
			s++;
		}
		r = s;
		while (s)
		{
			if (*s == ',')
			{
				*s = 0;
				//Ignore extra
				break;
			}
			s++;
		}
		if (!g || !r)
		{
			fnNetSimError("Format of PIM_Config file is not correct. It must be \"GROUP_ADDR,RP_ADDR,\"");
			continue;
		}

		NETSIM_IPAddress gip = STR_TO_IP4(g);
		NETSIM_IPAddress rip = STR_TO_IP4(r);

		create_multicast_group_for_all(gip, rip);
	}
}
