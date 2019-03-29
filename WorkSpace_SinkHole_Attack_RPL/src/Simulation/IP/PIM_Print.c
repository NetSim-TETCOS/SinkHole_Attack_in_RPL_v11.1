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

static int counter[50];

static print_tree(NETSIM_ID r, NETSIM_ID b, int l1, int l2, int c1, int c2,FILE* fp)
{
	fprintf(fp, "%d,%d,%d,%d,%d,%d\n",
			r, b,
			50 + 80 * c1, 50 + 80 * l1,
			50 + 80 * c2, 50 + 80 * l2);
	fflush(fp);
}

void print_rpt(NETSIM_ID d, ptrPIM_GROUP group, int level, int count,FILE* fp)
{
	UINT c = group->count;
	fprintf(stderr, "%d,%d,%d,%d\n", d, c, level, count);
	if (!c)
		return;
	NETSIM_ID* cid = calloc(c, sizeof* cid);
	NETSIM_ID* cin = calloc(c, sizeof* cin);
	NETSIM_ID f;
	UINT i;
	for (i = 0; i < c; i++)
	{
		NETSIM_ID l = fn_NetSim_Stack_GetConnectedDevice(d,
														 group->ifid[i],
														 &cid[i],
														 &f);
		print_tree(d, cid[i], level, level + 1, count, counter[level + 1], fp);
		cin[i] = counter[level + 1];
		counter[level + 1]++;
	}

	for (i = 0; i < c; i++)
	{
		ptrPIM_GROUP g = pim_find_group(cid[i], group->groupAddress);
		print_rpt(cid[i], g, level + 1, cin[i], fp);
	}
}

void print_RPT_Tree(NETSIM_ID rp, ptrPIM_GROUP group)
{
	int level = 0;
	int count = 0;

	fprintf(stderr, "\n");
	memset(counter, 0, 50 * sizeof* counter);
	FILE* fp = fopen("points.txt", "w");
	print_rpt(rp, group, level, count,fp);
	fclose(fp);
	_getch();
}
