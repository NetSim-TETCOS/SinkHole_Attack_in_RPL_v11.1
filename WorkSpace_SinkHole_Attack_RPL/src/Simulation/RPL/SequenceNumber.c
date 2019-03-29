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

static seq_num_mapping_t ** seq_num_mapping_list = NULL;
static UINT16               seq_num_mapping_count = 0;

void seq_num_mapping_cleanup()
{
	UINT16 i;
	for (i = 0; i < seq_num_mapping_count; i++)
	{
		seq_num_mapping_t *mapping = seq_num_mapping_list[i];

		bool in_use = FALSE;

		UINT16 j;
		for (j = 0; j < NETWORK->nDeviceCount; j++)
		{
			PRPL_NODE rpl = GET_RPL_NODE(j + 1);
			if(!rpl)
				continue; // RPL is not configured for this device.
			if (!rpl_node_is_root(rpl))
			{ /* only root nodes modify sequence numbers */
				continue;
			}
			if (!rpl->root_info->dodag_id)
				fnNetSimError("DODAG Id is NULL. This may occur because some RPL configuration is wrong. Don't know what?");

			if (IP_COMPARE(rpl->root_info->dodag_id, mapping->dodag_id) == 0)
			{
				in_use = TRUE;
				break;
			}
		}

		if (in_use)
		{
			continue;
		}

		for (j = i; j < seq_num_mapping_count - 1; j++)
		{
			seq_num_mapping_list[j] = seq_num_mapping_list[j + 1];
		}

		free(mapping);

		seq_num_mapping_count--;
	}
}

seq_num_mapping_t *seq_num_mapping_get(NETSIM_IPAddress dodag_id)
{
	UINT16 i;
	for (i = 0; i < seq_num_mapping_count; i++)
	{
		seq_num_mapping_t *mapping = seq_num_mapping_list[i];

		if (IP_COMPARE(mapping->dodag_id, dodag_id) == 0)
			return mapping;
	}

	seq_num_mapping_list = realloc(seq_num_mapping_list, (seq_num_mapping_count + 1) * sizeof(seq_num_mapping_t *));

	seq_num_mapping_list[seq_num_mapping_count] = malloc(sizeof(seq_num_mapping_t));
	seq_num_mapping_list[seq_num_mapping_count]->dodag_id = IP_COPY(dodag_id);
	seq_num_mapping_list[seq_num_mapping_count]->seq_num = 1;

	return seq_num_mapping_list[seq_num_mapping_count++];
}
