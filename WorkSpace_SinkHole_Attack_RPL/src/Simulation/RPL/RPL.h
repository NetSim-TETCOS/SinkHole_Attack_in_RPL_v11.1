#pragma once
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

/************** RFC's **************************************************************
https://tools.ietf.org/html/rfc6550		//RPL
https://tools.ietf.org/html/rfc6206		//The Trickle Algorithm
************************************************************************************/
#ifndef _NETSIM_RPL_H_
#define _NETSIM_RPL_H_
#ifdef  __cplusplus
extern "C" {
#endif

	//Log settings
// #define DEBUG_RPL
#ifdef DEBUG_RPL
#define DEBUG_RPL_PRINT_DAO_ROUTE_INFOMATION
//#define DEBUG_RPL_TRICKLE
#endif


#include "RPL_Message.h"
	
	//Include necessary lib's
#pragma comment(lib,"NetworkStack.lib")
#pragma comment(lib,"RPLlib.lib")


	/*
	* Maximum amount of timer doubling.
	*
	* The maximum interval will by default be 2^(12+8) ms = 1048.576 s.
	* RFC 6550 suggests a default value of 20
	*/
#define DEFAULT_DIO_INTERVAL_DOUBLINGS	20

	/*
	* The DIO interval (n) represents 2^n ms.
	*
	* According to the specification, the default value is 3 which
	* means 8 milliseconds.
	*/
#define DEFAULT_DIO_INTERVAL_MIN	3
	/*
	* DIO redundancy. To learn more about this, see RFC 6206.
	*
	* RFC 6550 suggests a default value of 10.
	*/
#define DEFAULT_DIO_REDUNDANCY_CONSTANT		10
	/*
	* MinHopRankIncrease is the minimum increase in Rank between a node and any of its DODAG parents
	* RFC 6550 suggests a default value of 256
	*/
#define DEFAULT_MIN_HOP_RANK_INCREASE	256
#define DEFAULT_DAO_DELAY				1 //Second

//Config parameter
#define RPL_NODE_TYPE_DEFAULT				_strdup("ROUTER")
#define RPL_INSTANCE_ID_DEFAULT				15
#define RPL_DIOIntervalDoublings_DEFAULT	DEFAULT_DIO_INTERVAL_DOUBLINGS
#define RPL_DIOIntervalMin_DEFAULT			DEFAULT_DIO_INTERVAL_MIN
#define RPL_DIORedundancyConstant_DEFAULT	DEFAULT_DIO_REDUNDANCY_CONSTANT
#define RPL_MinHopRankIncrease_DEFAULT		(UINT8)DEFAULT_MIN_HOP_RANK_INCREASE
#define RPL_DODAGPreference_DEFAULT			0
#define RPL_DAO_DELAY_DEFAULT				DEFAULT_DAO_DELAY
#define RPL_DIS_INITIAL_DELAY_DEFAULT		200 //Millisecond
#define RPL_DIS_INTERVAL_DEFAULT			100 //Millisecond

#define INFINITE_RANK						0xFFFF
#define RPL_RANK_ROOT						1
#define RPL_MINIMUM_RANK_INCREMENT			1
#define RPL_MAXIMUM_RANK_INCREMENT			16
#define RPL_DEFAULT_DAG_PREF				0 /* least preferred */
#define RPL_DEFAULT_MOP						2 /*Storing Mode of Operation with no Multicast support*/
#define RPL_DEFAULT_POISON_COUNT			4
#define RPL_DEFAULT_DAO_REMOVE_TIMEOUT		(2500*MILLISECOND)

	typedef UINT16 RPL_RANK;
	typedef NETSIM_IPAddress DODAGID;

	//USEFUL MACRO
#define is_rpl_control_packet(packet)	((packet)->nControlDataType/100==NW_PROTOCOL_RPL)
#define is_rpl_configured(d)			(DEVICE_NWLAYER((d)) && DEVICE_NWLAYER((d))->nRoutingProtocolId==NW_PROTOCOL_RPL)


	typedef enum
	{
		RPLNODETYPE_ROOT,
		RPLNODETYPE_ROUTER,
		RPLNODETYPE_LEAF,
	}RPLNODETYPE;

	/* used to coordinate the sequence numbers when multiple roots share the same DODAG id */
	typedef struct seq_num_mapping_t
	{

		UINT8 seq_num;
		NETSIM_IPAddress dodag_id;

	} seq_num_mapping_t;

	typedef struct stru_rpl_neighbor
	{
		NETSIM_ID nodeId;
		RPL_RANK rank;
		bool isParent;
		PRPL_CTRL_MSG lastDIOMSG;
	}RPL_NEIGHBOR, *PRPL_NEIGHBOR;

	typedef struct stru_rpl_root
	{
		DODAGID dodag_id;
		DODAGID configured_dodag_id;
		UINT8 dodag_pref;
		bool  grounded;
		bool  dao_supported;
		bool  dao_trigger;

		UINT8  dio_interval_doublings;
		UINT8  dio_interval_min;
		UINT8  dio_redundancy_constant;

		UINT8  max_rank_inc;
		UINT8  min_hop_rank_inc;

		UINT8 seq_num;
	}RPL_ROOT,*PRPL_ROOT;

	typedef struct stru_rpl_dodag 
	{
		DODAGID dodag_id;
		UINT dodag_pref:3;
		bool grounded;
		bool dao_supported;
		bool dao_trigger;

		UINT8 dio_interval_doublings;
		UINT8 dio_interval_min;
		UINT8 dio_redundancy_constant;

		UINT16 max_rank_inc;
		UINT16 min_hop_rank_inc;

		UINT8 seq_num;
		UINT16 lowest_rank;
		UINT16 rank;

		PRPL_NEIGHBOR* parent_list;
		UINT16 parent_count;
		PRPL_NEIGHBOR* sibling_list;
		UINT16 sibling_count;
		PRPL_NEIGHBOR pref_parent;
	} RPL_DODAG,*PRPL_DODAG;

	typedef struct stru_rpl_node
	{
		//Config variable
		UINT8 RPLInstanceId;
		RPLNODETYPE nodeType;
		double DAODelayTime;
		double DISInitDelay;
		double DISInterval;


		PRPL_ROOT root_info;
		PRPL_DODAG joined_dodag;
		bool storing;

		//RFC 6206 Section 4.1
		struct stru_trickle
		{
			double Imin;	// pow(2, dio_interval_min)
			UINT Imax;		// dio_interval_doublings
			UINT k;			// redundancy_constant
			
			double t;		// trickle_i_doublings_so_far
			double I;		// trickle_i
			UINT8 C;		// trickle_c

			//Sim parameter
			unsigned long long int trickle_i_eventid;
			unsigned long long int trickle_t_eventid;
			double last_trickle_i_schedule_time;
			double last_trickle_t_schedule_time;
		}trickle;

		PRPL_NEIGHBOR* neighbor_list;
		UINT16 neighbor_count;

		UINT8 poison_count_so_far;

		double last_dio_send_time; /* used for detecting collisions by simulating a risk window */

		UINT8 DaoSequence;

		//simulation parameter
		unsigned long long int dao_send_eventid;

	} RPL_NODE,*PRPL_NODE;
#define GET_RPL_NODE(d) ((PRPL_NODE)DEVICE_NWROUTINGVAR(d))





	/************************************************************************/
	/*  Function Prototype                                                  */
	/************************************************************************/
	void print_rpl_log(char* format, ...);

	//Init Function
	void rpl_node_init(NETSIM_ID d);
	void start_as_root(NETSIM_ID d);

	//RPL Utility function
	PRPL_ROOT get_global_root_info();
	bool rpl_node_is_root(PRPL_NODE r);
	bool rpl_node_is_joined(PRPL_NODE r);
	bool rpl_node_is_poisoning(PRPL_NODE r);
	bool rpl_node_is_isolated(PRPL_NODE rpl);

	//Trickle
	void rpl_trickle_reset(NETSIM_ID nDevId);
	void rpl_trickle_handle_t_timeout();
	void rpl_trickle_handle_i_timeout();

	//DODAG
	PRPL_DODAG rpl_dodag_create(PRPL_CTRL_MSG dio_pdu);
	void rpl_dodag_destroy(PRPL_DODAG dodag);
	void join_dodag_iteration(NETSIM_ID d, PRPL_CTRL_MSG dio_pdu);
	void update_dodag_config(NETSIM_ID node, PRPL_CTRL_MSG dio_pdu);

	//RPL Message
	void* get_option_from_msg(PRPL_CTRL_MSG msg, RPL_OPTION_TYPE type);
	void** get_all_option_from_msg(PRPL_CTRL_MSG msg, RPL_OPTION_TYPE type, UINT* count);
	NetSim_PACKET* create_current_dio_message(NETSIM_ID ndevId, double time, bool include_dodag_config);
	void rpl_option_destroy(PRPL_OPTION option);
	PRPL_OPTION rpl_option_copy(PRPL_OPTION option);

	/***RPL Message Processing***/
	void rpl_process_ctrl_msg();
	PRPL_CTRL_MSG rpl_dio_pdu_duplicate(PRPL_CTRL_MSG dio);
	void rpl_node_send_msg(NETSIM_ID ndevid, NetSim_PACKET* packet);
	
	//DIO
	PRPL_CTRL_MSG get_preferred_dodag_dio_pdu(NETSIM_ID d, bool *same, double time);
	NetSim_PACKET* create_root_dio_message(NETSIM_ID ndevId, double time, bool include_dodag_config, bool include_seq_num);
	void rpl_process_dio_msg();
	void rpl_dio_pdu_free(PRPL_CTRL_MSG dio);
	void start_dio_poisoning(NETSIM_ID d);
	void rpl_dio_msg_copy(const NetSim_PACKET* destPacket, const NetSim_PACKET* srcPacket);
	void rpl_dio_msg_destroy(NetSim_PACKET* packet);

	//DAO
	NetSim_PACKET* create_dao_message(NETSIM_ID ndevid, double time, NETSIM_ID parent);
	void create_and_add_rpl_target_option(NetSim_PACKET* dao_pdu, UINT8 prefix_len, NETSIM_IPAddress dest);
	void rpl_send_dao();
	void rpl_process_dao_msg();
	void rpl_dao_msg_destroy(NetSim_PACKET* packet);
	void rpl_dao_msg_copy(const NetSim_PACKET* destPacket, const NetSim_PACKET* srcPacket);
	void rpl_dao_route_timeout();

	//DIS
	void rpl_process_dis_msg();
	void rpl_dis_pdu_send();
	NetSim_PACKET* create_dis_message(NETSIM_ID ndevid, double time);
	void rpl_dis_msg_destroy(NetSim_PACKET* packet);
	void rpl_dis_msg_copy(const NetSim_PACKET* destPacket, const NetSim_PACKET* srcPacket);
	/******/

	//Sequence Number
	void seq_num_mapping_cleanup();
	seq_num_mapping_t *seq_num_mapping_get(NETSIM_IPAddress dodag_id);

	/*** RPL Neighbor ****/
	
	//Neighbor
	void rpl_add_to_neighbor_list();
	PRPL_NEIGHBOR rpl_find_neighbor(NETSIM_ID d, NETSIM_ID r);
	void update_neighbor_dio_message(PRPL_NEIGHBOR neighbor, PRPL_CTRL_MSG dio_pdu);
	void forget_neighbor_messages(PRPL_NODE rpl);
	void free_all_neighbor(PRPL_NODE rpl);
	
	//Parent
	void rpl_node_add_parent(NETSIM_ID d, PRPL_NEIGHBOR parent);
	void rpl_node_remove_all_parents(NETSIM_ID d);
	PRPL_NEIGHBOR rpl_node_find_parent(NETSIM_ID d, NETSIM_ID parent);
#define rpl_node_has_parent(node, parent)	(rpl_node_find_parent(node, parent) != NULL)
	
	//Siblings
	void rpl_node_add_sibling(NETSIM_ID d, PRPL_NEIGHBOR sibling);
	PRPL_NEIGHBOR rpl_node_find_sibling(NETSIM_ID d, NETSIM_ID sibling);
	void rpl_node_remove_all_siblings(NETSIM_ID d);
#define rpl_node_has_sibling(node, sibling)     (rpl_node_find_sibling(node, sibling) != NULL)

	void choose_parents_and_siblings(NETSIM_ID d);
	/*******************/

	//RPL IP Routing
	void rpl_delete_all_route(NETSIM_ID d);
	void rpl_add_route_to_parent(NETSIM_ID d, NETSIM_ID parent);

	//Global
	#define RPL_IP_TO_STR(ip) ((ip)->str_ip)

#ifdef  __cplusplus
}
#endif
#endif
