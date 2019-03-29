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
#pragma once
#ifndef _NETSIM_PIM_MSG_H_
#define _NETSIM_PIM_MSG_H_
#ifdef  __cplusplus
extern "C" {
#endif

	/*
	Type
	Types for specific PIM messages.  PIM Types are:

	Message Type                          Destination
	---------------------------------------------------------------------
	0 = Hello                             Multicast to ALL-PIM-ROUTERS
	1 = Register                          Unicast to RP
	2 = Register-Stop                     Unicast to source of Register
	packet
	3 = Join/Prune                        Multicast to ALL-PIM-ROUTERS
	4 = Bootstrap                         Multicast to ALL-PIM-ROUTERS
	5 = Assert                            Multicast to ALL-PIM-ROUTERS
	6 = Graft (used in PIM-DM only)       Unicast to RPF'(S)
	7 = Graft-Ack (used in PIM-DM only)   Unicast to source of Graft
	packet
	8 = Candidate-RP-Advertisement        Unicast to Domain's BSR
	*/
	typedef enum enum_pim_msg_type
	{
		PIMMSG_Hello,
		PIMMSG_Register,
		PIMMSG_RegisterStop,
		PIMMSG_JoinPrune,
		PIMMSG_Bootstrap,
		PIMMSG_Assert,
		PIMMSG_Graft,
		PIMMSG_GraftAck,
		PIMMSG_CandidateRPAdvertisement,
	}PIMMSG;

	/*
	The PIM header common to all PIM messages is:

	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|PIM Ver| Type  |   Reserved    |           Checksum            |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	*/
	typedef struct stru_pim_hdr
	{
		UINT PIM_Ver : 4;
		PIMMSG Type : 4;
		UINT8 Reserved;
		UINT16 Checksum;
	}PIM_HDR, *ptrPIM_HDR;
#define PIM_VER 2
#define PIM_HDR_LEN 4 //Bytes

	/*
	Encoded Unicast Address

	An encoded unicast address takes the following format:

	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|  Addr Family  | Encoding Type |     Unicast Address
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+...
	*/
	typedef struct stru_pim_encoded_unicast_addr
	{
		UINT8 addrFamily;
		UINT8 encodingType;
		NETSIM_IPAddress unicastAddr;
	}ENCODED_UNICAST_ADDR, *ptrENCODED_UNICAST_ADDR;
#define ENCODED_UNICAST_ADDR_LEN	6 //Byes for IPV4

	/*
	Encoded Group Address

	Encoded group addresses take the following format:

	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|  Addr Family  | Encoding Type |B| Reserved  |Z|  Mask Len     |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                Group multicast Address
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+...
	*/
	typedef struct stru_pim_encoded_group_addr
	{
		UINT8 addrFamily;
		UINT8 EncodingType;
		UINT B : 1;
		UINT Reserved : 6;
		UINT Z : 1;
		UINT8 MaskLen;
		NETSIM_IPAddress GroupMulticastAddr;
	}ENCODED_GROUP_ADDR, *ptrENCODED_GROUP_ADDR;
#define ENCODED_GROUP_ADDR_LEN	8 //Bytes

	/*
	Encoded Source Address

	An encoded source address takes the following format:

	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	| Addr Family   | Encoding Type | Rsrvd   |S|W|R|  Mask Len     |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                        Source Address
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...
	*/
	typedef struct stru_pim_encoded_source_addr
	{
		UINT8 addrFamily;
		UINT8 encodingType;
		UINT rsrvd : 5;
		UINT S : 1;
		UINT W : 1;
		UINT R : 1;
		UINT8 maskLen;
		NETSIM_IPAddress SourceAddr;
	}ENCODED_SOURCE_ADDR, *ptrENCODED_SOURCE_ADDR;
#define ENCODED_SOURCE_ADDR_LEN	8 //Bytes

	typedef struct stru_pim_hello_option
	{
		UINT16 optionType;
		UINT16 optionLength;
		void* optionValue;
	}PIM_HELLO_OPTION, *ptrPIM_HELLO_OPTION;
#define PIM_HELLO_OPTION_LEN	4 //Bytes

	/*
	OptionType 1: Holdtime

	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|          Type = 1             |         Length = 2            |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|          Holdtime             |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	*/
	typedef struct stru_option_holdtime
	{
		UINT16 holdTime;
	}OPTION_HOLDTIME, *ptrOPTION_HOLDTIME;
#define PIM_OPTION_HOLDTIME_LEN		2 //Bytes
#define PIM_OPTION_HOLDTIME_TYPE	1

	/*
	OptionType 2: LAN Prune Delay

	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|          Type = 2             |          Length = 4           |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|T|      Propagation_Delay      |      Override_Interval        |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	*/
	typedef struct stru_option_lan_prune_delay
	{
		bool T;
		UINT propagationDelay : 15;
		UINT16 overrideInterval;
	}OPTION_LANPRUNEDELAY, *ptrOPTION_LANPRUNEDELAY;
#define PIM_OPTION_LANPRUNEDELAY_LEN	4 // Bytes
#define PIM_OPTION_LANPRUNEDELAY_TYPE	2

	/*
	OptionType 19: DR Priority

	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|          Type = 19            |          Length = 4           |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                         DR Priority                           |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	*/
	typedef struct stru_option_dr_priority
	{
		UINT DRPriority;
	}OPTION_DRPRIORITY, *ptrOPTION_DRPRIORITY;
#define PIM_OPTION_DRPRIORITY_LEN	4 //Bytes
#define PIM_OPTION_DRPRIORITY_TYPE	19

	/*
	OptionType 20: Generation ID

	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|          Type = 20            |          Length = 4           |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                       Generation ID                           |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	*/
	typedef struct stru_option_gen_id
	{
		UINT GenerationId;
	}OPTION_GENERATIONID, *ptrOPTION_GENERATIONID;
#define PIM_OPTION_GENERATIONID_LEN		4 //Bytes
#define PIM_OPTION_GENERATIONID_TYPE	20

	/*
	OptionType 24: Address List

	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|          Type = 24            |      Length = <Variable>      |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|         Secondary Address 1 (Encoded-Unicast format)          |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	...
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|         Secondary Address N (Encoded-Unicast format)          |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	*/
	typedef struct stru_option_addrlist
	{
		UINT c;
		ptrENCODED_UNICAST_ADDR* SeconadayAddr;
	}OPTION_ADDRLIST, *ptrOPTION_ADDRLIST;
#define PIM_OPTION_ADDRLIST_LEN		0 //Bytes .... Not fixed
#define PIM_OPTION_ADDRLIST_TYPE	24

	/*
	4.9.2.  Hello Message Format

	A Hello message is sent periodically by routers on all interfaces.

	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|PIM Ver| Type  |   Reserved    |           Checksum            |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|          OptionType           |         OptionLength          |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                          OptionValue                          |
	|                              ...                              |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                               .                               |
	|                               .                               |
	|                               .                               |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|          OptionType           |         OptionLength          |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                          OptionValue                          |
	|                              ...                              |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	*/

	typedef struct stru_pim_Hello
	{
		PIM_HDR hdr;
		UINT optCount;
		ptrPIM_HELLO_OPTION* option;
	}PIM_HELLO, *ptrPIM_HELLO;
#define PIM_HELLO_LEN 0 //Bytes

	/*
	4.9.3.  Register Message Format

	A Register message is sent by the DR to the RP when a multicast
	packet needs to be transmitted on the RP-tree.  The IP source address
	is set to the address of the DR, the destination address to the RP's
	address.  The IP TTL of the PIM packet is the system's normal
	unicast TTL.

	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|PIM Ver| Type  |   Reserved    |           Checksum            |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|B|N|                       Reserved2                           |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                                                               |
	.                     Multicast data packet                     .
	|                                                               |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	*/
	typedef struct stru_pim_register_msg
	{
		PIM_HDR hdr;
		UINT B : 1;
		UINT N : 1;
		UINT Reserved2 : 30;
		void* multicastDataPacket;
	}PIM_REGISTERMSG, *ptrPIM_REGISTERMSG;

	/*
	4.9.4.  Register-Stop Message Format

	A Register-Stop is unicast from the RP to the sender of the Register
	message.  The IP source address is the address to which the register
	was addressed.  The IP destination address is the source address of
	the register message.

	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|PIM Ver| Type  |   Reserved    |           Checksum            |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|             Group Address (Encoded-Group format)              |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|            Source Address (Encoded-Unicast format)            |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	*/
	typedef struct stru_pim_register_stop_msg
	{
		PIM_HDR hdr;
		ptrENCODED_GROUP_ADDR groupAddr;
		ptrENCODED_SOURCE_ADDR sourceAddr;
	}PIM_REGISTERSTOPMSG, *ptrPIM_REGISTERSTOPMSG;

	/*
	4.9.5.  Join/Prune Message Format

	A Join/Prune message is sent by routers towards upstream sources and
	RPs.  Joins are sent to build shared trees (RP trees) or source trees
	(SPT).  Prunes are sent to prune source trees when members leave
	groups as well as sources that do not use the shared tree.
	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|PIM Ver| Type  |   Reserved    |           Checksum            |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|        Upstream Neighbor Address (Encoded-Unicast format)     |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|  Reserved     | Num groups    |          Holdtime             |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|         Multicast Group Address 1 (Encoded-Group format)      |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|   Number of Joined Sources    |   Number of Pruned Sources    |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|        Joined Source Address 1 (Encoded-Source format)        |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                             .                                 |
	|                             .                                 |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|        Joined Source Address n (Encoded-Source format)        |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|        Pruned Source Address 1 (Encoded-Source format)        |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                             .                                 |
	|                             .                                 |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|        Pruned Source Address n (Encoded-Source format)        |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                           .                                   |
	|                           .                                   |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|         Multicast Group Address m (Encoded-Group format)      |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|   Number of Joined Sources    |   Number of Pruned Sources    |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|        Joined Source Address 1 (Encoded-Source format)        |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                             .                                 |
	|                             .                                 |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|        Joined Source Address n (Encoded-Source format)        |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|        Pruned Source Address 1 (Encoded-Source format)        |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                             .                                 |
	|                             .                                 |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|        Pruned Source Address n (Encoded-Source format)        |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	*/
	typedef struct stru_msg_groups
	{
		ptrENCODED_GROUP_ADDR multicastAddr;
		UINT numJoinedSource;
		UINT numPrunedSource;
		ptrENCODED_SOURCE_ADDR* joinedSourceAddr;
		ptrENCODED_SOURCE_ADDR* pruneSourceAddr;
	}PIM_JOINMSG_GROUP, *ptrPIM_JOINMSG_GROUP;

	typedef struct stru_pim_join_prune_msg
	{
		PIM_HDR hdr;
		ptrENCODED_UNICAST_ADDR unicastAddr;
		UINT8 reserved;
		UINT8 numGroups;
		UINT16 holdTime;
		ptrPIM_JOINMSG_GROUP* groups;
	}PIM_JOINPRUNE_MSG,*ptrPIM_JOINPRUNE_MSG;
#define PIM_JP_MSG_LEN	(ENCODED_UNICAST_ADDR_LEN+4) //Bytes

	//Function pointer
	void* get_PIM_MSG(NetSim_PACKET* packet);
	void set_PIM_MSG(NetSim_PACKET* packet, void* msg);
	void set_pim_hdr(ptrPIM_HDR hdr, PIMMSG type);
	NetSim_PACKET* create_pim_packet(PIMMSG type,
									 void* opt,
									 double time,
									 NETSIM_ID source,
									 NETSIM_IPAddress sourceAddrss,
									 UINT destCount,
									 NETSIM_ID* destList,
									 NETSIM_IPAddress group,
									 UINT ttl);
	void send_pim_msg(NETSIM_ID d, double time, NetSim_PACKET* packet);
	ptrENCODED_UNICAST_ADDR encode_unicast_addr(NETSIM_IPAddress ip);
	ptrENCODED_SOURCE_ADDR encode_source_addr(NETSIM_IPAddress ip, NETSIM_IPAddress subnet);
	ptrENCODED_GROUP_ADDR encode_group_addr(NETSIM_IPAddress ip);

#ifdef  __cplusplus
}
#endif
#endif
