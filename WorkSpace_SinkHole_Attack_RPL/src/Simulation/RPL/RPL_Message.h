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

/************************************************************************************
https://tools.ietf.org/html/rfc6550
************************************************************************************/

#define ICMP_TYPE_RPL	0x9B

typedef enum
{
	DODAG_Information_Solicitation = 0x00,
	DODAG_Information_Object = 0x01,
	Destination_Advertisement_Object = 0x02,
	Destination_Advertisement_Object_Acknowledgment = 0x03,
	Secure_DODAG_Information_Solicitation = 0x80,
	Secure_DODAG_Information_Object = 0x81,
	Secure_Destination_Advertisement_Object = 0x82,
	Secure_Destination_Advertisement_Object_Acknowledgment = 0x83,
	Consistency_Check = 0x8A,
}RPL_CTRL_MSG_CODE;

#define GET_RPL_CTRL_PACKET_TYPE(code) (NW_PROTOCOL_RPL*100+code)
#define GET_RPL_CTRL_MSG_CODE(packet) (packet->nControlDataType%100)


typedef enum enum_rpl_option_type
{
	RPLOPTION_Pad1 = 0x00,
	RPLOPTION_PadN,
	RPLOPTION_DAGMetricsContainer,
	RPLOPTION_RoutingInformation,
	RPLOPTION_DODAGConfiguration,
	RPLOPTION_RPLTARGET,
	RPLOPTION_PrefixInformation = 0x08,
}RPL_OPTION_TYPE;
typedef struct stru_rpl_option
{
	RPL_OPTION_TYPE type;
	void* option;
}RPL_OPTION,*PRPL_OPTION;

/* 6.  ICMPv6 RPL Control Message

0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Code      |          Checksum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
.                             Base                              .
.                                                               .
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
.                           Option(s)                           .
.                                                               .
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Figure 6: RPL Control Message
*/

typedef struct stru_rpl_ctrl_message
{
	UINT8 Type;
	UINT8 Code;
	UINT16 Checksum;
	void* Base;
	PRPL_OPTION* options;
	UINT option_count;
}RPL_CTRL_MSG,*PRPL_CTRL_MSG;
#define GET_PRPL_CTRL_MSG(packet) ((PRPL_CTRL_MSG)(PACKET_NWDATA(packet)->Packet_RoutingProtocol))
#define SET_BASE_IN_MSG(packet,b) (GET_PRPL_CTRL_MSG(packet)->Base = b)
#define GET_BASE_FROM_MSG(packet) (GET_PRPL_CTRL_MSG(packet)->Base)
#define RPL_CTRL_MSG_SIZE_FIXED	4 //Bytes


/*
6.2.1.  Format of the DIS Base Object

0                   1                   2
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Flags     |   Reserved    |   Option(s)...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Figure 13: The DIS Base Object
*/
typedef struct stru_rpl_DIS_Base
{
	UINT8 Flags;
	UINT8 Reserved;
}RPL_DIS_BASE,*PRPL_DIS_BASE;
#define RPL_DIS_BASE_SIZE	2 //Bytes


/*
6.3.1.  Format of the DIO Base Object

0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| RPLInstanceID |Version Number |             Rank              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|G|0| MOP | Prf |     DTSN      |     Flags     |   Reserved    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                                                               |
+                            DODAGID                            +
|                                                               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Option(s)...
+-+-+-+-+-+-+-+-+

Figure 14: The DIO Base Object
*/
typedef struct stru_rpl_dio_base
{
	UINT8 RPLInstanceID;
	UINT8 Version_Number;
	UINT16 Rank;
	UINT G : 1;
	UINT zero : 1;
	UINT MOP : 3;
	UINT Prf : 3;
	UINT8 DTSN;
	UINT8 Flags;
	UINT8 Reserved;
	NETSIM_IPAddress DODAGID;
}RPL_DIO_BASE,*PRPL_DIO_BASE;
#define RPL_DIO_BASE_SIZE	24 //Bytes

/*
6.4.1.  Format of the DAO Base Object

0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| RPLInstanceID |K|D|   Flags   |   Reserved    | DAOSequence   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                                                               |
+                            DODAGID*                           +
|                                                               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Option(s)...
+-+-+-+-+-+-+-+-+
*/
typedef struct stru_rpl_dao_base
{
	UINT8 RPLInstanceID;
	UINT K : 1;
	UINT D : 1;
	UINT Flags : 6;
	UINT8 Reserved;
	UINT8 DAOSequence;
	NETSIM_IPAddress DODAGID;
}RPL_DAO_BASE, *PRPL_DAO_BASE;
#define RPL_DAO_BASE_SIZE	20 //Bytes

/*
6.5.1.  Format of the DAO-ACK Base Object

0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| RPLInstanceID |D|  Reserved   |  DAOSequence  |    Status     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                                                               |
+                            DODAGID*                           +
|                                                               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Option(s)...
+-+-+-+-+-+-+-+-+
*/
typedef struct stru_rpl_dao_ack_base
{
	UINT8 RPLInstanceID;
	UINT D : 1;
	UINT Reserved : 7;
	UINT8 DAOSequence;
	UINT8 Status;
	UINT DODAGID[4];
}RPL_DAOACK_BASE,*PRPL_DAOACK_BASE;
#define RPL_DAOACK_BASE_SIZE	20 //Bytes


/*
6.6.1.  Format of the CC Base Object

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       | RPLInstanceID |R|    Flags    |           CC Nonce            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                                                               |
       +                                                               +
       |                                                               |
       +                            DODAGID                            +
       |                                                               |
       +                                                               +
       |                                                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                      Destination Counter                      |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |   Option(s)...
       +-+-+-+-+-+-+-+-+

                       Figure 18: The CC Base Object
*/
typedef struct stru_rpl_cc_base
{
	UINT8 RPLInstanceID;
	UINT R : 1;
	UINT Flags : 7;
	UINT16 CC_Nonce;
	UINT DODAGID[4];
	UINT DestinationCounter;
}RPL_CC_BASE,*PRPL_CC_BASE;

/*
The DODAG Configuration option MAY be present in DIO messages, and
its format is as follows:

0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Type = 0x04 |Opt Length = 14| Flags |A| PCS | DIOIntDoubl.  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  DIOIntMin.   |   DIORedun.   |        MaxRankIncrease        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      MinHopRankIncrease       |              OCP              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Reserved    | Def. Lifetime |      Lifetime Unit            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Figure 24: Format of the DODAG Configuration Option
*/

typedef struct stru_dodag_config_option
{
	UINT8 Type;
	UINT8 OptLength;
	UINT Flags : 4;
	UINT A : 1;
	UINT PCS : 3;
	UINT8 DIOIntDoubl;
	UINT8 DIOIntMin;
	UINT8 DIORedun;
	UINT16 MaxRankIncrease;
	UINT16 MinHopRankIncrease;
	UINT16 OCP;
	UINT8 Reserved;
	UINT8 DefLifetime;
	UINT16 LifetimeUnit;
}RPL_DODAG_CONFIG_OPTION,*PRPL_DODAG_CONFIG_OPTION;
#define RPL_DODAG_CONFIG_OPTION_SIZE 16 //Bytes

/*
6.7.7.  RPL Target

The RPL Target option MAY be present in DAO messages, and its format
is as follows:

0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Type = 0x05 | Option Length |     Flags     | Prefix Length |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                Target Prefix (Variable Length)                |
.                                                               .
.                                                               .
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Figure 25: Format of the RPL Target Option
*/
typedef struct stru_rpl_target
{
	UINT8 Type;
	UINT8 Option_Length;
	UINT8 Flags;
	UINT8 Prefix_Length;
	NETSIM_IPAddress Traget_Prefix;
}RPL_TARGET_OPTION,*PRPL_TARGET_OPTION;
