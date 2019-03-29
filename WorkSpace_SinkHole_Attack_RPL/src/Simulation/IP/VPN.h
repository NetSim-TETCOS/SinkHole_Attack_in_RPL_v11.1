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
/** Data structure to store the VPN */
typedef struct stru_VPN
{
	unsigned int nConnectedDeviceCount;
	NETSIM_IPAddress* LocalIP;
	NETSIM_IPAddress* InternetIP;
}VPN;
/** Structure to store the VPN packet. */
typedef struct stru_VPN_Packet
{	
	NETSIM_IPAddress sourceIP; ///< Original source	
	NETSIM_IPAddress destIP;  ///< Original destination	
	void* ipVar;	///< Original IP header
	PACKET_TYPE nPacketType; ///< Original packet type
	unsigned int nControlPacketType; ///< Original control packet type
}VPN_PACKET;

NETSIM_IPAddress getVirtualIP(NETSIM_ID ndeviceId);
