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

/***********************************************************************

Network Working Group                                          J. Postel
Request for Comments:  792                                           ISI
														  September 1981
Updates:  RFCs 777, 760
Updates:  IENs 109, 128

				   INTERNET CONTROL MESSAGE PROTOCOL

						 DARPA INTERNET PROGRAM
						 PROTOCOL SPECIFICATION

*************************************************************************/

#ifndef _NETSIM_ICMP_H_
#define _NETSIM_ICMP_H_
#ifdef  __cplusplus
extern "C" {
#endif

#define ICMP_MAX_RETRY	5
#define ICMP_SEND_TIME	(1*SECOND)

	//Typedef of ICMP message
	typedef struct stru_NetSim_ICMP_DestinationUnreachableMessage ICMP_DestinationUnreachableMessage;
	typedef struct stru_NetSim_ICMP_ECHO ICMP_ECHO;
	typedef struct stru_NetSim_ICMP_RouterAdvertisement ICMP_RouterAdvertisement;

	/** 
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	As per RFC 792 page 3  :
	Destination Unreachable Message

	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             unused                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      Internet Header + 64 bits of Original Data Datagram      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   */
	struct stru_NetSim_ICMP_DestinationUnreachableMessage
	{
		char Type; //3		
		char code;	/**<
						~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
						0 = net unreachable;
						1 = host unreachable;
						2 = protocol unreachable;
						3 = port unreachable;
						4 = fragmentation needed and DF set;
						5 = source route failed.
						~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
					*/		 
		unsigned short int Checksum; /**< 
										The checksum is the 16-bit ones's complement of the one's
										complement sum of the ICMP message starting with the ICMP Type.
										For computing the checksum , the checksum field should be zero.
										This checksum may be replaced in the future.
									*/
		unsigned int unused;		
		void* InternetHeader;	/**<
									The internet header plus the first 64 bits of the original
									datagram's data.  This data is used by the host to match the
									message to the appropriate process.  If a higher level protocol
									uses port numbers, they are assumed to be in the first 64 data
									bits of the original datagram's data.
								*/
	};


	/**
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	RFC 792 page 13
	Echo or Echo Reply Message

	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Identifier          |        Sequence Number        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Data ...
   +-+-+-+-+-
   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   */
	struct stru_NetSim_ICMP_ECHO
	{		
		char Type;	/**<
						~~~~~~~~~~~~~~~~~~~~~~~~~
						8 for echo message;
						0 for echo reply message.
						~~~~~~~~~~~~~~~~~~~~~~~~~
					*/
		char Code; //0		
		unsigned short int Checksum;	 /**<
										  The checksum is the 16-bit ones's complement of the one's
										  complement sum of the ICMP message starting with the ICMP Type.
										  For computing the checksum , the checksum field should be zero.
										  If the total length is odd, the received data is padded with one
										  octet of zeros for computing the checksum.  This checksum may be replaced in the future.
										*/		
		unsigned short int Identifier;  ///< If code = 0, an identifier to aid in matching echos and replies,may be zero.		
		unsigned short int SequenceNumber; ///< If code = 0, a sequence number to aid in matching echos and replies, may be zero.
		void* Data;
	};

/**
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	Network Working Group                                 S. Deering, Editor
	Request for Comments: 1256                            Xerox PARC
														  September 1991


	ICMP Router Advertisement Message

	   0                   1                   2                   3
	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	  |     Type      |     Code      |           Checksum            |
	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	  |   Num Addrs   |Addr Entry Size|           Lifetime            |
	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	  |                       Router Address[1]                       |
	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	  |                      Preference Level[1]                      |
	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	  |                       Router Address[2]                       |
	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	  |                      Preference Level[2]                      |
	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	  |                               .                               |
	  |                               .                               |
	  |                               .                               |


   IP Fields:

	  Source Address        An IP address belonging to the interface
							from which this message is sent.

	  Destination Address   The configured AdvertisementAddress or the
							IP address of a neighboring host.

	  Time-to-Live          1 if the Destination Address is an IP
							multicast address; at least 1 otherwise.


   ICMP Fields:

	  Type                  9

	  Code                  0

	  Checksum              The  16-bit one's complement of the one's
							complement sum of the ICMP message, start-
							ing with the ICMP Type.  For computing the
							checksum, the Checksum field is set to 0.


	  Num Addrs             The number of router addresses advertised
							in this message.

	  Addr Entry Size       The number of 32-bit words of information
							per each router address (2, in the version
							of the protocol described here).

	  Lifetime              The maximum number of seconds that the
							router addresses may be considered valid.

	  Router Address[i],    The sending router's IP address(es) on the
	   i = 1..Num Addrs     interface from which this message is sent.

	  Preference Level[i],  The preferability of each Router Address[i]
	   i = 1..Num Addrs     as a default router address, relative to
							other router addresses on the same subnet.
							A signed, twos-complement value; higher
							values mean more preferable.
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
*/
	struct stru_NetSim_ICMP_RouterAdvertisement
	{
		char Type;	//9
		char Code;	//0
		unsigned short int CheckSum;
		char NumAddrs;
		char AddrEntrySize;
		unsigned short int Lifetime;
		NETSIM_IPAddress* RouterAddress;
		unsigned int* PreferenceLevel;
	};

#ifdef  __cplusplus
}
#endif
#endif