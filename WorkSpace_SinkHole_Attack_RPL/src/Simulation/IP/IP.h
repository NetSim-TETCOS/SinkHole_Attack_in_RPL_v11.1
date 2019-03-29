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
#ifndef _NETSIM_IP_H_
#define _NETSIM_IP_H_
#ifdef  __cplusplus
extern "C" {
#endif
#ifndef _NETSIM_IP_LIB_
#pragma comment(lib,"IP.lib")
#endif

//#define PRINT_MATCH_TABLE

#define IP_IGMP_STATUS_DEFAULT	false
#define IP_PIM_STATUS_DEFAULT	false
#define IP_ICMP_STATUS_DEFAULT	false
#define IP_STATIC_IP_ROUTE_DEFAULT _strdup("")

#define on_link				NULL
#define DEFAULT_METRIC		999
#define ONLINK_METRIC		300
#define MULTICAST_METRIC	306
#define IPV4_HEADER_SIZE	20
#define PROTOCOL_VPN		1
#define VPN_METRIC			200

#define GET_IP_DEVVAR(d) (DEVICE_NWLAYER(d)?(IP_DEVVAR*)(DEVICE_NWLAYER(d)->ipVar):NULL)

	typedef struct stru_IP_DevVar IP_DEVVAR;
	/// Enumeration for routing types
	typedef enum
	{
		RoutingType_string,
		RoutingType_DEFAULT=1,
		RoutingType_STATIC,
	}ROUTING_TYPE;

	/// Enumeration for IP control packets
	typedef enum
	{
		//ICMP Packet
		PACKET_ICMP_DstUnreachableMsg=NW_PROTOCOL_IPV4*100+10,
		PACKET_ICMP_ECHORequest,
		PACKET_ICMP_ECHOReply,
		PACKET_ROUTER_ADVERTISEMENT,

		//VPN
		PACKET_VPN = NW_PROTOCOL_IPV4*100+20,
		
		//IGMP Packet
		PACKET_IGMP_QUERY = NW_PROTOCOL_IPV4*100+30,
		PACKET_IGMP_REPORT,
		PACKET_IGMP_LEAVE,

		//PIM Packet
		PACKET_PIM_HELLO = NW_PROTOCOL_IPV4*100+40,
		PACKET_PIM_REGISTER,
		PACKET_PIM_REGISTERSTOP,
		PACKET_PIM_JOINPRUNE,
		PACKET_PIM_BOOTSTRAP,
		PACKET_PIM_ASSERT,
		PACKET_PIM_GRAFT,
		PACKET_PIM_GRAFTACK,
		PACKET_PIM_CANDRPADVER,
	}IP_CONTROL_PACKET;
#define isPIMPacket(packet) (packet->pstruNetworkData->IPProtocol == IPPROTOCOL_PIM)

	/// Enumeration for ip sub-events.
	typedef enum
	{
		//ICMP
		EVENT_ICMP_POLL=NW_PROTOCOL_IPV4*100+1,
		EVENT_ADVERTISE_ROUTER,

		//IGMP
		EVENT_IGMP_Unsolicited_report,
		EVENT_IGMP_SendStartupQuery,
		EVENT_IGMP_SendQuery,
		EVENT_IGMP_OtherQuerierPresentTimer,
		EVENT_IGMP_DelayTimer,
		EVENT_IGMP_GroupMembershipTimer,

		//PIM
		EVENT_PIM_SEND_HELLO,
		EVENT_PIM_NEIGHBOR_TIMEOUT,
		EVENT_PIM_JT,
		EVENT_PIM_ET,

		EVENT_IP_INIT_TABLE,

		//PING
		EVENT_ICMP_SEND_ECHO,
	}IP_SUBEVENT;

	//http://www.cisco.com/en/US/docs/net_mgmt/ciscoworks_ip_communications_operations_manager/1.0/user/guide/SNMPInfo.html#wp1024287
	/// Enumeration for IP gateway states.
	typedef enum
	{
		GATEWAYSTATE_UP,
		GATEWAYSTATE_DOWN,
		GATEWAYSTATE_NOTIFICATION_PENDING,
		GATEWAYSTATE_CLEARANCE_PENDING,
	}IP_GATEWAYSTATE;
	/// Enumeration for VPN states.
	typedef enum
	{
		VPN_DISABLE=0,
		VPN_SERVER,
		VPN_CLIENT,
	}VPN_STATE;

	typedef enum
	{
		ACTION_DROP,
		ACTION_MOVEUP,
		ACTION_REROUTE,
	}IP_PROTOCOL_ACTION;

	typedef struct ForwardRoute 
	{
		UINT count;
		NETSIM_IPAddress* nextHop;
		NETSIM_IPAddress* gateway;
		NETSIM_ID* interfaceId;
		NETSIM_ID* nextHopId;
		struct ForwardRoute* next;
	}IP_FORWARD_ROUTE,*ptrIP_FORWARD_ROUTE;

/// Structure to store ip routing table
typedef struct stru_NetSim_IPRoutingTable
{
	NETSIM_IPAddress networkDestination;
	NETSIM_IPAddress netMask;
	NETSIM_IPAddress gateway;
	UINT interfaceCount;
	NETSIM_IPAddress* Interface;
	unsigned int prefix_len;
	unsigned int Metric;
	ROUTING_TYPE type;
	char* szType;
	_ele* ele;
	double update_time;
	//NetSim specific
	NETSIM_ID* nInterfaceId;
	NETSIM_ID nGatewayId;
}IP_ROUTINGTABLE, *ptrIP_ROUTINGTABLE,**pptrIP_ROUTINGTABLE;
/*
3.1.  Internet Header Format

  A summary of the contents of the internet header follows:

									
	0                   1                   2                   3   
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

					Example Internet Datagram Header

							   Figure 4.
*/
/*typedef struct stru_IP_Option
{
	unsigned int optType;
	unsigned int optLen;
	void* option;
	struct stru_IP_Option* next;
}IP_OPTION;
struct stru_NetSim_IPHeader
{
	unsigned int version:4;
	unsigned int IHL:4;
	unsigned int TypeofService:8;
	unsigned int TotalLength:16;
	unsigned int Identification:16;
	unsigned int flags:3;
	unsigned int FragmentOffset:13;
	unsigned int TimetoLive:8;
	unsigned int Protocol:8;
	unsigned int HeaderChecksum:16;
	NETSIM_IPAddress SourceAddress;
	NETSIM_IPAddress DestinationAddess;
	IP_OPTION* options;
	unsigned int Padding;
};*/

/// Structure to store the device ip details
struct stru_IP_DevVar
{
	//Static IP table file
	char* staticIPTableFile;

	//Firewall variable
	void* ACL;
	bool isFirewallConfigured;
	char* firewallConfig;
	
	//ICMP Variable
	bool isICMP;
	//Router Advertisement
	unsigned int nRouterAdvertisementFlag; 
	unsigned int nRouterAdverMinInterval;
	unsigned int nRouterAdverMaxInterval;
	unsigned int nRouterAdverLifeTime;
	//ICMP POLL
	unsigned int nICMPPollingTime;
	unsigned int nGatewayCount;
	NETSIM_IPAddress* GatewayIPAddress;
	NETSIM_ID* nGatewayId;
	NETSIM_ID* nInterfaceId;
	IP_GATEWAYSTATE* nGatewayState;

	//VPN variable
	VPN_STATE nVPNStatus;	/*	0--Disable
								1--Server
								2--Client */
	//Client variable
	NETSIM_IPAddress serverIP;
	//Server variable
	NETSIM_IPAddress ipPoolStart;
	NETSIM_IPAddress ipPoolEnd;
	NETSIM_IPAddress ipPoolMask;
	void* vpn;
	void* dnsList;

	//DHCP
	void* dhcp;

	//Multicast
	void* multicast;

	//IGMP
	bool isIGMPConfigured;
	void* igmp;

	//PIM
	bool isPIMConfigured;
	void* pim;
};
/// Structure to store the IP metrics.
struct stru_IP_Metrics
{
	NETSIM_ID nDeviceId;
	unsigned int nPacketSent;
	unsigned int nPacketReceived;
	unsigned int nPacketForwarded;
	unsigned int nPacketDiscarded;
	unsigned int nFirewallBlocked;
	unsigned int nTTLDrop;
};
struct stru_IP_Metrics** ipMetrics;
/// Data structure for dns.
typedef struct stru_dnsList
{
	NETSIM_ID deviceId;
	NETSIM_IPAddress ip;
	_ele* ele;
}DNS;
#define DNS_ALLOC() (struct stru_dnsList*)list_alloc(sizeof(struct stru_dnsList),offsetof(struct stru_dnsList,ele))

#define IPROUTINGTABLE_ALLOC() (ptrIP_ROUTINGTABLE)list_alloc(sizeof(IP_ROUTINGTABLE),offsetof(IP_ROUTINGTABLE,ele))
#define IPROUTINGTABLE_ADD(table,current,fun) list_add(((void**)(table)),current,offsetof(IP_ROUTINGTABLE,ele),fun)


//Lib function
int iptable_add_check(ptrIP_ROUTINGTABLE current,ptrIP_ROUTINGTABLE mem);
ptrIP_ROUTINGTABLE iptable_check(ptrIP_ROUTINGTABLE* table,NETSIM_IPAddress dest,NETSIM_IPAddress subnet);
int iptable_change(ptrIP_WRAPPER wrapper,
				   NETSIM_IPAddress dest,
				   NETSIM_IPAddress subnet,
				   UINT prefix_len,
				   NETSIM_IPAddress gateway,
				   UINT interfaceCount,
				   NETSIM_IPAddress* interfaceIp,
				   NETSIM_ID* interfaceId,
				   unsigned int metric);
int iptable_change_byRoute(ptrIP_WRAPPER wrapper,
						   ptrIP_ROUTINGTABLE route,
						   NETSIM_IPAddress dest,
						   NETSIM_IPAddress subnet,
						   unsigned int prefix_len,
						   NETSIM_IPAddress gateway,
						   UINT interfaceCount,
						   NETSIM_IPAddress* interfaceIp,
						   NETSIM_ID* interfaceId,
						   unsigned int metric);
int iptable_delete(ptrIP_WRAPPER wrapper,
				   NETSIM_IPAddress dest,
				   NETSIM_IPAddress in);
int iptable_delete_by_type(ptrIP_WRAPPER wrapper,
						   char* type);
int iptable_delete_by_route(ptrIP_WRAPPER wrapper,
							ptrIP_ROUTINGTABLE route);
ptrIP_ROUTINGTABLE iptable_add(ptrIP_WRAPPER wrapper,
							 NETSIM_IPAddress dest,
							 NETSIM_IPAddress subnet,
							 unsigned int prefix_len,
							 NETSIM_IPAddress gateway,
							 UINT interfaceCount,
							 NETSIM_IPAddress* interfaceIp,
							 NETSIM_ID* interfaceId,
							 unsigned int metric,
							 char* type);
int iptable_print(FILE* fp, ptrIP_ROUTINGTABLE routeTable);
ptrIP_ROUTINGTABLE* iptable_get_table_by_type(ptrIP_ROUTINGTABLE table, char* type, UINT* count);

_declspec(dllexport) NETSIM_IPAddress dns_query(NETSIM_ID nDeviceId,NETSIM_ID id);

//VPN
_declspec(dllexport) int fn_NetSim_IP_VPN_Run();

//IP Routing
ptrIP_FORWARD_ROUTE fn_NetSim_IP_RoutePacket(NetSim_PACKET* packet,
											 NETSIM_ID dev);
ptrIP_FORWARD_ROUTE fn_NetSim_IP_RoutePacketViaStaticEntry(NetSim_PACKET* packet, NETSIM_ID dev);
void pass_to_lower_layer(NetSim_PACKET* packet, ptrIP_FORWARD_ROUTE route, UINT c);

//NAT
int fn_NetSim_NAT_NetworkOut(NETSIM_ID ndev,NetSim_PACKET* packet);
int fn_NetSim_NAT_NetworkIn(NETSIM_ID ndev,NetSim_PACKET* packet);

//ICMP
void ICMP_copyPacket(NetSim_PACKET* d, NetSim_PACKET* s);
void process_icmp_packet();
_declspec(dllexport) int ICMP_CHECKSTATE(NETSIM_IPAddress ip);

//Multicast
void multicast_join_group();
IP_PROTOCOL_ACTION check_ip_in_multicastgroup(NETSIM_IPAddress ip, NETSIM_ID d, NetSim_PACKET* packet);
bool is_reserved_multicast_address(NETSIM_IPAddress ip);
bool isCorrectRoute(pptrIP_ROUTINGTABLE table, NETSIM_IPAddress dest, NETSIM_IPAddress src);

//IGMP
void igmp_configure(NETSIM_ID d, void* xmlNode);
void igmp_init(NETSIM_ID d);
void igmp_host_join_group(NETSIM_ID d, NETSIM_IPAddress group);
void host_handle_unsolicited_report_timer();
void process_igmp_packet();
void IGMP_FreePacket(NetSim_PACKET* packet);
IP_PROTOCOL_ACTION host_is_ip_present_in_db(NETSIM_ID d, NETSIM_IPAddress ip, NetSim_PACKET* packet);
IP_PROTOCOL_ACTION router_is_ip_present_in_db(NETSIM_ID d, NETSIM_IPAddress ip, NetSim_PACKET* packet);
void send_query_msg(NETSIM_ID d, NETSIM_IPAddress groupAddr, double time);
void igmp_router_processOtherQuerierPresentTime();
void host_send_report();
void igmp_router_ProcessGroupMembershipTimer();
void copy_igmp_packet(NetSim_PACKET* d, NetSim_PACKET* s);
void igmp_free(NETSIM_ID d);

//PIM
void pim_configure(NETSIM_ID d, void* xmlNetSimNode);
void Router_PIM_Init(NETSIM_ID d);
void pim_handle_timer_event();
void pim_join_group(NETSIM_ID d, NETSIM_IPAddress group);
IP_PROTOCOL_ACTION pim_decide_action(NetSim_PACKET* packet, NETSIM_ID d);
void process_pim_packet();

//PCAP writer
void ip_write_to_pcap(NetSim_PACKET* packet,
					  NETSIM_ID d,
					  NETSIM_ID i,
					  double time);

//Ping
_declspec(dllexport) void* ICMP_StartPingRequest(NETSIM_ID src,
												 NETSIM_ID dest,
												 UINT count,
												 bool(*resp)(void*, char*, bool),
												 void* arg);
void icmp_send_echo_request();

#ifdef  __cplusplus
}
#endif
#endif