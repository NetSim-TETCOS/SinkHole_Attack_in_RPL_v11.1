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
#include "IGMP.h"

static FILE* igmp_log = NULL;
static void init_igmp_log()
{
	char str[BUFSIZ];
	sprintf(str, "%s/%s", pszIOPath, "igmp_log.txt");
	igmp_log = fopen(str, "w");
}

static void close_igmp_log()
{
	fclose(igmp_log);
}

void print_igmp_log(char* format, ...)
{
	va_list l;
	va_start(l, format);
	vfprintf(igmp_log, format, l);
	fprintf(igmp_log, "\n");
	fflush(igmp_log);
}

//IGMP Device
void igmp_configure(NETSIM_ID d, void* xmlNode)
{
	ptrIGMP_VAR var = GET_IGMP_VAR(d);
	ptrIGMP_HOST host;
	ptrIGMP_ROUTER router;
	if (!var)
	{
		var = calloc(1, sizeof* var);
		SET_IGMP_VAR(d, var);
	}

	if (isHost(d))
	{
		var->devType = IP_HOST;
		host = GET_IGMP_HOST(d);
		if (!host)
		{
			host = (ptrIGMP_HOST)calloc(1, sizeof* host);
			SET_IGMP_HOST(d, host);
		}
	}
	else if (isRouter(d))
	{
		var->devType = IP_ROUTER;
		router = GET_IGMP_ROUTER(d);
		if (!router)
		{
			router = (ptrIGMP_ROUTER)calloc(1, sizeof* router);
			SET_IGMP_ROUTER(d, router);
		}
	}
	else
		fnNetSimError("IGMP is only for either host or router");

	getXmlVar(&var->RobustnessVar, ROBUSTNESS_VARIABLE, xmlNode, 1, _UINT, IGMP);
	getXmlVar(&var->QueryInterval, QUERY_INTERVAL, xmlNode, 1, _UINT, IGMP);
	getXmlVar(&var->lastMemQueryInterval, LAST_MEMBER_QUERY_INTERVAL, xmlNode, 1, _DOUBLE, IGMP);

	if (isIPHOST(d))
	{
		getXmlVar(&var->UnsolicitedReportInterval, UNSOLICITED_REPORT_INTERVAL, xmlNode, 1, _DOUBLE, IGMP);
		var->UnsolicitedReportInterval *= SECOND;
	}

	if (isIPRouter(d))
	{
		getXmlVar(&var->QueryResponseInterval, QUERY_RESPONSE_INTERVAL, xmlNode, 1, _UINT, IGMP);
	}
}

static double get_subevent_delay(NETSIM_ID d,
								 IP_SUBEVENT sev,
								 NETSIM_IPAddress group)
{
	ptrIGMP_VAR igmp = GET_IGMP_VAR(d);
	switch (sev)
	{
	case EVENT_IGMP_SendStartupQuery:
		return igmp->StartupQueryInterval*0.1*SECOND;
	case EVENT_IGMP_SendQuery:
		return igmp->QueryInterval*0.1*SECOND;
	case EVENT_IGMP_Unsolicited_report:
		return igmp->UnsolicitedReportInterval*NETSIM_RAND_01();
	case EVENT_IGMP_OtherQuerierPresentTimer:
		return igmp->QueryPresentInterval*0.1*SECOND;
	case EVENT_IGMP_DelayTimer:
	{
		ptrIGMP_HOST_DB db = host_get_multicast_db(d, group);
		double t = db->maxResponseTime*0.1*SECOND*NETSIM_RAND_01();
		db->delayTime = t;
		return t;
	}
	case EVENT_IGMP_GroupMembershipTimer:
		return igmp->GroupMembershipInterval*0.1*SECOND;
	default:
		fnNetSimError("Unknown subevnet %d\n", sev);
		return 0;
	}
}

void start_timer(NETSIM_ID d,
						IP_SUBEVENT sev,
						NETSIM_IPAddress addr,
						double time)
{
	NetSim_EVENTDETAILS pevent;
	memset(&pevent, 0, sizeof pevent);

	pevent.dEventTime = time + get_subevent_delay(d, sev, addr);
	pevent.nDeviceId = d;
	pevent.nDeviceType = DEVICE_TYPE(d);
	pevent.nEventType = TIMER_EVENT;
	pevent.nProtocolId = NW_PROTOCOL_IPV4;
	pevent.nSubEventType = sev;
	pevent.szOtherDetails = addr;
	fnpAddEvent(&pevent);
}

void igmp_init(NETSIM_ID d)
{
	if(!igmp_log)
		init_igmp_log();

	if (isIPRouter(d))
		igmp_router_init(d);
	else if (isIPHOST(d))
		igmp_host_init(d);
	else
		fnNetSimError("Device %d is neither host nor router\n", d);

	ptrIGMP_VAR var = GET_IGMP_VAR(d);

	var->GroupMembershipInterval = var->RobustnessVar*
		var->QueryInterval + var->QueryResponseInterval;

	var->QueryPresentInterval = var->RobustnessVar*
		var->QueryInterval + var->QueryResponseInterval / 2;

	var->lastMemQueryCount = var->RobustnessVar;
}

void igmp_free(NETSIM_ID d)
{
	ptrIGMP_VAR v = GET_IGMP_VAR(d);
	if (!v)
		return; //IGMP is not configured

	if (isIPHOST(d))
		host_free(d);
	else if (isIPRouter(d))
		router_free(d);

	free(v);
	SET_IGMP_VAR(d, NULL);
}
