/************************************************************************************
* Copyright (C) 2016
* TETCOS, Bangalore. India															*

* Tetcos owns the intellectual property rights in the Product and its content.     *
* The copying, redistribution, reselling or publication of any or all of the       *
* Product or its content without express prior written consent of Tetcos is        *
* prohibited. Ownership and / or any other right relating to the software and all  *
* intellectual property rights therein shall remain at all times with Tetcos.      *
* Author:	Shashi Kant Suman														*
* ---------------------------------------------------------------------------------*/
#include "EnumString.h"

BEGIN_ENUM(RPL_Subevent)
{
	DECL_ENUM_ELEMENT_WITH_VAL(RPL_SEND_DIS, NW_PROTOCOL_RPL * 100),
	DECL_ENUM_ELEMENT(RPL_SEND_DIO),
	DECL_ENUM_ELEMENT(RPL_SEND_DAO),
	DECL_ENUM_ELEMENT(RPL_TRICKLE_T_TIMEOUT),
	DECL_ENUM_ELEMENT(RPL_TRICKLE_I_TIMEOUT),
	DECL_ENUM_ELEMENT(RPL_NEW_PREF_PARENT),
	DECL_ENUM_ELEMENT(RPL_DAO_ROUTE_TIMEOUT),
}
#pragma warning(disable:4028)
END_ENUM(RPL_Subevent);
#pragma warning(default:4028)
