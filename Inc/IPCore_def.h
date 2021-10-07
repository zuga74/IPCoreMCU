/*
 * IPCore_def.h
 *
 *  Created on: 21 мая 2021 г.
 *      Author: lenovo
 */

#ifndef INC_IPCORE_DEF_H_
#define INC_IPCORE_DEF_H_

#include "stm32f1xx_hal.h"
#include "ulog.h"
#include "more.h"

#define USE_ICMP

#define USE_UDP

#ifdef USE_UDP
#define USE_DNS
#ifdef USE_DNS
#define USE_DHCP
#endif
#endif

#define USE_TCP


#endif /* INC_IPCORE_DEF_H_ */
