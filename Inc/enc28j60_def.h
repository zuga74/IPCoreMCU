/*
 * enc28j60_def.h
 *
 *  Created on: 21 мая 2021 г.
 *      Author: lenovo
 */

#ifndef INC_ENC28J60_DEF_H_
#define INC_ENC28J60_DEF_H_

#include "main.h"
#include "stm32f1xx_hal.h"


#define ETHERNET_CS_DELAY	0

#define ETHERNET_CS_PIN		ETHERNET_CS_PIN_Pin
#define ETHERNET_CS_GPIO	ETHERNET_CS_PIN_GPIO_Port

#define ETHERNET_RES_PIN	ETHERNET_RES_PIN_Pin
#define ETHERNET_RES_PORT	ETHERNET_RES_PIN_GPIO_Port

#define ETHERNET_LED_PIN	B_BUSY_Pin
#define ETHERNET_LED_GPIO	B_BUSY_GPIO_Port


#endif /* INC_ENC28J60_DEF_H_ */
