/*
 * more.h
 *
 *  Created on: 21 мая 2021 г.
 *      Author: lenovo
 */

#ifndef MORE_H_
#define MORE_H_

#include "stm32f1xx_hal.h"

char * ip2str(uint32_t ip);

uint32_t str2ip(char * str);

//void mac_to_str(uint8_t * mac, char * str);

char * mac2str(uint8_t * mac);


void print_frame_k12(uint8_t * data, uint16_t data_len);

//парсим урл
void parse_url(char * url, char * sheme, char * host, char * path, unsigned short * port);


#endif
