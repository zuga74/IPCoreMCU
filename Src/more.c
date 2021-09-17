/*
 * more.c
 *
 *  Created on: 21 мая 2021 г.
 *      Author: lenovo
 */

#include "more.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>


#include "IPCore.h"
#include "xprintf.h"
#include "ulog.h"



void ip_to_str(uint32_t ip, char * str)
{
	uint8_t * ipaddr = (uint8_t *)&ip;
	xsprintf(str, "%d.%d.%d.%d", ipaddr[0], ipaddr[1], ipaddr[2], ipaddr[3]);
}

char * ip2str(uint32_t ip)
{
	static char __ip2str[16];

	ip_to_str(ip, __ip2str);
	return __ip2str;
}


uint32_t str2ip(char * str)
{
  char * ptr = str;
  int i = 0;
  uint32_t res = 0;
  uint8_t * ipaddr = (uint8_t *)&res;

  do
  {
    ipaddr[i] = (unsigned char)atoi(ptr);
    ++i;
    if ( (ptr = strchr(ptr, '.')) != NULL ) ++ptr;
  }
  while (ptr != NULL);

  return res;
}


void mac_to_str(uint8_t * mac, char * str)
{
	xsprintf(str, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

char * mac2str(uint8_t * mac)
{
	static char __mac2str[18];

	mac_to_str(mac, __mac2str);
	return __mac2str;
}


void get_passed_day_from_ms(uint32_t ms, int * day, int * hour, int * min, int *sec, int * msec)
{
  int passed_sec = ms / 1000; //прошло секунд
  *msec = ms -  passed_sec * 1000;

  int passed_min = passed_sec / 60; //прошло минут
  *sec = passed_sec -  passed_min * 60;

  int passed_hour = passed_min / 60; //прошло часов
  *min = passed_min -  passed_hour * 60;

  *day = passed_hour / 24; //прошло дней
  *hour = passed_hour -  *day * 24;
}

void print_frame_k12(uint8_t * data, uint16_t data_len)
{
	char str[64];
	int day, hour, min, sec, msec;

	get_passed_day_from_ms(get_ms(), &day, &hour, &min, &sec, &msec);


	ulog("\r\n+---------+---------------+----------+\r\n");

	xsprintf(str, "%02d:%02d:%02d,%03d,000   ETHER\r\n", hour, min, sec, msec);
	ulog(str);


	ulog("|0   |");
	for (uint16_t i = 0; i < data_len; ++i) {
		if (data[i] == 0) strcpy(str, "00|");
		else if (data[i] == 1) strcpy(str, "01|");
		else if (data[i] == 2) strcpy(str, "02|");
		else if (data[i] == 3) strcpy(str, "03|");
		else if (data[i] == 4) strcpy(str, "04|");
		else if (data[i] == 5) strcpy(str, "05|");
		else if (data[i] == 6) strcpy(str, "06|");
		else if (data[i] == 7) strcpy(str, "07|");
		else if (data[i] == 8) strcpy(str, "08|");
		else if (data[i] == 9) strcpy(str, "09|");
		else if (data[i] == 10) strcpy(str, "0a|");
		else if (data[i] == 11) strcpy(str, "0b|");
		else if (data[i] == 12) strcpy(str, "0c|");
		else if (data[i] == 13) strcpy(str, "0d|");
		else if (data[i] == 14) strcpy(str, "0e|");
		else if (data[i] == 15) strcpy(str, "0f|");
		else {
			itoa(data[i], str , 16);
			strcat(str, "|");
		}
		ulog(str);
	}
	ulog("\r\n");
}

//парсим урл
void parse_url(char * url, char * sheme, char * host, char * path, unsigned short * port)
{
  char * pch = url;
  char * pche, * pchb, * pcht;
  int l;
  int len = l = strlen(url);

  sheme[0] = 0;
  host[0] = 0;
  path[0] = 0;
  *port = 0;

  if ( NULL != (pch = strnstr(url, "://", l)) )
  {
     memcpy(sheme, url, pch - url);
     sheme[pch - url] = 0;
     pch += 3;
     l = len - (pch - url);
  } else pch = url;

  if ( NULL == (pche = strnstr(pch, "/", l)) )
    pche = pch + l;

  pchb = pche;
  if ( NULL != (pcht = strnstr(pch, ":", pche - pch)) )
  {
    *port = atoi(pcht + 1);
    pche = pcht;
  }
  else *port = 0;

  memcpy(host, pch, pche - pch);
  host[pche - pch] = 0;
   pch = pchb;
  l = len - (pch - url);

  memcpy(path, pch, l);
  path[l] = 0;
  if (strlen(path) == 0) { path[0] = '/'; path[1] = 0; }
}


