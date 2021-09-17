/*
 * ulog.c
 *
 *  Created on: 20 мая 2021 г.
 *      Author: lenovo
 */

#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include "xprintf.h"

#include "main.h"


//посылка строки через UART
void ulog(char *m)
{
	HAL_UART_Transmit(&huart1, (uint8_t *)m, strlen(m), 1000); //время выполнения примерно 2 млс
}

static char ulog_fmt_buf[1024];

//посылка строки с форматом через UART
void ulog_fmt(const char * fmt, ... )
{

	va_list arg;

	va_start(arg, fmt);


	xvsnprintf(ulog_fmt_buf, sizeof(ulog_fmt_buf), fmt, arg);

	va_end(arg);

	ulog_fmt_buf[1023] = '\0';
	ulog(ulog_fmt_buf);
}
