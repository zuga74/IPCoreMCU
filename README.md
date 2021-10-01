IP core for microcontrollers

Includes TCP, UDP, DNS, DHCP, ICMP

The kernel is written on the basis of:
http://we.easyelectronics.ru/electro-and-pc/podklyuchenie-mikrokontrollera-k-lokalnoy-seti-zaklyuchenie.html

The IP core is located in the /IPCore folder

For use in any project:

Include files /IPCore/IPCore.h and /IPCore/IPCore.c

Create IPCore_def.h file and connect it to the project.

If necessary, override the constants in this file and connect other modules.


EXAMPLE:

```
//call eth_recv function when Ethenet packet arrives:
eth_len = enc28j60PacketReceive (sizeof (buf), buf);
if (eth_len> 0) eth_recv (buf, eth_len);

//check the receipt of DHCP addresses by the dhcp_resolve function
if (!dhcp_resolve()) return;

//to send a UDP packet, call the function:
uint8_t udp_send(uint32_t to_addr, uint16_t to_port, uint16_t from_port, uint8_t *data, uint16_t data_len);

//to get the ip address of a host by name, call the DNS function:
uint32_t dns_resolve(char * node_name);

//for TCP client use functions (id is the connection number):
uint8_t tcp_send_connect(int32_t to_addr, uint16_t to_port, uint16_t from_port);
uint8_t tcp_send _...(uint8_t id, uint8_t * data, uint16_t data_len)
uint8_t TCP_SEND_CLOSE(uint8_t id)
```



You need to write functions in your program:

```
//for time:
uint32_t get_ms (void)

//to send an Ethenet package:
void eth_send (uint8_t * data, uint16_t data_len)

//for TCP:
void tcp_recv (uint8_t id, uint8_t * data, uint16_t data_len)
void tcp_recv_connected (uint8_t id)
void tcp_recv_closed (uint8_t id, uint8_t why)

//for TCP server function:
uint8_t tcp_accept (uint32_t from_addr, uint16_t from_port, uint16_t to_port)

//for UDP:
void udp_recv (uint32_t from_addr, uint16_t from_port, uint16_t to_port, uint8_t * data, uint16_t data_len)

//for DHCP
void dhcp_complete (void)
```

An example of use is built on the STM32F105VCTx microcontroller
STM32 CUBE MX Project - myIPCore.ioc file
The build is done using a makefile in the current directory
compiler arm-none-eabi-gcc
(originally used Windows 10 and Eclipse)
The example is compiled from the address 0x800A000
To build from address 0x8000000
Install in STM32F105VCTx_FLASH.ld file:
FLASH (rx): ORIGIN = 0x8000000, LENGTH = 256KK
and put in the system_stm32f1xx.c file
#define VECT_TAB_OFFSET 0x00000000U

Libraries in example used:
Ethernet enc28j60 driver for stm32
Folder /stm32-enc28j60 https://github.com/xaionaro/stm32-enc28j60
Universal string handler for user console interface Copyright (C) 2011, ChaN, all right reserved.
/Xprintf folder



---------------------------------- RUS -------------------------------------------------------------

IP ядро для микроконтроллеров

Включает TCP, UDP, DNS, DHCP, ICMP

Ядро написано на базе:
http://we.easyelectronics.ru/electro-and-pc/podklyuchenie-mikrokontrollera-k-lokalnoy-seti-zaklyuchenie.html 

Ядро IP находиться в папке /IPCore

Для использования в любом проекте:

Подключить файлы /IPCore/IPCore.h и /IPCore/IPCore.с

Создать файл IPCore_def.h и подключить его к проекту. 

Если необходимо в этом файле переопределить константы и подключить другие модули.



ПРИМЕР:

```
//вызывать функцию eth_recv при приходе Ethenet пакета:
eth_len = enc28j60PacketReceive(sizeof(buf), buf);
if (eth_len > 0) eth_recv(buf, eth_len);

//проверять получение DHCP адресов функцией dhcp_resolve
if (!dhcp_resolve()) return;

//для отправки UDP пакета вызвать функцию: 
uint8_t udp_send(uint32_t to_addr, uint16_t to_port, uint16_t from_port, uint8_t *data, uint16_t data_len);

//для получения ip адреса хоста по названию вызвать DNS функцию:
uint32_t dns_resolve(char * node_name);

//для TCP клиента использовать функции (id это номер соединения):
uint8_t tcp_send_connect(int32_t to_addr, uint16_t to_port, uint16_t from_port);
uint8_t tcp_send_...(uint8_t id, uint8_t * data, uint16_t data_len)
uint8_t TCP_SEND_CLOSE(uint8_t id)
```

В своей программе необходимо написать функции:

```
//для времени:
uint32_t get_ms(void)

//для отправки Ethenet пакета:
void eth_send(uint8_t * data, uint16_t data_len)

//для TCP:
void tcp_recv(uint8_t id, uint8_t * data, uint16_t data_len)
void tcp_recv_connected(uint8_t id)
void tcp_recv_closed(uint8_t id, uint8_t why)

//для TCP сервера функцию:
uint8_t tcp_accept(uint32_t from_addr, uint16_t from_port, uint16_t to_port)

//для UDP:
void udp_recv(uint32_t from_addr, uint16_t from_port, uint16_t to_port, uint8_t * data, uint16_t data_len)

//для DHCP
void dhcp_complete(void)
```

Пример использования собран на микроконтроллере STM32F105VCTx
Проект STM32 CUBE MX - файл myIPCore.ioc
Сборка осуществляется с использованием make файла в текущем каталоге
компилятор arm-none-eabi-gcc
(в оригинале использовалась Windows 10 и Eclipse)
Пример собран с адреса 0x800A000
Для сборки с адреса 0x8000000
Установить в файле STM32F105VCTx_FLASH.ld: 
FLASH (rx)      : ORIGIN = 0x8000000, LENGTH = 256KK 
и в файле system_stm32f1xx.c поставить 
#define VECT_TAB_OFFSET  0x00000000U 

Используемые в примере библиотеки:
Ethernet enc28j60 driver for stm32
Папка /stm32-enc28j60 https://github.com/xaionaro/stm32-enc28j60
Universal string handler for user console interface Copyright (C) 2011, ChaN, all right reserved.
Папка /xprintf 




