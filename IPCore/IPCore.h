/*
 * IPCore.h
 *
 *  Created on: 20 мая 2021 г.
 *      Author: lenovo
 */

#ifndef IPCORE_IPCORE_H_
#define IPCORE_IPCORE_H_

#include "IPCore_def.h"


#ifndef NULL
#define NULL 0
#endif

#define GET_BIT(v, n) 			((0u == (v & (1<<n))) ? 0u : 1u)
#define SETT_BIT(v, n) 			(v |= (1<<n))
#define CLR_BIT(v, n)       	(v &= (~(1<<n)))
#define INV_BIT(v, n)          	(v ^= (1<<n))

#ifndef RANDOM
#define RANDOM(a) (rand() % (a))
#endif

#ifndef MIN
#define MIN(a,b) (((a) < (b)) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a,b) (((a) > (b)) ? (a) : (b))
#endif

#ifndef BOUND
#define BOUND(low, high, value) MAX(MIN(high, value), low)
#endif


#define IP_BROADCAST (ip_addr | ~ip_mask)

// ---------------------- Conversion ---------------------------------

#define HTONS(a)			((((a)>>8)&0xff)|(((a)<<8)&0xff00))
#define NTOHS(a)			HTONS(a)

#define HTONL(a)			( (((a)>>24)&0xff) | (((a)>>8)&0xff00) |\
							(uint32_t)((((uint64_t)a)<<8) & 0xff0000) |\
							(uint32_t)((((uint64_t)a)<<24) & 0xff000000) )

#define NTOHL(a)			HTONL(a)


#define IPV4ADDR(a,b,c,d)	( ((uint32_t)a) | ((uint32_t)b << 8) |\
								((uint32_t)c << 16) | ((uint32_t)d << 24) )


#pragma pack(push, 1)

// ---------------------- Ethernet ---------------------------------

#define ETH_TYPE_ARP		HTONS(0x0806)
#define ETH_TYPE_IP			HTONS(0x0800)

typedef struct _eth_frame {
	uint8_t to_addr[6];
	uint8_t from_addr[6];
	uint16_t type;
} eth_frame_t;

//размер буфера под отсылаемый ethernet пакет
//the size of the buffer for the sent ethernet packet
#ifndef ETH_BUF_SIZE
#define ETH_BUF_SIZE	1600
#endif

// ---------------------- Arp ---------------------------------

#define ARP_HW_TYPE_ETH		HTONS(0x0001)
#define ARP_PROTO_TYPE_IP	HTONS(0x0800)

#define ARP_TYPE_REQUEST	HTONS(1)
#define ARP_TYPE_RESPONSE	HTONS(2)

typedef struct _arp_message {
	uint16_t hw_type;
	uint16_t proto_type;
	uint8_t hw_addr_len;
	uint8_t proto_addr_len;
	uint16_t type;
	uint8_t mac_addr_from[6];
	uint32_t ip_addr_from;
	uint8_t mac_addr_to[6];
	uint32_t ip_addr_to;
} arp_message_t;

typedef struct _arp_cache_entry {
	uint32_t ip_addr;
	uint8_t mac_addr[6];
} arp_cache_entry_t;

//кол-во записей в ARP таблице
//number of entries in the ARP table
#ifndef ARP_CACHE_SIZE
#define ARP_CACHE_SIZE			10
#endif


// ---------------------- Ip ---------------------------------

#define IP_PROTOCOL_ICMP	1
#define IP_PROTOCOL_TCP		6
#define IP_PROTOCOL_UDP		17

typedef struct _ip_packet {
	uint8_t ver_head_len;
	uint8_t tos;
	uint16_t total_len;
	uint16_t fragment_id;
	uint16_t flags_framgent_offset;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t cksum;
	uint32_t from_addr;
	uint32_t to_addr;
} ip_packet_t;

#define IP_PACKET_TTL			64


// ---------------------- ICMP ----------------------------

#define ICMP_TYPE_ECHO_RQ	8
#define ICMP_TYPE_ECHO_RPLY	0

typedef struct _icmp_echo_packet {
	uint8_t type;
	uint8_t code;
	uint16_t cksum;
	uint16_t id;
	uint16_t seq;
} icmp_echo_packet_t;


// -------------------- UDP -------------------------------

typedef struct _udp_packet {
	uint16_t from_port;
	uint16_t to_port;
	uint16_t len;
	uint16_t cksum;
} udp_packet_t;


// -------------------- DNS -------------------------------

typedef struct _dns_request {
  uint16_t id;
  uint8_t flags1, flags2;
#define DNS_FLAG1_RESPONSE        0x80
#define DNS_FLAG1_OPCODE_STATUS   0x10
#define DNS_FLAG1_OPCODE_INVERSE  0x08
#define DNS_FLAG1_OPCODE_STANDARD 0x00
#define DNS_FLAG1_AUTHORATIVE     0x04
#define DNS_FLAG1_TRUNC           0x02
#define DNS_FLAG1_RD              0x01
#define DNS_FLAG2_RA              0x80
#define DNS_FLAG2_ERR_MASK        0x0f
#define DNS_FLAG2_ERR_NONE        0x00
#define DNS_FLAG2_ERR_NAME        0x03
  uint16_t numquestions;
  uint16_t numanswers;
  uint16_t numauthrr;
  uint16_t numextrarr;
} dns_request_t;



typedef struct _dns_answer {
  uint16_t type;
  uint16_t class;
  uint16_t ttl[2];
  uint16_t len;
  uint32_t ipaddr;
} dns_answer_t;

#define DNS_SERVER_PORT        HTONS(53)
#define DNS_CLIENT_PORT        HTONS(1052)


//кол-во записей в DNS таблице
#ifndef DNS_CACHE_SIZE
#define DNS_CACHE_SIZE 			10
#endif

//максимальная длина DNS имени
//number of records in the DNS table
#ifndef DNS_CACHE_NAME_SIZE
#define DNS_CACHE_NAME_SIZE 	128
#endif

typedef struct _dns_cache_entry {
	char name[DNS_CACHE_NAME_SIZE];
	uint32_t ip_addr;
} dns_cache_entry_t;

// -------------------- DHCP -------------------------------

#define DHCP_SERVER_PORT		HTONS(67)
#define DHCP_CLIENT_PORT		HTONS(68)

#define DHCP_OP_REQUEST			1
#define DHCP_OP_REPLY			2

#define DHCP_HW_ADDR_TYPE_ETH	1

#define DHCP_FLAG_BROADCAST		HTONS(0x8000)

#define DHCP_MAGIC_COOKIE		HTONL(0x63825363)

typedef struct _dhcp_message {
	uint8_t operation;
	uint8_t hw_addr_type;
	uint8_t hw_addr_len;
	uint8_t unused1;
	uint32_t transaction_id;
	uint16_t second_count;
	uint16_t flags;
	uint32_t client_addr;
	uint32_t offered_addr;
	uint32_t server_addr;
	uint32_t unused2;
	uint8_t hw_addr[16];
	uint8_t unused3[192];
	uint32_t magic_cookie;
} dhcp_message_t;

#define DHCP_CODE_PAD			0
#define DHCP_CODE_END			255
#define DHCP_CODE_SUBNETMASK	1
#define DHCP_CODE_GATEWAY		3
#define DHCP_CODE_DNS_SERVER    6
#define DHCP_CODE_REQUESTEDADDR	50
#define DHCP_CODE_LEASETIME		51
#define DHCP_CODE_MESSAGETYPE	53
#define DHCP_CODE_DHCPSERVER	54
#define DHCP_CODE_RENEWTIME		58
#define DHCP_CODE_REBINDTIME	59

typedef struct _dhcp_option {
	uint8_t code;
	uint8_t len;
} dhcp_option_t;

#define DHCP_MESSAGE_DISCOVER	1
#define DHCP_MESSAGE_OFFER		2
#define DHCP_MESSAGE_REQUEST	3
#define DHCP_MESSAGE_DECLINE	4
#define DHCP_MESSAGE_ACK		5
#define DHCP_MESSAGE_NAK		6
#define DHCP_MESSAGE_RELEASE	7
#define DHCP_MESSAGE_INFORM		8

typedef enum _dhcp_state {
	DHCP_NONE,
	DHCP_SEND_REQUEST_LEASE,
	DHCP_RECV_MESSAGE_OFFER,
	DHCP_RECV_ACK
} dhcp_state_t;

//таймоут на dhcp запрос
//timeout for dhcp request
#ifndef DHCP_TIMEOUT_MS
#define DHCP_TIMEOUT_MS			60000
#endif

// -------------------- TCP -------------------------------

//максимальное кол-во TCP соединений
//maximum number of TCP connections
#ifndef TCP_MAX_CONNECTIONS
#define TCP_MAX_CONNECTIONS		5
#endif

#define TCP_WINDOW_SIZE			65535
#define TCP_SYN_MSS				512

//сколько существет открытое соединение без активности в миллисекундах
//how long there is an open connection without activity in milliseconds
#ifndef TCP_CONN_TIMEOUT
#define TCP_CONN_TIMEOUT		5000
#endif



#define TCP_FLAG_URG		0x20
#define TCP_FLAG_ACK		0x10
#define TCP_FLAG_PSH		0x08
#define TCP_FLAG_RST		0x04
#define TCP_FLAG_SYN		0x02
#define TCP_FLAG_FIN		0x01

typedef struct _tcp_packet {
	uint16_t from_port;
	uint16_t to_port;
	uint32_t seq_num;
	uint32_t ack_num;
	uint8_t data_offset;
	uint8_t flags;
	uint16_t window;
	uint16_t cksum;
	uint16_t urgent_ptr;
} tcp_packet_t;


#define	TCP_CLOSED 			0
#define	TCP_SYN_SENT		1
#define	TCP_SYN_RECEIVED	2
#define	TCP_ESTABLISHED		3
#define	TCP_FIN_WAIT		4

typedef struct _tcp_state {
	uint8_t status;
	uint32_t event_time;
	uint32_t seq_num;
	uint32_t ack_num;
	uint32_t remote_addr;
	uint16_t remote_port;
	uint16_t local_port;
	uint8_t tcp_ack_sent;
} tcp_state_t;



#pragma pack(pop)

// -------------------------------------------------------------
// -------------------- FUNCTION -------------------------------
// -------------------------------------------------------------


// ---------------------- Network setting -------------------------

//инициализация ядра IP
//initialize the IP core
void ipcore_init(void);

uint8_t * get_mac(void);
void set_mac(uint8_t * mac);

uint32_t get_ip_addr(void);
void set_ip_addr(uint32_t addr);

uint32_t get_ip_mask(void);
void set_ip_mask(uint32_t addr);

uint32_t get_ip_gateway(void);
void set_ip_gateway(uint32_t addr);

uint32_t get_ip_dns(void);
void set_ip_dns(uint32_t addr);

uint32_t get_ip_dhcp(void);
void set_ip_dhcp(uint32_t addr);


// ---------------------- Ponter --------------------------------

//возвращает указатель на ethernet буффер отпраляемого пакета
//returns a pointer to the ethernet buffer of the sent packet
uint8_t * get_eth_buf(void);
//возвращает указатель на udp данные отпраляемого пакета
//returns a pointer to the udp data of the sent packet
uint8_t * get_udp_snd_packet_data(void);
//возвращает указатель на tcp данные отправляемого пакета
//returns a pointer to the tcp data of the sent packet
uint8_t * get_tcp_snd_packet_data(void);

// ---------------------- Time ------------------------------------

//должна быть определена !!! и возвращать время в миллисекундах
//must be defined !!! and return time in milliseconds
uint32_t get_ms(void);
//разница двух тиков, to - старое время, tn - новое время
//difference between two ticks, to - old time, tn - new time
uint32_t get_ms_diff(uint32_t to, uint32_t tn);
//разница с текущим временем
//difference with the current time
#define MS_DIFF_NOW(to) get_ms_diff(to, get_ms())

// ---------------------- Ethernet ---------------------------------

//должна вызываться при получении Ethernet пакета
//should be called when receiving an Ethernet packet
void eth_recv(uint8_t * data, uint16_t data_len);
//должна быть определена !!! и отсылать Ethernet пакет
// must be defined !!! and send Ethernet packet
void eth_send(uint8_t * data, uint16_t data_len);

// ---------------------- Arp ---------------------------------

//поиск мас-адреса по ip аддресу
//search for mac-address by ip address
uint8_t *arp_resolve(uint32_t node_ip_addr);

// -------------------- UDP -------------------------------

//должна быть определена !!!, вызывается при получении UDP пакета
//must be defined !!!, called when a UDP packet is received
void udp_recv(uint32_t from_addr, uint16_t from_port, uint16_t to_port, uint8_t * data, uint16_t data_len);
//послать UDP пакет, возвращает 0 или 1
//send UDP packet, returns 0 or 1
uint8_t udp_send(uint32_t to_addr, uint32_t to_port, uint32_t from_port, uint8_t *data, uint16_t data_len);


// -------------------- DNS -------------------------------

//получить ip адрес хоста, возвращает ip адрес или 0 в случае ошибки
//get the ip address of the host, returns the ip address or 0 in case of an error
uint32_t dns_resolve(char * node_name);

// -------------------- DHCP -------------------------------

//инициализвция DHCP
//initialize DHCP
void dhcp_init(void);
//возвращает 0 или 1. 1 - в случае получения ip-адресов с dhcp сервера
// returns 0 or 1.  1 - in case of receiving ip-addresses from the dhcp server
uint8_t dhcp_resolve(void);
//должна быть определена !!! вызывается при получении ip адреса, маски и т.д.
//must be defined !!! called when getting an ip address, mask, etc.
void dhcp_complete(void);
//возвращает время аренды ip адреса в милисекундах
//returns the lease time of the ip address in milliseconds
uint32_t get_dhcp_lease_time_ms(void);


// -------------------- TCP -------------------------------
// -- TCP UTIL --
//информация о TCP соединении
//information about TCP connection
tcp_state_t * tcp_get_state(uint8_t id);
//желательно вызывать один раз в TCP_CONN_TIMEOUT миллисекунд для проверки незакрытых соединений
//preferably call once per TCP_CONN_TIMEOUT milliseconds to check for open connections
void tcp_poll(void);
//возвращает свободный порт TCP
//returns a free TCP port
uint16_t tcp_get_free_port(void);

// -- TCP SERVER ---
//должна быть определена !!! вызывается когда удаленный хост хочет присоединится, должна возвращать разрешение на соединение 0 или 1
//must be defined !!! called when the remote host wants to join, must return 0 or 1 connection permission
uint8_t tcp_accept(uint32_t from_addr, uint16_t from_port, uint16_t to_port);

// -- TCP CLIENT CONECTION --
//послать соединится c удаленным хостом, возвращает  0xff или номер соединения
//send connect to remote host, return 0xff or connection number
uint8_t tcp_send_connect(int32_t to_addr, uint16_t to_port, uint16_t from_port);
//должна быть определена !!! вызывается когда TCP соединение установлено, id - номер соединения
//must be defined !!! called when TCP connection is established, id is the connection number
void tcp_recv_connected(uint8_t id);

// -- TCP RECEIVE DATA --
//должна быть определена !!! вызывается когда приходят TCP данные, id - номер соединения
//must be defined !!! called when TCP data arrives, id is the connection number
void tcp_recv(uint8_t id, uint8_t * data, uint16_t data_len);

// -- TCP SEND DATA --
//отправка TCP пакета с флагами flags, возвращает 0 или 1
//send a TCP packet with flags, returns 0 or 1
uint8_t tcp_send_flags(uint8_t id, uint8_t * data, uint16_t data_len, uint8_t flags);
//послать данные по TCP с флагом ack, id - номер соединения, возвращает 0 или 1
//send data over TCP with the ack flag, id is the connection number, returns 0 or 1
uint8_t tcp_send_ack(uint8_t id, uint8_t * data, uint16_t data_len);
//послать данные по TCP с флагом push, id - номер соединения, возвращает 0 или 1
//send data over TCP with the push flag, id is the connection number, returns 0 or 1
uint8_t tcp_send_push(uint8_t id, uint8_t * data, uint16_t data_len);
//послать данные по TCP с флагом fin (просьба закрыть TCP соединение), id - номер соединения, возвращает 0 или 1
//send data over TCP with the fin flag (request to close the TCP connection), id is the connection number, returns 0 or 1
uint8_t tcp_send_fin(uint8_t id, uint8_t * data, uint16_t data_len);


// -- TCP CLOSE --
//послать флаг rst (оборвать TCP соединение), id - номер соединения, возвращает 0 или 1
//send the rst flag (terminate TCP connection), id is the connection number, returns 0 or 1
uint8_t tcp_send_rst(uint8_t id);
//послать закрыть TCP соединение, id - номер соединения, возвращает 0 или 1
//send close TCP connection, id - connection number, returns 0 or 1
#define TCP_SEND_CLOSE(id) tcp_send_fin(id, NULL, 0)
//удаленный хост закрыл соединение
//the remote host closed the connection
#define TCP_WHY_CLOSED_ESTABLISHED	1
//мы закрыли соединение и удаленный хост прислал подтверждение
//we closed the connection and the remote host sent a confirmation
#define TCP_WHY_CLOSED_FIN_WAIT		2
//удаленный хост сбросил соединение
//the remote host dropped the connection
#define TCP_WHY_CLOSED_RESET		3
//соединение сброшено т.к. нет активности
//connection dropped since no activity
#define TCP_WHY_CLOSED_CONN_TIMEOUT	4
//должна быть определена !!!, вызывается когда соединение сброшено (удаленный хост разорвал соединение или другие причины), id - номер соединения
//must be defined !!!, called when the connection is dropped (the remote host has dropped the connection or other reasons), id is the connection number
void tcp_recv_closed(uint8_t id, uint8_t why);



#endif /* IPCORE_IPCORE_H_ */
