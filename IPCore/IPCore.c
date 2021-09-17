/*
 * IPCore.c
 *
 *  Created on: 20 мая 2021 г.
 *      Author: lenovo
 */

#include "IPCore.h"

#include <string.h>
#include <stdlib.h>


static uint8_t mac_addr[6] = {0};
static uint32_t ip_addr = 0;
static uint32_t ip_mask = 0;
static uint32_t ip_gateway = 0;
static uint32_t ip_dns = 0;
static uint32_t ip_dhcp = 0xffffffff;

static dhcp_state_t dhcp_state = DHCP_NONE;
static uint32_t dhcp_ms = 0;

//время аренды ip адреса в милисекундах
//IP address lease time in milliseconds
static uint32_t dhcp_lease_time_ms = 0;
uint32_t get_dhcp_lease_time_ms(void) { return dhcp_lease_time_ms; }

static uint8_t arp_cache_wr = 0;
static arp_cache_entry_t arp_cache[ARP_CACHE_SIZE] = {0};

static uint8_t dns_cache_wr = 0;
static dns_cache_entry_t dns_cache[DNS_CACHE_SIZE] = {0};


static uint8_t eth_buf[ETH_BUF_SIZE];

uint8_t * get_eth_buf(void) { return eth_buf; }

static eth_frame_t * eth_snd_frame = (eth_frame_t *)eth_buf;
static uint8_t * eth_snd_frame_data = eth_buf + sizeof(eth_frame_t);
static ip_packet_t *ip_snd_packet = (ip_packet_t *)(eth_buf + sizeof(eth_frame_t));
static uint8_t * ip_snd_packet_data = eth_buf + sizeof(eth_frame_t) + sizeof(ip_packet_t);
static udp_packet_t *udp_snd_packet = (udp_packet_t *)(eth_buf + sizeof(eth_frame_t) + sizeof(ip_packet_t));
static uint8_t * udp_snd_packet_data = eth_buf + sizeof(eth_frame_t) + sizeof(ip_packet_t) + sizeof(udp_packet_t);
static tcp_packet_t * tcp_snd_packet = (tcp_packet_t *)(eth_buf + sizeof(eth_frame_t) + sizeof(ip_packet_t));
static uint8_t * tcp_snd_packet_data = eth_buf + sizeof(eth_frame_t) + sizeof(ip_packet_t) + sizeof(tcp_packet_t);


uint8_t * get_udp_snd_packet_data(void) { return udp_snd_packet_data; }
uint8_t * get_tcp_snd_packet_data(void) { return tcp_snd_packet_data; }

static uint32_t dhcp_transaction_id = 0;


uint8_t * get_mac(void) { return mac_addr; }
void set_mac(uint8_t * mac) { memcpy(mac_addr, mac, 6); }

uint32_t get_ip_addr(void) { return ip_addr; }
void set_ip_addr(uint32_t addr) { ip_addr = addr; }

uint32_t get_ip_mask(void) { return ip_mask; }
void set_ip_mask(uint32_t addr) { ip_mask = addr; }

uint32_t get_ip_gateway(void) { return ip_gateway; }
void set_ip_gateway(uint32_t addr) { ip_gateway = addr; }

uint32_t get_ip_dns(void) { return ip_dns; }
void set_ip_dns(uint32_t addr) { ip_dns = addr; }

uint32_t get_ip_dhcp(void) { return ip_dhcp; }
void set_ip_dhcp(uint32_t addr) { ip_dhcp = addr; }

static tcp_state_t tcp_pool[TCP_MAX_CONNECTIONS] = {0};

static uint8_t broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};



//послать ETHERNET пакет
//send ETHERNET packet
void eth_snd(uint8_t * to_mac, uint8_t *data, uint16_t data_len, uint16_t type);
//послать ip пакет
//send ip packet
uint8_t ip_snd(uint32_t to_addr, uint8_t * data,  uint16_t data_len, uint8_t protocol);
//Отправка запроса на DNS-сервер
//Send request to DNS server
uint8_t dns_request(uint16_t id, char * name);
//послать DHCP запрос с просбой аренды ip алреса
//send a DHCP request asking for an ip address lease
uint8_t dhcp_request_lease(void);
//послать DHCP запрос с просбой продлить аренду ip алреса
//send a DHCP request with a request to extend the lease of the ip address
uint8_t dhcp_extend_lease(void);


static uint16_t eth_data_max_size = ETH_BUF_SIZE - sizeof(eth_frame_t);
static uint16_t ip_data_max_size = ETH_BUF_SIZE - sizeof(eth_frame_t) - sizeof(ip_packet_t);
static uint16_t udp_data_max_size = ETH_BUF_SIZE - sizeof(eth_frame_t) - sizeof(ip_packet_t) - sizeof(udp_packet_t);
static uint16_t tcp_data_max_size = ETH_BUF_SIZE - sizeof(eth_frame_t) - sizeof(ip_packet_t) - sizeof(tcp_packet_t);

static uint8_t last_arp_search_cache_index = 0;
static uint8_t last_dns_resolve_index = 0;

void ipcore_init(void)
{
	memset(mac_addr, 0, 6);

	ip_addr = 0;
	ip_mask = 0;
	ip_gateway = 0;
	ip_dns = 0;
	ip_dhcp = 0xffffffff;

	dhcp_state = DHCP_NONE;
	dhcp_ms = 0;
	dhcp_lease_time_ms = 0;

	arp_cache_wr = 0;

	memset(arp_cache, 0, ARP_CACHE_SIZE * sizeof(arp_cache_entry_t));

	dns_cache_wr = 0;
	memset(dns_cache, 0, DNS_CACHE_SIZE * sizeof(dns_cache_entry_t));

	dhcp_transaction_id = 0;

    memset(tcp_pool, 0, TCP_MAX_CONNECTIONS * sizeof(tcp_state_t));

    last_arp_search_cache_index = 0;
}




uint32_t get_ms_diff(uint32_t to, uint32_t tn)
{
	if (tn >= to) return tn - to;
	else return 0xFFFFFFFF - to + tn;
}



uint16_t ip_cksum(uint32_t sum, uint8_t *buf, uint16_t len)
{
	while(len >= 2)
	{
		sum += ((uint16_t)*buf << 8) | *(buf+1);
		buf += 2;
		len -= 2;
	}

	if(len)
		sum += (uint16_t)*buf << 8;

	while(sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return ~HTONS((uint16_t)sum);
}



uint16_t pseudo_checksum(uint8_t *buff, uint16_t len, uint32_t src_addr, uint32_t dest_addr, uint16_t proto)
{
	uint16_t *buf= (uint16_t *)buff;
	uint16_t *ip_src=(void *)&src_addr, *ip_dst=(void *)&dest_addr;
	uint32_t sum;
	size_t length=len;

	// Calculate the sum
	sum = 0;
	while (len > 1)
	{
		sum += *buf++;
		if (sum & 0x80000000)
			sum = (sum & 0xFFFF) + (sum >> 16);
		len -= 2;
	}
	if ( len & 1 )
		// Add the padding if the packet lenght is odd
		sum += *((uint8_t *)buf);

	// Add the pseudo-header
	sum += *(ip_src++);
	sum += *ip_src;

	sum += *(ip_dst++);
	sum += *ip_dst;
	sum += HTONS(proto);
	sum += HTONS(length);

	// Add the carries
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);
		// Return the one's complement of sum
	return ( (uint16_t)(~sum)  );
}

#define UDP_CHECKSUM(b, l, s, d)  pseudo_checksum(b, l, s, d, IP_PROTOCOL_UDP)
#define TCP_CHECKSUM(b, l, s, d)  pseudo_checksum(b, l, s, d, IP_PROTOCOL_TCP)

// -------------------- TCP -------------------------------

// periodic event
void tcp_poll(void)
{
	uint8_t id;

	for (id = 0; id < TCP_MAX_CONNECTIONS; ++id)
	{
		// check if connection timed out
		if( (tcp_pool[id].status != TCP_CLOSED) && (get_ms() - tcp_pool[id].event_time > TCP_CONN_TIMEOUT) )
		{
			if (tcp_pool[id].status == TCP_ESTABLISHED) tcp_send_flags(id, NULL, 0, TCP_FLAG_FIN | TCP_FLAG_ACK);
			// kill connection
			tcp_pool[id].status = TCP_CLOSED;
			tcp_recv_closed(id, TCP_WHY_CLOSED_CONN_TIMEOUT);
		}
	}
}


uint16_t tcp_get_free_port(void)
{
	uint8_t id;
	uint16_t port = 1024;

	for (id = 0; id < TCP_MAX_CONNECTIONS; ++id)
	{
		//if (tcp_pool[id].status != TCP_CLOSED ) {
			if (NTOHS(tcp_pool[id].local_port) > port) port = NTOHS(tcp_pool[id].local_port);
		//}
	}
	++port;
	if (port < 1024) port = 1024;

	return port;
}


tcp_state_t * tcp_get_state(uint8_t id)
{
	return &tcp_pool[id];
}

uint32_t generate_seq(void)
{
	uint32_t ms = get_ms();
	return (uint32_t)(ms << 16) + (ms & 0xffff);
}


uint8_t tcp_send_connect(int32_t to_addr, uint16_t to_port, uint16_t from_port)
{
	uint8_t id;

	for (id = 0; id < TCP_MAX_CONNECTIONS; ++id) {
		if (tcp_pool[id].status == TCP_CLOSED)	break;
	}

	if (id == TCP_MAX_CONNECTIONS) return 0xff;

	uint32_t seq = generate_seq();

	tcp_snd_packet->to_port = to_port;
	tcp_snd_packet->from_port = from_port;
	tcp_snd_packet->seq_num = HTONL(seq);
	tcp_snd_packet->ack_num = 0;
	tcp_snd_packet->data_offset = (sizeof(tcp_packet_t) + 4) << 2;
	tcp_snd_packet->flags = TCP_FLAG_SYN;
	tcp_snd_packet->window = HTONS(TCP_WINDOW_SIZE);
	tcp_snd_packet->cksum = 0;
	tcp_snd_packet->urgent_ptr = 0;

	tcp_snd_packet_data[0] = 2; // MSS option
	tcp_snd_packet_data[1] = 4; // MSS option length = 4 bytes
	tcp_snd_packet_data[2] = TCP_SYN_MSS >> 8;
	tcp_snd_packet_data[3] = TCP_SYN_MSS & 0xff;

	uint16_t len = sizeof(tcp_packet_t) + 4;

	tcp_snd_packet->cksum = 0;
	tcp_snd_packet->cksum = TCP_CHECKSUM((uint8_t*)tcp_snd_packet, len, ip_addr, to_addr);

	if ( !ip_snd(to_addr, (uint8_t *)tcp_snd_packet,  len, IP_PROTOCOL_TCP) ) return 0xff;

	tcp_pool[id].status = TCP_SYN_SENT;
	tcp_pool[id].event_time = get_ms();
	tcp_pool[id].seq_num = seq + 1; //?
	tcp_pool[id].ack_num = tcp_snd_packet->ack_num; //?
	tcp_pool[id].remote_port = to_port;
	tcp_pool[id].local_port =  from_port;
	tcp_pool[id].remote_addr = to_addr;
	tcp_pool[id].tcp_ack_sent = 0;


	return id;
}


/*
//соединение
uint8_t tcp_connect(int32_t to_addr, uint32_t to_port, uint32_t from_port)
{
	uint8_t id;

	for (id = 0; id < TCP_MAX_CONNECTIONS; ++id) {
		if ( (tcp_pool[id].status != TCP_CLOSED) &&
			 (to_addr == tcp_pool[id].remote_addr) &&
			 (to_port == tcp_pool[id].remote_port) &&
			 (from_port == tcp_pool[id].local_port) )
			break;
	}

	if (id == TCP_MAX_CONNECTIONS) {
		tcp_send_connect(to_addr, to_port, from_port);
	} else {
		if (tcp_pool[id].status == TCP_ESTABLISHED) return id;
		else if (tcp_pool[id].status == TCP_SYN_SENT) {
			if (get_ms() - tcp_pool[id].event_time > TCP_CONNECT_TIMEOUT) {
				tcp_pool[id].status = TCP_CLOSED;
			}
		}
	}

	return 0xff;
}
*/

uint8_t tcp_snd(int32_t to_addr, uint32_t to_port, uint32_t from_port,
				uint32_t seq_num, uint32_t ack_num,	uint8_t data_offset, uint8_t flags, uint16_t window, uint16_t urgent_ptr,
				uint8_t *data, uint16_t data_len)
{
	uint16_t dlen = MIN(data_len, tcp_data_max_size);

	if (data != NULL) {
		if  (tcp_snd_packet_data != data) memcpy(tcp_snd_packet_data, data, dlen);
	}

	uint16_t len = sizeof(tcp_packet_t) + dlen;
	tcp_snd_packet->from_port = from_port;
	tcp_snd_packet->to_port = to_port;

	tcp_snd_packet->seq_num = seq_num;
	tcp_snd_packet->ack_num = ack_num;
	tcp_snd_packet->data_offset = data_offset;
	tcp_snd_packet->flags = flags;
	tcp_snd_packet->window = window;
	tcp_snd_packet->urgent_ptr = urgent_ptr;


	tcp_snd_packet->cksum = 0;
	tcp_snd_packet->cksum = TCP_CHECKSUM((uint8_t*)tcp_snd_packet, len, ip_addr, to_addr);


	return ip_snd(to_addr, (uint8_t *)tcp_snd_packet,  len, IP_PROTOCOL_TCP);

}



uint8_t tcp_send_flags(uint8_t id, uint8_t * data, uint16_t data_len, uint8_t flags)
{
	uint8_t res;

	// send packet
	res = tcp_snd(tcp_pool[id].remote_addr, tcp_pool[id].remote_port, tcp_pool[id].local_port,
			HTONL(tcp_pool[id].seq_num), HTONL(tcp_pool[id].ack_num), sizeof(tcp_packet_t) << 2,  flags, HTONS(TCP_WINDOW_SIZE), 0,
			data, data_len);

	// advance sequence number
	tcp_pool[id].seq_num += data_len;
	if( (flags & TCP_FLAG_SYN) || (flags & TCP_FLAG_FIN) )
		tcp_pool[id].seq_num++;

	// set "ACK sent" flag
	if( (flags & TCP_FLAG_ACK) && (res) )
		tcp_pool[id].tcp_ack_sent = 1;

	return res;
}

uint8_t tcp_send_ack(uint8_t id, uint8_t * data, uint16_t data_len)
{
	// check if connection established
	if (tcp_pool[id].status != TCP_ESTABLISHED)	return 0;

	return tcp_send_flags(id, data, data_len, TCP_FLAG_ACK);
}

uint8_t tcp_send_push(uint8_t id, uint8_t * data, uint16_t data_len)
{
	// check if connection established
	if (tcp_pool[id].status != TCP_ESTABLISHED)	return 0;

	return tcp_send_flags(id, data, data_len, TCP_FLAG_ACK | TCP_FLAG_PSH);
}

uint8_t tcp_send_fin(uint8_t id, uint8_t * data, uint16_t data_len)
{
	// check if connection established
	if (tcp_pool[id].status != TCP_ESTABLISHED)	return 0;

	tcp_pool[id].status = TCP_FIN_WAIT;

	return tcp_send_flags(id, data, data_len, TCP_FLAG_ACK | TCP_FLAG_FIN);
}

uint8_t tcp_send_rst(uint8_t id)
{
	if ( (tcp_pool[id].status != TCP_ESTABLISHED) || (tcp_pool[id].status != TCP_FIN_WAIT) ) return 0;

	tcp_pool[id].status = TCP_CLOSED;

	return tcp_send_flags(id, NULL, 0, TCP_FLAG_ACK | TCP_FLAG_RST);
}


void tcp_filter(tcp_packet_t *tcp_packet, uint16_t tcp_packet_len, uint32_t from_addr)
{


	uint8_t id, tcpflags;
	uint16_t data_len = tcp_packet_len - sizeof(tcp_packet_t);
	uint8_t * data = (uint8_t *)tcp_packet + sizeof(tcp_packet_t);

	// me needs only SYN/FIN/ACK/RST
	tcpflags = tcp_packet->flags & (TCP_FLAG_SYN | TCP_FLAG_ACK | TCP_FLAG_RST | TCP_FLAG_FIN);

	// sending packets back
	//tcp_send_mode = TCP_SENDING_REPLY;
	//tcp_ack_sent = 0;

	// search connection pool for connection
	//	to specific port from specific host/port
	for (id = 0; id < TCP_MAX_CONNECTIONS; ++id) {

		if ( (tcp_pool[id].status != TCP_CLOSED) &&
			(from_addr == tcp_pool[id].remote_addr) &&
			(tcp_packet->from_port == tcp_pool[id].remote_port) &&
			(tcp_packet->to_port == tcp_pool[id].local_port) )
			break;
	}

	//ulog_fmt("tcp search1 id=%d tcpflags=%d\r\n", id, tcpflags);

	// connection not found/new connection
	if (id == TCP_MAX_CONNECTIONS)
	{
		//ulog("tcp id == TCP_MAX_CONNECTIONS\r\n");

		// received SYN - initiating new connection
		if (tcpflags != TCP_FLAG_SYN) return;

		// search for free slot for connection
		for (id = 0; id < TCP_MAX_CONNECTIONS; ++id) {
			if (tcp_pool[id].status == TCP_CLOSED)	break;
		}

		//ulog_fmt("tcp search2 id=%d\r\n", id);
		if (id == TCP_MAX_CONNECTIONS) return;

		// slot found and app accepts connection?
		if (!tcp_accept(from_addr, tcp_packet->from_port, tcp_packet->to_port)) return;


		// add embrionic connection to pool
		tcp_pool[id].status = TCP_SYN_RECEIVED;
		tcp_pool[id].event_time = get_ms();
		tcp_pool[id].seq_num = generate_seq();
		tcp_pool[id].ack_num = NTOHL(tcp_packet->seq_num) + 1;
		tcp_pool[id].remote_addr = from_addr;
		tcp_pool[id].remote_port = tcp_packet->from_port;
		tcp_pool[id].local_port = tcp_packet->to_port;
		tcp_pool[id].tcp_ack_sent = 0;

		// send SYN/ACK
		tcp_snd_packet_data[0] = 2;//option: MSS
		tcp_snd_packet_data[1] = 4;//option len
		tcp_snd_packet_data[2] = TCP_SYN_MSS >> 8;
		tcp_snd_packet_data[3] = TCP_SYN_MSS & 0xff;

		//ulog_fmt("tcp new connection, snd syn/ack id=%d seqnum=%ul\r\n", id, NTOHL(tcp_packet->seq_num));

		tcp_snd(tcp_pool[id].remote_addr, tcp_pool[id].remote_port, tcp_pool[id].local_port,
				HTONL(tcp_pool[id].seq_num), HTONL(tcp_pool[id].ack_num), (sizeof(tcp_packet_t) + 4) << 2,  TCP_FLAG_SYN | TCP_FLAG_ACK, HTONS(TCP_WINDOW_SIZE), 0,
				tcp_snd_packet_data, 4);

		// advance sequence number
		tcp_pool[id].seq_num++;
		return;
	}

	//ulog_fmt("tcp old connection id=%d tcp_pool[id].status=%d tcpflags=%d (%ul, %ul) (%ul, %ul)\r\n", id, tcp_pool[id].status, tcpflags, NTOHL(tcp_packet->seq_num), NTOHL(tcp_packet->ack_num), tcp_pool[id].seq_num, tcp_pool[id].ack_num);

	tcp_pool[id].tcp_ack_sent = 0;

	// connection reset by peer?
	if (tcpflags & TCP_FLAG_RST)
	{
		if( (tcp_pool[id].status == TCP_ESTABLISHED) ||	(tcp_pool[id].status == TCP_FIN_WAIT) ) {
			tcp_recv_closed(id, TCP_WHY_CLOSED_RESET);
		}
		tcp_pool[id].status = TCP_CLOSED;
		return;
	}


	if (tcp_pool[id].ack_num == 0) {
		if ( (NTOHL(tcp_packet->ack_num) != tcp_pool[id].seq_num) || (!(tcpflags & TCP_FLAG_ACK)) )	return;
		tcp_pool[id].ack_num = NTOHL(tcp_packet->seq_num) + 1;
	} else {
		// me needs only ack packet
		if( (NTOHL(tcp_packet->seq_num) != tcp_pool[id].ack_num) || (NTOHL(tcp_packet->ack_num) != tcp_pool[id].seq_num) || (!(tcpflags & TCP_FLAG_ACK)) ) return;

		// update ack pointer
		tcp_pool[id].ack_num += data_len;
		if ( (tcpflags & TCP_FLAG_FIN) || (tcpflags & TCP_FLAG_SYN) ) tcp_pool[id].ack_num++;
}



	// reset timeout counter
	tcp_pool[id].event_time = get_ms();


	//ulog_fmt("tcp ok old connection id=%d tcp_pool[id].status=%d tcpflags=%d\r\n", id, tcp_pool[id].status, tcpflags);

	switch (tcp_pool[id].status)
	{

		// SYN sent by me (active open, step 1)
	 	// awaiting SYN/ACK (active open, step 2)
		case TCP_SYN_SENT:

			if (tcpflags != (TCP_FLAG_SYN | TCP_FLAG_ACK)) { // received packet must be SYN/ACK
				tcp_pool[id].status = TCP_CLOSED;
			} else {

				tcp_send_flags(id, NULL, 0, TCP_FLAG_ACK);

				// connection is now established
				tcp_pool[id].status = TCP_ESTABLISHED;

				// app can send some data
				tcp_recv_connected(id);
			}
			break;

		// SYN received my me (passive open, step 1)
		// SYN/ACK sent by me (passive open, step 2)
		// awaiting ACK (passive open, step 3)
		case TCP_SYN_RECEIVED:
			// received packet must be ACK
			if(tcpflags != TCP_FLAG_ACK) {
				tcp_pool[id].status = TCP_CLOSED;
			} else {

				// connection is now established
				tcp_pool[id].status = TCP_ESTABLISHED;

				//ulog_fmt("tcp connection %d is now established\r\n", id);
				//ulog_fmt("tcp seq=%ul ack=%ul, tcp_pool seq=%ul ack=%ul\r\n", HTONL(tcp_packet->seq_num), HTONL(tcp_packet->ack_num), tcp_pool[id].seq_num, tcp_pool[id].ack_num);

				// app can send some data
				tcp_recv_connected(id);
			}

			break;

		// connection established
		// awaiting ACK or FIN/ACK
		case TCP_ESTABLISHED:

			// received FIN/ACK?
			// (passive close, step 1)
			if (tcpflags == (TCP_FLAG_FIN | TCP_FLAG_ACK))
			{
				//feed data to app
				//ulog("feed data to app\r\n")
				if (data_len) tcp_recv(id, data, data_len);

				//ulog("send FIN/ACK (passive close, step 2)\r\n");
				//ulog_fmt("tcp seq=%ul ack=%ul, tcp_pool seq=%ul ack=%ul\r\n", HTONL(tcp_packet->seq_num), HTONL(tcp_packet->ack_num), tcp_pool[id].seq_num, tcp_pool[id].ack_num);
				// send FIN/ACK (passive close, step 2)
				tcp_send_flags(id, NULL, 0, TCP_FLAG_FIN | TCP_FLAG_ACK);


				// connection is now closed
				//ulog("connection is now closed\r\n");
				tcp_pool[id].status = TCP_CLOSED;
				tcp_recv_closed(id, TCP_WHY_CLOSED_ESTABLISHED);

			}

			// received ACK
			else if (tcpflags == TCP_FLAG_ACK)
			{
				// feed data to app
				if (data_len) tcp_recv(id, data, data_len);

				// app can send some data
				//tcp_read(id, frame, 0);

				// send ACK
				//ulog("connection send ACK\r\n");
				//ulog_fmt("tcp seq=%ul ack=%ul, tcp_pool seq=%ul ack=%ul\r\n", HTONL(tcp_packet->seq_num), HTONL(tcp_packet->ack_num), tcp_pool[id].seq_num, tcp_pool[id].ack_num);
				if ( (data_len) && (!tcp_pool[id].tcp_ack_sent) ) tcp_send_flags(id, NULL, 0, TCP_FLAG_ACK);
			}

			break;

		// FIN/ACK sent by me (active close, step 1)
		// awaiting ACK or FIN/ACK
		case TCP_FIN_WAIT:

			// received FIN/ACK?
			// (active close, step 2)
			if (tcpflags == (TCP_FLAG_FIN | TCP_FLAG_ACK))
			{
				// feed data to app
				if (data_len) tcp_recv(id, data, data_len);

				// send ACK (active close, step 3)
				tcp_send_flags(id, NULL, 0, TCP_FLAG_ACK);

				// connection is now closed
				tcp_pool[id].status = TCP_CLOSED;
				tcp_recv_closed(id, TCP_WHY_CLOSED_FIN_WAIT);
			}

			// received ACK+data?
			// (buffer flushing by peer)
			else if ( (tcpflags == TCP_FLAG_ACK) && (data_len) )
			{
				// feed data to app
				tcp_recv(id, data, data_len);

				// send ACK
				tcp_send_flags(id, NULL, 0, TCP_FLAG_ACK);

			}

			break;

		default:
			tcp_pool[id].status = TCP_CLOSED;
			break;
	}

}


// -------------------- DHCP -------------------------------

#define DHCP_ADD_OPTION(ptr, optcode, type, value) \
	((dhcp_option_t*)ptr)->code = optcode; \
	((dhcp_option_t*)ptr)->len = sizeof(type); \
	*(type*)((dhcp_option_t*)(ptr + sizeof(dhcp_option_t))) = value; \
	ptr += sizeof(dhcp_option_t) + sizeof(type); \
	if(sizeof(type)&1) *(ptr++) = 0;


void dhcp_filter(uint8_t * data, uint16_t data_len, uint32_t from_addr)
{
	dhcp_option_t *option;
	uint8_t *op, optlen;
	uint32_t offered_net_mask = 0, offered_gateway = 0, offered_dns = 0;
	uint32_t lease_time = 0, renew_server = 0;
	uint8_t type = 0;
	uint32_t temp;
	uint8_t * option_data;
	dhcp_message_t * dhcp_snd_message;


	dhcp_message_t * dhcp_message = (dhcp_message_t *)data;

	//ulog_fmt("dhcp filter %d %ld %ld-%ld\r\n", dhcp_message->operation, NTOHL(dhcp_message->transaction_id), dhcp_message->magic_cookie, DHCP_MAGIC_COOKIE);

	if ( (dhcp_message->operation != DHCP_OP_REPLY) || (NTOHL(dhcp_message->transaction_id) != dhcp_transaction_id) || (dhcp_message->magic_cookie != DHCP_MAGIC_COOKIE) ) return;


	uint16_t len = data_len - sizeof(dhcp_message_t);
	op = data + sizeof(dhcp_message_t);

	while (len >= sizeof(dhcp_option_t))
	{
		option = (dhcp_option_t *)op;

		if (option->code == DHCP_CODE_END) break;

		if (option->code == DHCP_CODE_PAD)
		{
			op++;
			len--;
			continue;
		}

		option_data = op + sizeof(dhcp_option_t);

		switch (option->code)
		{
			case DHCP_CODE_MESSAGETYPE:
				type = *(option_data);
				break;
			case DHCP_CODE_SUBNETMASK:
				offered_net_mask = *(uint32_t*)(option_data);
				break;
			case DHCP_CODE_GATEWAY:
				offered_gateway = *(uint32_t*)(option_data);
				break;
			case DHCP_CODE_DHCPSERVER:
				renew_server = *(uint32_t*)(option_data);
				break;
			case DHCP_CODE_DNS_SERVER:
				offered_dns = *(uint32_t*)(option_data);
				break;
			case DHCP_CODE_LEASETIME:
				temp = *(uint32_t*)(option_data);
				lease_time = NTOHL(temp);
				if(lease_time > 21600) lease_time = 21600;
				break;
		}

		optlen = sizeof(dhcp_option_t) + option->len;
		op += optlen;
		len -= optlen;
	}

	//ulog_fmt("dhcp replay type=%d\r\n", type);

	if (!renew_server) {
		renew_server = from_addr;
	}

	switch (type)
	{
		case DHCP_MESSAGE_OFFER:

			dhcp_snd_message =  (dhcp_message_t *)udp_snd_packet_data;
			memcpy(dhcp_snd_message, dhcp_message, sizeof(dhcp_message_t));
			dhcp_snd_message->operation = DHCP_OP_REQUEST;
			dhcp_snd_message->offered_addr = 0;
			dhcp_snd_message->server_addr = 0;
			dhcp_snd_message->flags = DHCP_FLAG_BROADCAST;
			uint8_t *op = udp_snd_packet_data + sizeof(dhcp_message_t);
			DHCP_ADD_OPTION(op, DHCP_CODE_MESSAGETYPE,	uint8_t, DHCP_MESSAGE_REQUEST);
			DHCP_ADD_OPTION(op, DHCP_CODE_REQUESTEDADDR, uint32_t, dhcp_message->offered_addr);
			DHCP_ADD_OPTION(op, DHCP_CODE_DHCPSERVER,	uint32_t, renew_server);
			*(op++) = DHCP_CODE_END;


			//ulog_fmt("dhcp send request\r\n");
			udp_send(0xffffffff, DHCP_SERVER_PORT, DHCP_CLIENT_PORT, udp_snd_packet_data, op - udp_snd_packet_data);
			dhcp_state = DHCP_RECV_MESSAGE_OFFER;
			dhcp_ms = get_ms();
			break;

		case DHCP_MESSAGE_ACK:
			ip_addr = dhcp_message->offered_addr;
			ip_mask = offered_net_mask;
			ip_gateway = offered_gateway;
			ip_dns = offered_dns;
			dhcp_lease_time_ms = lease_time * 1000;
			ip_dhcp = renew_server;
			dhcp_state = DHCP_RECV_ACK;
			dhcp_ms = get_ms();
			dhcp_complete();
		break;
	}
}


uint8_t dhcp_extend_lease(void)
{
	dhcp_lease_time_ms = 0;

	dhcp_message_t * dhcp_message =  (dhcp_message_t *)udp_snd_packet_data;

	memset(dhcp_message, 0, sizeof(dhcp_message_t));
	dhcp_message->operation = DHCP_OP_REQUEST;
	dhcp_message->hw_addr_type = DHCP_HW_ADDR_TYPE_ETH;
	dhcp_message->hw_addr_len = 6;
	dhcp_transaction_id++;
	dhcp_message->transaction_id = HTONL(dhcp_transaction_id);
	dhcp_message->client_addr = ip_addr;
	dhcp_message->flags = DHCP_FLAG_BROADCAST;
	memcpy(dhcp_message->hw_addr, mac_addr, 6);
	dhcp_message->magic_cookie = DHCP_MAGIC_COOKIE;

	uint8_t *op = udp_snd_packet_data + sizeof(dhcp_message_t);
	DHCP_ADD_OPTION(op, DHCP_CODE_MESSAGETYPE, uint8_t, DHCP_MESSAGE_REQUEST);
	DHCP_ADD_OPTION(op, DHCP_CODE_REQUESTEDADDR, uint32_t, ip_addr);
	DHCP_ADD_OPTION(op, DHCP_CODE_DHCPSERVER, uint32_t, ip_dhcp);
	*(op++) = DHCP_CODE_END;

	//ulog("dhcp_extend_lease\r\n");
	return udp_send(ip_dhcp, DHCP_SERVER_PORT, DHCP_CLIENT_PORT, udp_snd_packet_data, op - udp_snd_packet_data);
}

void dhcp_init(void)
{
	dhcp_state = DHCP_NONE;
	// network down
	ip_addr = 0;
	ip_mask = 0;
	ip_gateway = 0;
	ip_dns = 0;
	ip_dhcp = 0xffffffff;
	dhcp_lease_time_ms = 0;
	dhcp_ms = 0;
}


uint8_t dhcp_request_lease(void)
{
	dhcp_init();


	dhcp_message_t * dhcp_message =  (dhcp_message_t *)udp_snd_packet_data;

	memset(dhcp_message, 0, sizeof(dhcp_message_t));
	dhcp_message->operation = DHCP_OP_REQUEST;
	dhcp_message->hw_addr_type = DHCP_HW_ADDR_TYPE_ETH;
	dhcp_message->hw_addr_len = 6;
	dhcp_transaction_id++;
	dhcp_message->transaction_id = HTONL(dhcp_transaction_id);
	dhcp_message->flags = DHCP_FLAG_BROADCAST;
	memcpy(dhcp_message->hw_addr, mac_addr, 6);
	dhcp_message->magic_cookie = DHCP_MAGIC_COOKIE;

	uint8_t *op = udp_snd_packet_data + sizeof(dhcp_message_t);
	DHCP_ADD_OPTION(op, DHCP_CODE_MESSAGETYPE, uint8_t, DHCP_MESSAGE_DISCOVER);
	*(op++) = DHCP_CODE_END;

	//ulog("dhcp_request_lease\r\n");
	return udp_send(0xffffffff, DHCP_SERVER_PORT, DHCP_CLIENT_PORT, udp_snd_packet_data, op - udp_snd_packet_data);
}


uint8_t dhcp_resolve(void)
{
	uint8_t res = 0;

	switch (dhcp_state) {
		case DHCP_NONE:
			if (dhcp_request_lease()) {
				//ulog("DHCP_NONE goto DHCP_SEND_REQUEST_LEASE\r\n");
				dhcp_state = DHCP_SEND_REQUEST_LEASE;
				dhcp_ms = get_ms();
			}
			break;
		case DHCP_SEND_REQUEST_LEASE:
			//ожидание message offer
			if (MS_DIFF_NOW(dhcp_ms) > DHCP_TIMEOUT_MS) {
				dhcp_state = DHCP_NONE;
				//ulog("DHCP_SEND_REQUEST_LEASE goto DHCP_NONE\r\n");
			}
			break;
		case DHCP_RECV_MESSAGE_OFFER:
			//ожидание ack
			if ( MS_DIFF_NOW(dhcp_ms) > DHCP_TIMEOUT_MS) {
				dhcp_state = DHCP_NONE;
				//ulog("DHCP_RECV_MESSAGE_OFFER goto DHCP_NONE\r\n");
			}
			break;
		case DHCP_RECV_ACK:
			//проверка lease
			if ( (dhcp_lease_time_ms != 0) && (MS_DIFF_NOW(dhcp_ms) > dhcp_lease_time_ms) ) {
				if (dhcp_extend_lease()) {
					//ulog("DHCP_RECV_ACK goto DHCP_SEND_REQUEST_LEASE\r\n");
					dhcp_state = DHCP_SEND_REQUEST_LEASE;
					dhcp_ms = get_ms();
				}
			}
			res = 1;
			break;


	}

	return res;
}

// -------------------- DNS -------------------------------

char * dns_parse_name(char *query)
{
  unsigned char n;

  do {
    n = *query++;

    while(n > 0) {
      /*      printf("%c", *query);*/
      ++query;
      --n;
    };
    /*    printf(".");*/
  } while(*query != 0);
  /*  printf("\n");*/
  return query + 1;
}

void dns_answer(uint16_t id, uint32_t ipaddr)
{
    //ulog_fmt("dns_answer id=%d\r\n", id);
	if (id >= DNS_CACHE_SIZE) return;
	dns_cache[id].ip_addr = ipaddr;
}


void dns_filter(uint8_t * data, uint16_t data_len)
{

	dns_answer_t * ans;

	dns_request_t * dns_request = (dns_request_t *)data;

	uint16_t id = NTOHS(dns_request->id); //id запроса

   	ans = (dns_answer_t *)(data + data_len - sizeof(dns_answer_t));
   	if(ans->type == HTONS(1) && ans->class == HTONS(1) && ans->len == HTONS(4)) {
   		dns_answer(id, ans->ipaddr);
   		return;
   	}

    uint16_t nanswers = HTONS(dns_request->numanswers); //кол-во ответов
    //ulog_fmt("dns_answer nanswers=%d\r\n", nanswers);
    char * nameptr = dns_parse_name((char *)data + sizeof(dns_request_t)) + 4;

    while (nanswers > 0) {

    	if(*nameptr & 0xc0) nameptr +=2;
    	else nameptr = dns_parse_name((char *)nameptr);
    	ans = (dns_answer_t *)nameptr;
    	if(ans->type == HTONS(1) && ans->class == HTONS(1) && ans->len == HTONS(4)) {
    		dns_answer(id, ans->ipaddr);
    		return;
    	} else 	nameptr = nameptr + 10 + HTONS(ans->len);
    	--nanswers;
    }
}

// Отправка запроса на DNS-сервер
uint8_t dns_request(uint16_t id, char * name)
{
    dns_request_t * dns_request =  (dns_request_t *)udp_snd_packet_data;

    // остальные поля заполняем нулями
    memset(dns_request, 0, sizeof(dns_request_t));

    char *query, *nameptr, *nptr;
    uint8_t n;


    dns_request->id = HTONS(id);
    dns_request->flags1 = DNS_FLAG1_RD;
    dns_request->numquestions = HTONS(1);

    query = (char *)udp_snd_packet_data + sizeof(dns_request_t);
    nameptr = name;
    --nameptr;
    /* Convert hostname into suitable query format. */
    do {
    	++nameptr;
    	nptr = query;
    	++query;
    	for(n = 0; *nameptr != '.' && *nameptr != 0; ++nameptr) {
    		*query = *nameptr;
    		++query;
    		++n;
    	}
    	*nptr = n;
    } while(*nameptr != 0);


	static unsigned char endquery[] =  {0,0,1,0,1};
	memcpy(query, endquery, 5);

	uint16_t len = (uint8_t *)query + 5 - udp_snd_packet_data;

    return udp_send(ip_dns, DNS_SERVER_PORT, DNS_CLIENT_PORT, udp_snd_packet_data, len);
}


int16_t dns_search_cache(char * node_name)
{
	if (node_name == NULL) return -1;

	if (strncmp(dns_cache[last_dns_resolve_index].name, node_name, DNS_CACHE_NAME_SIZE) == 0) return (int16_t)last_dns_resolve_index; //кэширование

	for(uint8_t i = 0; i < DNS_CACHE_SIZE; ++i)	{
		if (strncmp(dns_cache[i].name, node_name, DNS_CACHE_NAME_SIZE) == 0) {
			last_dns_resolve_index = i;
			return (int16_t)i;
		}
	}
	return -1;
}


uint32_t dns_resolve(char * node_name)
{
	int16_t index;

	if (node_name == NULL) return 0;

	index = dns_search_cache(node_name);
	//ulog_fmt("dns_search_cache  %d, %s\r\n", index, node_name);

	if (index != -1) {
		if (dns_cache[index].ip_addr) return dns_cache[index].ip_addr;
	} else {
		if (dns_cache_wr >= DNS_CACHE_SIZE) dns_cache_wr = 0;
		index = dns_cache_wr;
		dns_cache[dns_cache_wr].ip_addr = 0;
		strncpy(dns_cache[dns_cache_wr].name, node_name, DNS_CACHE_NAME_SIZE);
		dns_cache_wr++;
	}

	//ulog_fmt("dns_request %d, %s\r\n", index, node_name);
	dns_request(index, node_name);
	return 0;
}


// -------------------- UDP -------------------------------

uint8_t udp_send(uint32_t to_addr, uint32_t to_port, uint32_t from_port, uint8_t *data, uint16_t data_len)
{

	uint16_t dlen = MIN(data_len, udp_data_max_size);

	if  (udp_snd_packet_data != data) memcpy(udp_snd_packet_data, data, dlen);

	uint16_t len = sizeof(udp_packet_t) + dlen;
	udp_snd_packet->from_port = from_port;
	udp_snd_packet->to_port = to_port;
	udp_snd_packet->len = HTONS(len);
	udp_snd_packet->cksum = 0;
	udp_snd_packet->cksum = UDP_CHECKSUM((uint8_t*)udp_snd_packet, len, ip_addr, to_addr);
	return ip_snd(to_addr, (uint8_t *)udp_snd_packet,  len, IP_PROTOCOL_UDP);
}



void udp_filter(udp_packet_t *udp_packet, uint16_t udp_packet_len, uint32_t from_addr)
{
	uint16_t data_len = udp_packet_len - sizeof(udp_packet_t);
	uint8_t * data = (uint8_t *)udp_packet + sizeof(udp_packet_t);

	switch(udp_packet->to_port) {
		case DHCP_CLIENT_PORT:
			if (data_len >= sizeof(dhcp_message_t)) dhcp_filter(data, data_len, from_addr);
			break;
		case DNS_CLIENT_PORT:
			if (data_len >= sizeof(dns_request_t)) dns_filter(data, data_len);
			break;
		default:
			udp_recv(from_addr, udp_packet->from_port, udp_packet->to_port, data, data_len);
			break;
	}
}


// ---------------------- ICMP ----------------------------

void icmp_filter(icmp_echo_packet_t *icmp, uint32_t from_addr)
{
	if(icmp->type != ICMP_TYPE_ECHO_RQ) return;

	icmp_echo_packet_t * new_icmp = (icmp_echo_packet_t *)ip_snd_packet_data;

	new_icmp->type = ICMP_TYPE_ECHO_RPLY;
	new_icmp->code= icmp->code;
	new_icmp->id = icmp->id;
	new_icmp->seq = icmp->seq;
	new_icmp->cksum = icmp->cksum + 8; // update cksum
	//ulog("icmp send\r\n");
	ip_snd(from_addr, (uint8_t *)new_icmp,  sizeof(icmp_echo_packet_t), IP_PROTOCOL_ICMP);
}


// ---------------------- Ip ---------------------------------



uint8_t ip_snd(uint32_t to_addr, uint8_t * data,  uint16_t data_len, uint8_t protocol)
{
	uint8_t to_mac[6];
	uint32_t route_ip;
	uint8_t *mac_addr_to;

	//ulog_fmt("ip send begin data=%ld data_len=%d\r\n", (uint32_t)data, data_len);

	if (to_addr == IP_BROADCAST) memset(to_mac, 0xff, 6); // use broadcast MAC
	else
	{
		//ulog("ip_snd apply route\r\n");
		// apply route
		if( ((to_addr ^ ip_addr) & ip_mask) == 0 ) route_ip = to_addr;
		else route_ip = ip_gateway;

		// resolve mac address
		mac_addr_to = arp_resolve(route_ip);

		//ulog("ip_snd resolve mac address 1\r\n");
		if (!mac_addr_to) return 0;

		memcpy(to_mac, mac_addr_to, 6);
		//ulog("ip_snd resolve mac address 2\r\n");
	}


	uint16_t dlen = MIN(data_len, ip_data_max_size);

	if (ip_snd_packet_data != data) memcpy(ip_snd_packet_data, data, dlen);

	uint16_t len = sizeof(ip_packet_t) + dlen;

	ip_snd_packet->ver_head_len = 0x45;
	ip_snd_packet->tos = 0;
	ip_snd_packet->total_len = HTONS(len);
	ip_snd_packet->fragment_id = 0;
	ip_snd_packet->flags_framgent_offset = 0;
	ip_snd_packet->ttl = IP_PACKET_TTL;
	ip_snd_packet->protocol = protocol;
	ip_snd_packet->cksum = 0;
	ip_snd_packet->from_addr = ip_addr;
	ip_snd_packet->to_addr = to_addr;
	ip_snd_packet->cksum = ip_cksum(0, (void*)ip_snd_packet, sizeof(ip_packet_t));


	eth_snd(to_mac, (uint8_t *)ip_snd_packet, len,  ETH_TYPE_IP);
	return 1;
}


// ip пакет
void ip_filter(ip_packet_t *ip_packet, uint16_t ip_packet_len)
{
	uint16_t hcs;

	if (ip_packet->ver_head_len != 0x45) return;

	if ( (ip_packet->to_addr != ip_addr) && (ip_packet->to_addr != IP_BROADCAST) && (ip_packet->to_addr != 0xffffffff) ) return;

	hcs = ip_packet->cksum;
	ip_packet->cksum = 0;

	if (ip_cksum(0, (void*)ip_packet, sizeof(ip_packet_t)) != hcs) return;



	uint16_t len = NTOHS(ip_packet->total_len) - sizeof(ip_packet_t); //длина icmp или udp заголовка и данных

	//ip_rcv(ip_packet->from_addr, ip_packet->data,  len, ip_packet->protocol);


	switch (ip_packet->protocol) {
		case IP_PROTOCOL_ICMP:
			//ulog_fmt("ip rcv icmp from %s len=%d\r\n", ip2str(ip_packet->from_addr),  len);
			if (len >= sizeof(icmp_echo_packet_t)) icmp_filter((icmp_echo_packet_t *)((uint8_t *)ip_packet + sizeof(ip_packet_t)), ip_packet->from_addr);
			break;
		case IP_PROTOCOL_UDP:
			//ulog_fmt("ip rcv udp from %s len=%d\r\n", ip2str(ip_packet->from_addr),  len);
			if (len >= sizeof(udp_packet_t)) udp_filter((udp_packet_t *)((uint8_t *)ip_packet + sizeof(ip_packet_t)), len, ip_packet->from_addr);
			break;
		case IP_PROTOCOL_TCP:
			//ulog_fmt("ip rcv tcp from %s len=%d\r\n", ip2str(ip_packet->from_addr),  len);
			if (len >= sizeof(tcp_packet_t)) tcp_filter((tcp_packet_t *)((uint8_t *)ip_packet + sizeof(ip_packet_t)), len, ip_packet->from_addr);
			break;
	}
}


// ---------------------- Arp ---------------------------------

uint8_t *arp_search_cache(uint32_t node_ip_addr)
{
	if (!node_ip_addr) return NULL;

	if (arp_cache[last_arp_search_cache_index].ip_addr == node_ip_addr) return arp_cache[last_arp_search_cache_index].mac_addr; //кэширование

	for(uint8_t i = 0; i < ARP_CACHE_SIZE; ++i)	{
		if (arp_cache[i].ip_addr == node_ip_addr) {
			last_arp_search_cache_index = i;
			return arp_cache[i].mac_addr;
		}
	}
	return NULL;
}

//static uint32_t arp_resolve_last_ip = 0;
//static uint32_t arp_resolve_last_ms = 0;
//#define ARP_REXMIT_TIMEOUT	100


// resolve MAC address
// returns 0 if still resolving
// (invalidates net_buffer if not resolved)
uint8_t *arp_resolve(uint32_t node_ip_addr)
{
	uint8_t *mac;

	if (!node_ip_addr) return NULL;

	//ulog("arp_resolve search arp cache\r\n");
	// search arp cache
	if((mac = arp_search_cache(node_ip_addr)))
		return mac;

//	if (arp_resolve_last_ip && (node_ip_addr == arp_resolve_last_ip)) {
//		if  (MS_DIFF_NOW(arp_resolve_last_ms) < ARP_REXMIT_TIMEOUT) return NULL;
//	}



	//ulog("arp_resolve send request\r\n");
	// send request
	arp_message_t * msg = (arp_message_t *)eth_snd_frame_data;

	msg->hw_type = ARP_HW_TYPE_ETH;
	msg->proto_type = ARP_PROTO_TYPE_IP;
	msg->hw_addr_len = 6;
	msg->proto_addr_len = 4;
	msg->type = ARP_TYPE_REQUEST;
	memcpy(msg->mac_addr_from, mac_addr, 6);
	msg->ip_addr_from = ip_addr;
	memset(msg->mac_addr_to, 0x00, 6);
	msg->ip_addr_to = node_ip_addr;

	//ulog_fmt("arp_resolve send query ip:%s\r\n", ip2str(msg->ip_addr_to));

	//arp_resolve_last_ip = node_ip_addr;
	//arp_resolve_last_ms = get_ms();

	eth_snd(broadcast_mac, eth_snd_frame_data, sizeof(arp_message_t), ETH_TYPE_ARP);

	//ulog("arp_resolve finish\r\n");


	return NULL;
}

// process arp packet
void arp_filter(arp_message_t *msg, uint8_t * from_addr)
{

	if( (msg->hw_type != ARP_HW_TYPE_ETH) || (msg->proto_type != ARP_PROTO_TYPE_IP) ||	(msg->ip_addr_to != ip_addr) ) return;


	arp_message_t *new_msg;

	switch (msg->type)	{
		case ARP_TYPE_REQUEST:
			new_msg = (arp_message_t *)eth_snd_frame_data;
			new_msg->hw_type = msg->hw_type;
			new_msg->proto_type = msg->proto_type;
			new_msg->hw_addr_len = msg->hw_addr_len;
			new_msg->proto_addr_len = msg->proto_addr_len;
			new_msg->type = ARP_TYPE_RESPONSE;
			memcpy(new_msg->mac_addr_to, msg->mac_addr_from, 6);
			memcpy(new_msg->mac_addr_from, mac_addr, 6);
			new_msg->ip_addr_to = msg->ip_addr_from;
			new_msg->ip_addr_from = ip_addr;
			//ulog_fmt("arp snd response to %s=%s\r\n", ip2str(new_msg->ip_addr_to), mac2str(new_msg->mac_addr_to));
			eth_snd(from_addr, eth_snd_frame_data, sizeof(arp_message_t), ETH_TYPE_ARP);
			break;
		case ARP_TYPE_RESPONSE:
			if (!arp_search_cache(msg->ip_addr_from))
			{
				if (arp_cache_wr >= ARP_CACHE_SIZE) arp_cache_wr = 0; //!!! должна быть в начале !!!
				arp_cache[arp_cache_wr].ip_addr = msg->ip_addr_from;
				memcpy(arp_cache[arp_cache_wr].mac_addr, msg->mac_addr_from, 6);
				arp_cache_wr++;
				//ulog_fmt("arp to cache %s=%s size %d\r\n", ip2str(msg->ip_addr_from), mac2str(msg->mac_addr_from), arp_cache_wr);
			}
			break;
	}
}

// ---------------------- Ethernet ---------------------------------

void eth_snd(uint8_t * to_mac, uint8_t *data, uint16_t data_len, uint16_t type)
{
	if ( (to_mac == NULL) || (data == NULL) || (data_len == 0) ) return;

	uint16_t dlen = MIN(data_len, eth_data_max_size);

	memcpy(eth_snd_frame->to_addr, to_mac, 6);
	memcpy(eth_snd_frame->from_addr, mac_addr, 6);
	eth_snd_frame->type = type;
	if (eth_snd_frame_data != data) memcpy(eth_snd_frame_data, data, dlen);

	//ulog_fmt("eth_send %d\r\n", sizeof(eth_frame_t) + dlen);
	eth_send(eth_buf, sizeof(eth_frame_t) + dlen);
}

void eth_recv(uint8_t * data, uint16_t data_len)
{
	if (data_len < sizeof(eth_frame_t)) return;

	eth_frame_t * eth_frame = (eth_frame_t *)data;
	//if (memcmp(eth_frame->to_addr, mac_addr, 6) != 0) return;
	uint16_t len = data_len - sizeof(eth_frame_t); //длина без ethernet заголовка


	switch (eth_frame->type) {
		case ETH_TYPE_ARP:
			if (len >= sizeof(arp_message_t)) arp_filter((arp_message_t *)(data + sizeof(eth_frame_t)), eth_frame->from_addr);
			break;
		case ETH_TYPE_IP:
			//if (len >= sizeof(ip_packet_t)) ip_filter((ip_packet_t *)(data + sizeof(eth_frame_t)), len);
			if (len >= sizeof(ip_packet_t)) {
				ip_packet_t * ip_packet = (ip_packet_t *)(data + sizeof(eth_frame_t));
				if (ip_packet->total_len < len) {
					 //ulog_fmt("ip_packet->total_len (%d) != len (%d)\r\n", ip_packet->total_len, len);
					 ip_filter(ip_packet, ip_packet->total_len);
					 if (data_len > (sizeof(eth_frame_t) + ip_packet->total_len))
						 eth_recv(data + sizeof(eth_frame_t) + ip_packet->total_len, data_len - (sizeof(eth_frame_t) + ip_packet->total_len));
				}
				else ip_filter((ip_packet_t *)(data + sizeof(eth_frame_t)), len);
			}
			break;
	}
}

// -------------------------- More ----------------------------------

