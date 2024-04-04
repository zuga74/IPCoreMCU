/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body
  ******************************************************************************
  * @attention
  *
  * <h2><center>&copy; Copyright (c) 2021 STMicroelectronics.
  * All rights reserved.</center></h2>
  *
  * This software component is licensed by ST under BSD 3-Clause license,
  * the "License"; You may not use this file except in compliance with the
  * License. You may obtain a copy of the License at:
  *                        opensource.org/licenses/BSD-3-Clause
  *
  ******************************************************************************
  */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "ulog.h"
#include "IPCore.h"
#include "EtherShield.h"
#include "more.h"

/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */
/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
IWDG_HandleTypeDef hiwdg;

SPI_HandleTypeDef hspi2;

UART_HandleTypeDef huart1;

/* USER CODE BEGIN PV */

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_SPI2_Init(void);
static void MX_USART1_UART_Init(void);
static void MX_IWDG_Init(void);
/* USER CODE BEGIN PFP */

/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */

//#define PRINT_FRAME
//#define PRINT_FRAME_FILTER 	ETH_TYPE_IP

#define RN	"\r\n"

//буфер под прием ETHERNET пакетов
//buffer for receiving ETHERNET packets
static uint8_t net_buf[1600];
#ifdef USE_DHCP
//использовать DHCP?
//use DHCP?
static uint8_t use_dhcp = 0;
#endif
//таймер на посылку пакета
//timer for sending a packet
static uint32_t tick_snd;
#ifdef USE_TCP
//таймер на TCP pool
//timer on TCP pool
static uint32_t tick_tcp_pool;
#endif


#ifdef USE_TCP
// ---------------------- HTTP SERVER EXAMPLE (TCP) -------------------------

#define HTTP_SERVER			"IPCore/1.0 Alfa"
#define HTTP_SERVER_PORT	80

const char http_200[] =
"HTTP/1.1 200 OK"RN
"Content-Type: text/html"RN
"Content-Encoding: identity"RN
"Server: "HTTP_SERVER""RN
"Connection: Closed"RN
""RN
;

const char html_index_header[] =
"<!DOCTYPE html>"RN
"<html  lang=\"en\">"RN
"	<head>"RN
"		<title>"HTTP_SERVER"</title>"RN
"		<meta charset=\"UTF-8\" />"RN
"	</head>"RN
"<body>"RN
;

const char html_index_body[] = "This is a test string<br>\r\n";

const char html_index_footer[] =
"</body>"RN
"</html>"
;

const char http_404[] =
"HTTP/1.1 404 Not Found"RN
"Server: "HTTP_SERVER""RN
"Connection: Closed"RN
""RN
"Not Found";

const char http_400[] =
"HTTP/1.1 400 Bad Request"RN
"Server: "HTTP_SERVER""RN
"Connection: Closed"RN
""RN
"Bad Request";


// ---------------------- HTTP CLIENT EXAMPLE (TCP) -------------------------

const char http_get[] =
"GET %s HTTP/1.1"RN
"Host: %s"RN
"Accept-Encoding: identity"RN
"Accept: */*"RN
"Connection: Close"RN
"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Safari/537.36 Edg/89.0.774.57"RN
"Accept-Language: ru,en;q=0.9,en-GB;q=0.8,en-US;q=0.7"RN
""RN
;

#ifdef USE_DNS
#define HTTP_CLIENT_HOST	"example.com"
#else
#define HTTP_CLIENT_HOST	"93.184.216.34"
#endif
#define HTTP_CLIENT_PORT	80
#define HTTP_CLIENT_PATH	"/"
static uint32_t http_client_ip = 0;

#endif

// ---------------------- SIP CLIENT EXAMPLE (UDP) -------------------------

#ifdef USE_UDP

#ifdef USE_DNS
#define SIP_SERVER_HOST 	"iptel.org"
#else
#define SIP_SERVER_HOST 	"212.79.111.155"
#endif
#define SIP_SERVER_PORT		5060
#define SIP_CLIENT_ID		"3335"
#define SIP_CLIENT_PORT		12345
static uint32_t sip_client_ip = 0;

const char sip_snd_pack[] =
"REGISTER sip:"SIP_SERVER_HOST" SIP/2.0"RN
"Via: SIP/2.0/UDP %s:%d;rport;branch=z9hG4bKPj57ba556fab2b4d7aaffe54ae55cdb558"RN
"From: "SIP_CLIENT_ID"<sip:"SIP_CLIENT_ID"@"SIP_SERVER_HOST">;tag=e3228d7dac5c41a0b53ca65a25b81b44"RN
"To: "SIP_CLIENT_ID"<sip:"SIP_CLIENT_ID"@"SIP_SERVER_HOST">"RN
"Call-ID: d4ff74f019d44f04a50c1e4eceb350a8"RN
"CSeq: 12 REGISTER"RN
"Contact: *"RN
"Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, INFO, MESSAGE"RN
"Max-Forwards: 70"RN
"Expires: 0"RN
"Content-Length: 0"RN
""RN
;

#endif

// --------------------------------------------------------------------------

void print_ip_config(void)
{
	ulog_fmt("ip %s\r\n", ip2str(get_ip_addr()));
	ulog_fmt("rout %s\r\n", ip2str(get_ip_gateway()));
	ulog_fmt("mask %s\r\n", ip2str(get_ip_mask()));
#ifdef USE_DNS
	ulog_fmt("dns ip %s\r\n", ip2str(get_ip_dns()));
#endif
#ifdef USE_DHCP
	if (use_dhcp) {
		ulog_fmt("dhcp ip %s\r\n", ip2str(get_ip_dhcp()));
		ulog_fmt("dhcp lease time %ld\r\n", get_dhcp_lease_time_ms());
	}
#endif
}


// --------------- FUNCTIONS MUST BE DIFINED ---------------------------------

uint32_t get_ms(void)
{
	return HAL_GetTick();
}

void eth_send(uint8_t * data, uint16_t data_len)
{
	enc28j60PacketSend(data_len, data);

#ifdef PRINT_FRAME
#ifdef PRINT_FRAME_FILTER
	if (((eth_frame_t *)data)->type == PRINT_FRAME_FILTER)
#endif
		print_frame_k12(data, data_len);
#endif
}

#ifdef USE_DHCP
void dhcp_complete(void)
{
	ulog("dhcp comlete\r\n");
	print_ip_config();
}
#endif

#ifdef USE_TCP
void tcp_recv(uint8_t id, uint8_t * data, uint16_t data_len)
{
	ulog_fmt("tcp recv  id:%d data_len:%d\r\n", id, data_len);

	tcp_state_t * tcp_state = tcp_get_state(id);

	if (tcp_state->local_port == HTONS(HTTP_SERVER_PORT)) {
		//HTTP server
		if (memcmp(data, "GET / ", 6) == 0)	{
			//быстрая посылка данных только с ACK
			//fast data sending only with ACK
			tcp_send_ack(id, (uint8_t *)http_200, strlen(http_200));
			tcp_send_ack(id, (uint8_t *)html_index_header, strlen(html_index_header));
			for (int i = 0; i < 10; ++i) tcp_send_ack(id, (uint8_t *)html_index_body, strlen(html_index_body));
			tcp_send_fin(id, (uint8_t *)html_index_footer, strlen(html_index_footer)); //at the end send FIN
		}
		else if (memcmp(data, "GET /", 5) == 0)	tcp_send_fin(id, (uint8_t *)http_404, strlen(http_404));
		else tcp_send_fin(id, (uint8_t *)http_400, strlen(http_400));
	} else {
		//HTTP client
		//пришли данные с сервера от запросов HTTP клиента
		//data came from the server from HTTP client requests
		ulog("http client receive data:\r\n\r\n");
		data[data_len] = 0;
		ulog((char * )data);
		ulog("\r\n");
	}
}

void tcp_recv_connected(uint8_t id)
{
	char * buf;
	tcp_state_t * tcp_state = tcp_get_state(id);

	ulog_fmt("tcp connected id:%d connect to %s:%d\r\n", id, ip2str(tcp_state->remote_addr), NTOHS(tcp_state->remote_port));

	if ( http_client_ip && (tcp_state->remote_addr == http_client_ip) &&  (NTOHS(tcp_state->remote_port) == HTTP_CLIENT_PORT) ) {
		//http клиент соединился с удаленным хостом
		//http client connected to remote host
		buf = (char * )get_tcp_snd_packet_data();
		sprintf(buf, http_get, HTTP_CLIENT_PATH, HTTP_CLIENT_HOST);
		//запрос GET к клиенту
		//GET request to the client
		tcp_send_push(id, (uint8_t *)buf, strlen(buf));
		ulog("http client send GET:\r\n\r\n");
		ulog(buf);
		ulog("\r\n");
	}

}

void tcp_recv_closed(uint8_t id, uint8_t why)
{
	ulog_fmt("tcp closed  id:%d why:%d\r\n", id, why);
}

uint8_t tcp_accept(uint32_t from_addr, uint16_t from_port, uint16_t to_port)
{
	ulog_fmt("tcp accept  from %s:%d to port %d\r\n", ip2str(from_addr), NTOHS(from_port), NTOHS(to_port));
	//разрешаем соединение всем клиентам к нашему серверу на порту 80
	//allow all clients to connect to our server on port 80
	return NTOHS(to_port) == HTTP_SERVER_PORT;
}
#endif

#ifdef USE_UDP
void udp_recv(uint32_t from_addr, uint16_t from_port, uint16_t to_port, uint8_t * data, uint16_t data_len)
{
	ulog_fmt("udp rsv from %s:%d to port %d len %d\r\n", ip2str(from_addr), NTOHS(from_port), NTOHS(to_port), data_len);

	if ( sip_client_ip && (from_addr == sip_client_ip) &&  (NTOHS(from_port) == SIP_SERVER_PORT) ) {
		ulog("sip client receive data:\r\n\r\n");
		data[data_len] = 0;
		ulog((char * )data);
		ulog("\r\n");
	}
}
#endif


#ifdef WITH_TCP_REXMIT

void tcp_rexmit(uint8_t id, uint32_t rexmit_sec_num)
{

	tcp_state_t * tcp_state;

	tcp_state = tcp_get_state(id);
	tcp_state->status = TCP_ESTABLISHED;
	tcp_state->seq_num = rexmit_sec_num;

	//search from database packets where id (connection number) and database.rexmit_sec_num >= rexmit_sec_num
	//and repeat packets
	//tcp_send_flags(id, database.data, database.data_len, database.flags);

}

void tcp_rexmit_db_push(uint8_t id, uint32_t rexmit_sec_num, uint8_t * data, uint16_t data_len, uint8_t flags)
{
	//write to database id (connection number), rexmit_sec_num, data[data_len], flags
}

void tcp_rexmit_db_clear(uint8_t id)
{
	//clear from database where id (connection number)
}

void tcp_rexmit_db_pop(uint8_t id, uint32_t rexmit_sec_num)
{

}

#endif

// --------------- NET PROCESS ---------------------------------

void net_process(void)
{
	uint16_t eth_len;

	eth_len = ES_enc28j60PacketReceive(sizeof(net_buf), net_buf);
	if (eth_len > 0) {
#ifdef PRINT_FRAME
#ifdef PRINT_FRAME_FILTER
		if (((eth_frame_t *)net_buf)->type == PRINT_FRAME_FILTER)
#endif
			print_frame_k12(net_buf, eth_len);
#endif
		eth_recv(net_buf, eth_len);
	}

#ifdef USE_DHCP
	if (use_dhcp) {
		if (!dhcp_resolve()) return; //return if dhcp not resolve
	}
#endif

#ifdef USE_TCP
	if  (MS_DIFF_NOW(tick_tcp_pool) > TCP_CONN_TIMEOUT) {
		tick_tcp_pool = get_ms();
		tcp_poll(); //call pooll periodically
	}
#endif


	if  (MS_DIFF_NOW(tick_snd) > 30000) { // once every 30 sec
		tick_snd = get_ms();

 	 	//HTTP CLIENT EXAMPLE (TCP)
#ifdef USE_TCP
		if (!http_client_ip) http_client_ip = str2ip(HTTP_CLIENT_HOST);
#ifdef USE_DNS
		if (!http_client_ip) http_client_ip = dns_resolve(HTTP_CLIENT_HOST);
#endif
		if (http_client_ip) {
			uint16_t free_port = tcp_get_free_port();
			uint8_t id = tcp_send_connect(http_client_ip, HTONS(HTTP_CLIENT_PORT), HTONS(free_port));
			if (id != 0xff)	ulog_fmt("http client send connect successful id:%d\r\n", id);
		}
#endif




		//SIP CLIENT EXAMPLE (UDP)
#ifdef USE_UDP
		if (!sip_client_ip) sip_client_ip = str2ip(SIP_SERVER_HOST);
#ifdef USE_DNS
		if (!sip_client_ip) sip_client_ip = dns_resolve(SIP_SERVER_HOST);
#endif
		if (sip_client_ip) {
			char * buf = (char * )get_udp_snd_packet_data();
			sprintf(buf, sip_snd_pack, ip2str(get_ip_addr()), SIP_CLIENT_PORT);
			if ( udp_send(sip_client_ip, HTONS(SIP_SERVER_PORT), HTONS(SIP_CLIENT_PORT), (uint8_t *)buf, strlen(buf)) ) {
				ulog("sip send REGISTER to "SIP_SERVER_HOST"\r\n\r\n");
				ulog(buf);
				ulog("\r\n");
			}
		}
#endif



	}


}




/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{
  /* USER CODE BEGIN 1 */

  /* USER CODE END 1 */

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* USER CODE BEGIN Init */

  /* USER CODE END Init */

  /* Configure the system clock */
  SystemClock_Config();

  /* USER CODE BEGIN SysInit */

  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_SPI2_Init();
  MX_USART1_UART_Init();
  MX_IWDG_Init();
  /* USER CODE BEGIN 2 */

  ulog_fmt("start myIPCore ver:%d\r\n", 9877);

  HAL_GPIO_WritePin(ETHERNET_RES_PORT, ETHERNET_RES_PIN, GPIO_PIN_SET);
  HAL_Delay(100);
  HAL_GPIO_WritePin(ETHERNET_RES_PORT, ETHERNET_RES_PIN, GPIO_PIN_RESET);
  HAL_Delay(100);
  HAL_GPIO_WritePin(ETHERNET_RES_PORT, ETHERNET_RES_PIN, GPIO_PIN_SET);
  HAL_Delay(500);

  uint8_t mac[6] = {0x1c,0x1b, 0x0d, 0x2c, 0xcb, 0x55};
  ES_enc28j60SpiInit(&hspi2);
  ES_enc28j60Init(mac);
  HAL_Delay(500);


  ipcore_init();
  set_mac(mac);


#ifdef USE_DHCP
  if (use_dhcp) {
	  dhcp_init();
  } else  {
#endif
	  set_ip_addr(str2ip("192.168.100.190"));
	  set_ip_mask(str2ip("255.255.255.0"));
	  set_ip_gateway(str2ip("192.168.100.1"));
#ifdef USE_DNS
	  set_ip_dns(str2ip("8.8.8.8"));
#endif
	  print_ip_config();
	  //arp_resolve(get_ip_gateway());
#ifdef USE_DHCP
  }
#endif




//  uint32_t tick_rst = get_ms();
//  uint8_t work_minutes = 3;
  uint32_t iwdg_tick = get_ms();
  tick_snd = get_ms();
#ifdef USE_TCP
  tick_tcp_pool = get_ms();
#endif


  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
  while (1)
  {
    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */

	  net_process();


//	  if  (MS_DIFF_NOW(tick_rst) >  60000) {
//		tick_rst = HAL_GetTick();
//		work_minutes--;
//		ulog_fmt("reset after %d minutes\r\n", work_minutes);
//		if (work_minutes == 0) NVIC_SystemReset(); //work only work_minutes
//	  }

	  if (MS_DIFF_NOW(iwdg_tick) > 100) {
			iwdg_tick = HAL_GetTick();
			HAL_IWDG_Refresh(&hiwdg); // reset WatchDog
	  }
  }
  /* USER CODE END 3 */
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Initializes the RCC Oscillators according to the specified parameters
  * in the RCC_OscInitTypeDef structure.
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_LSI|RCC_OSCILLATORTYPE_HSE;
  RCC_OscInitStruct.HSEState = RCC_HSE_ON;
  RCC_OscInitStruct.HSEPredivValue = RCC_HSE_PREDIV_DIV1;
  RCC_OscInitStruct.HSIState = RCC_HSI_ON;
  RCC_OscInitStruct.LSIState = RCC_LSI_ON;
  RCC_OscInitStruct.Prediv1Source = RCC_PREDIV1_SOURCE_HSE;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSE;
  RCC_OscInitStruct.PLL.PLLMUL = RCC_PLL_MUL6;
  RCC_OscInitStruct.PLL2.PLL2State = RCC_PLL_NONE;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }
  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV2;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_2) != HAL_OK)
  {
    Error_Handler();
  }
  /** Configure the Systick interrupt time
  */
  __HAL_RCC_PLLI2S_ENABLE();
}

/**
  * @brief IWDG Initialization Function
  * @param None
  * @retval None
  */
static void MX_IWDG_Init(void)
{

  /* USER CODE BEGIN IWDG_Init 0 */

  /* USER CODE END IWDG_Init 0 */

  /* USER CODE BEGIN IWDG_Init 1 */

  /* USER CODE END IWDG_Init 1 */
  hiwdg.Instance = IWDG;
  hiwdg.Init.Prescaler = IWDG_PRESCALER_256;
  hiwdg.Init.Reload = 3125;
  if (HAL_IWDG_Init(&hiwdg) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN IWDG_Init 2 */

  /* USER CODE END IWDG_Init 2 */

}

/**
  * @brief SPI2 Initialization Function
  * @param None
  * @retval None
  */
static void MX_SPI2_Init(void)
{

  /* USER CODE BEGIN SPI2_Init 0 */

  /* USER CODE END SPI2_Init 0 */

  /* USER CODE BEGIN SPI2_Init 1 */

  /* USER CODE END SPI2_Init 1 */
  /* SPI2 parameter configuration*/
  hspi2.Instance = SPI2;
  hspi2.Init.Mode = SPI_MODE_MASTER;
  hspi2.Init.Direction = SPI_DIRECTION_2LINES;
  hspi2.Init.DataSize = SPI_DATASIZE_8BIT;
  hspi2.Init.CLKPolarity = SPI_POLARITY_LOW;
  hspi2.Init.CLKPhase = SPI_PHASE_1EDGE;
  hspi2.Init.NSS = SPI_NSS_SOFT;
  hspi2.Init.BaudRatePrescaler = SPI_BAUDRATEPRESCALER_2;
  hspi2.Init.FirstBit = SPI_FIRSTBIT_MSB;
  hspi2.Init.TIMode = SPI_TIMODE_DISABLE;
  hspi2.Init.CRCCalculation = SPI_CRCCALCULATION_DISABLE;
  hspi2.Init.CRCPolynomial = 10;
  if (HAL_SPI_Init(&hspi2) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN SPI2_Init 2 */

  /* USER CODE END SPI2_Init 2 */

}

/**
  * @brief USART1 Initialization Function
  * @param None
  * @retval None
  */
static void MX_USART1_UART_Init(void)
{

  /* USER CODE BEGIN USART1_Init 0 */

  /* USER CODE END USART1_Init 0 */

  /* USER CODE BEGIN USART1_Init 1 */

  /* USER CODE END USART1_Init 1 */
  huart1.Instance = USART1;
  huart1.Init.BaudRate = 19200;
  huart1.Init.WordLength = UART_WORDLENGTH_8B;
  huart1.Init.StopBits = UART_STOPBITS_1;
  huart1.Init.Parity = UART_PARITY_NONE;
  huart1.Init.Mode = UART_MODE_TX_RX;
  huart1.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart1.Init.OverSampling = UART_OVERSAMPLING_16;
  if (HAL_UART_Init(&huart1) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN USART1_Init 2 */

  /* USER CODE END USART1_Init 2 */

}

/**
  * @brief GPIO Initialization Function
  * @param None
  * @retval None
  */
static void MX_GPIO_Init(void)
{
  GPIO_InitTypeDef GPIO_InitStruct = {0};

  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOB_CLK_ENABLE();
  __HAL_RCC_GPIOD_CLK_ENABLE();
  __HAL_RCC_GPIOA_CLK_ENABLE();

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(ETHERNET_CS_PIN_GPIO_Port, ETHERNET_CS_PIN_Pin, GPIO_PIN_RESET);

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(B_BUSY_GPIO_Port, B_BUSY_Pin, GPIO_PIN_RESET);

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(ETHERNET_RES_PIN_GPIO_Port, ETHERNET_RES_PIN_Pin, GPIO_PIN_RESET);

  /*Configure GPIO pin : ETHERNET_CS_PIN_Pin */
  GPIO_InitStruct.Pin = ETHERNET_CS_PIN_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_PULLUP;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(ETHERNET_CS_PIN_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pin : B_BUSY_Pin */
  GPIO_InitStruct.Pin = B_BUSY_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(B_BUSY_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pin : BUSY_Pin */
  GPIO_InitStruct.Pin = BUSY_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_INPUT;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(BUSY_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pin : ETHERNET_RES_PIN_Pin */
  GPIO_InitStruct.Pin = ETHERNET_RES_PIN_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_PULLUP;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(ETHERNET_RES_PIN_GPIO_Port, &GPIO_InitStruct);

}

/* USER CODE BEGIN 4 */

/* USER CODE END 4 */

 /**
  * @brief  Period elapsed callback in non blocking mode
  * @note   This function is called  when TIM1 interrupt took place, inside
  * HAL_TIM_IRQHandler(). It makes a direct call to HAL_IncTick() to increment
  * a global variable "uwTick" used as application time base.
  * @param  htim : TIM handle
  * @retval None
  */
void HAL_TIM_PeriodElapsedCallback(TIM_HandleTypeDef *htim)
{
  /* USER CODE BEGIN Callback 0 */

  /* USER CODE END Callback 0 */
  if (htim->Instance == TIM1) {
    HAL_IncTick();
  }
  /* USER CODE BEGIN Callback 1 */

  /* USER CODE END Callback 1 */
}

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  /* User can add his own implementation to report the HAL error return state */
  __disable_irq();
  while (1)
  {
  }
  /* USER CODE END Error_Handler_Debug */
}

#ifdef  USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
