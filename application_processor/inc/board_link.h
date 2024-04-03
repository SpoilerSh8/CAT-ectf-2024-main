#ifndef __BOARD_LINK__
#define __BOARD_LINK__

#include "simple_i2c_controller.h"

/******************************** MACRO DEFINITIONS ********************************/
// Last byte of the component ID is the I2C address
#define COMPONENT_ADDR_MASK 0x000000FF             
#define SUCCESS_RETURN 0
#define ERROR_RETURN -1

/******************************** FUNCTION PROTOTYPES ********************************/
/**
 * @brief Initialize the board link connection
 * 
 * Initiailize the underlying i2c simple interface
*/
void board_link_init(void);
int secure_send(uint8_t address, uint8_t* buffer, uint8_t len);
int secure_receive(i2c_addr_t address, uint8_t* buffer, uint8_t len);

/**
 * @brief Convert 4-byte component ID to I2C address
 * 
 * @param component_id: uint32_t, component_id to convert
 * 
 * @return i2c_addr_t, i2c address
*/
i2c_addr_t component_id_to_i2c_addr(uint32_t component_id);

/**
 * @brief Send an arbitrary packet over I2C
 * 
 * @param address: i2c_addr_t, i2c address
 * @param len: uint8_t, length of the packet
 * @param packet: uint8_t*, pointer to packet to be sent
 * 
 * @return status: SUCCESS_RETURN if success, ERROR_RETURN if error
 * Function sends an arbitrary packet over i2c to a specified component
*/
int send_packet(i2c_addr_t address, uint8_t len, uint8_t* packet);

/**
 * @brief Poll a component and receive a packet
 * 
 * @param address: i2c_addr_t, i2c address
 * @param packet: uint8_t*, pointer to a buffer where a packet will be received 
 * 
 * @return int: size of data received, ERROR_RETURN if error
*/
int poll_and_receive_packet(i2c_addr_t address, uint8_t* packet);

#endif
