#define POST_BOOT
#include <stdint.h>
#include <stdio.h>
#include "simple_i2c_controller.h"


int secure_send(uint8_t address, uint8_t* buffer, uint8_t len);
int secure_receive(i2c_addr_t address, uint8_t* buffer, uint8_t len);
int get_provisioned_ids(uint32_t* buffer);