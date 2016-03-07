/*
 Copyright (c) 2016 Mathieu Laurendeau
 License: GPLv3
 */

#ifndef GADGET_H_
#define GADGET_H_

#include <gusb.h>

int gadget_open(const char * path);
int gadget_close(int device);

const s_ep_props * gadget_get_properties(int device);
int gadget_configure(int device, s_usb_descriptors * descriptors, unsigned short endpoints[2]);
int gadget_register(int device, int user, USBASYNC_READ_CALLBACK fp_read, USBASYNC_WRITE_CALLBACK fp_write,
    USBASYNC_CLOSE_CALLBACK fp_close, GPOLL_REGISTER_FD fp_register);
int gadget_write(int device, unsigned char endpoint, const void * buf, unsigned int count);
int gadget_poll(int device, unsigned char endpoint);
int gadget_stall_control(int device, unsigned char direction);
int gadget_ack_control(int device, unsigned char direction);

#endif /* GADGET_H_ */
