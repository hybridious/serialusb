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
int gadget_configure(int device, s_usb_descriptors * descriptors);

#endif /* GADGET_H_ */
