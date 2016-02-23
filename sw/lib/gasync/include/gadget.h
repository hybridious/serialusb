/*
 Copyright (c) 2016 Mathieu Laurendeau
 License: GPLv3
 */

#ifndef GADGET_H_
#define GADGET_H_

#include <gusb.h>

int gadget_get_properties(const char * path, s_ep_props * props);

int gadget_open(const char * path);

#endif /* GADGET_H_ */
