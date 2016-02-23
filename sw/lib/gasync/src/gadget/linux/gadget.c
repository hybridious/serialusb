/*
 Copyright (c) 2016 Mathieu Laurendeau
 License: GPLv3
 */

#include <gadget.h>

#include <stdio.h>
#include <proxy.h>
#include <protocol.h>
#include <dirent.h>
#include <string.h>

#define PRINT_ERROR_ERRNO(MSG) perror(MSG);

int gadget_get_properties(const char * path, s_ep_props * props) {

   struct dirent * d;

   DIR * dirp = opendir(path);
   if (dirp == NULL) {
     PRINT_ERROR_ERRNO("opendir")
     return -1;
   }

   while ((d = readdir(dirp))) {

     if (d->d_type == DT_REG) {
       char * ptr = d->d_name;
       if (ptr[0] != 'e' || ptr[1] != 'p') {
         continue;
       }
       ptr += 2;
       unsigned int number;
       int ret = sscanf(ptr, "%u", &number);
       if (ret != 1 || number == 0 || number > USB_ENDPOINT_NUMBER_MASK) {
         fprintf(stderr, "bad endpoint number\n");
         continue;
       }
       if (number > 9) {
         ptr += 2;
       } else {
         ptr += 1;
       }
       --number;
       unsigned char dir;
       if (strstr(ptr, "out")) {
         dir = 0;
         ptr += 3;
       } else if (strstr(ptr, "in")) {
         dir = 1;
         ptr += 2;
       } else {
         dir = 2;
       }
       unsigned char prop;
       if (strstr(ptr, "-iso")) {
         prop = GUSB_EP_CAP_ISO;
       } else if (strstr(ptr, "-int")) {
         prop = GUSB_EP_CAP_INT;
       } else if (strstr(ptr, "-bulk")) {
         prop = GUSB_EP_CAP_BLK;
       } else {
         prop = GUSB_EP_CAP_ALL;
       }
       switch (dir) {
       case 0:
         prop = GUSB_EP_DIR_OUT(prop);
         break;
       case 1:
         prop = GUSB_EP_DIR_IN(prop);
         break;
       case 2:
         prop = GUSB_EP_BIDIR(prop);
         break;
       }
       props->ep[number] |= prop;
       if ((props->ep[number] & GUSB_EP_DIR_OUT(GUSB_EP_CAP_ALL))
           && (props->ep[number] & GUSB_EP_DIR_IN(GUSB_EP_CAP_ALL))) {
         props->ep[number] |= GUSB_EP_BIDIR(0);
       }
     }
   }

   return 0;
}

int gadget_open(const char * path) {

  int ret = -1;

  return ret;
}
