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
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#define GADGET_MAX_DEVICES 8

static struct {
  int fd;
  char * path;
} devices[GADGET_MAX_DEVICES] = { };

#define GADGET_PRINT_ERROR(msg) gadget_print_error(__FILE__, __LINE__, msg);
void gadget_print_error(const char * file, int line, const char * msg) {

  fprintf(stderr, "%s:%d %s failed with error: %m\n", file, line, msg);
}

static inline int gadget_check_device(int device, const char * file, unsigned int line, const char * func) {
  if (device < 0 || device >= GADGET_MAX_DEVICES) {
    fprintf(stderr, "%s:%d %s: invalid device (%d)\n", file, line, func, device);
    return -1;
  }
  if (devices[device].fd == -1) {
    fprintf(stderr, "%s:%d %s: no such device (%d)\n", file, line, func, device);
    return -1;
  }
  return 0;
}
#define GADGET_CHECK_DEVICE(device,retValue) \
  if(gadget_check_device(device, __FILE__, __LINE__, __func__) < 0) { \
    return retValue; \
  }

void gadget_init(void) __attribute__((constructor (101)));
void gadget_init(void) {
  int i;
  for (i = 0; i < GADGET_MAX_DEVICES; ++i) {
    devices[i].fd = -1;
  }
}

void gadget_clean(void) __attribute__((destructor (101)));
void gadget_clean(void) {
  int i;
  for (i = 0; i < GADGET_MAX_DEVICES; ++i) {
    if (devices[i].fd >= 0) {
      gadget_close(i);
    }
  }
}

static int add_device(const char * path, int fd) {
  int i;
  for (i = 0; i < GADGET_MAX_DEVICES; ++i) {
    if (devices[i].path && !strcmp(devices[i].path, path)) {
      fprintf(stderr, "%s:%d add_device %s: device already opened\n", __FILE__, __LINE__, path);
      return -1;
    }
  }
  for (i = 0; i < GADGET_MAX_DEVICES; ++i) {
    if (devices[i].fd == -1) {
      devices[i].path = strdup(path);
      if (devices[i].path != NULL) {
        devices[i].fd = fd;
        return i;
      } else {
        fprintf(stderr, "%s:%d add_device %s: can't duplicate path\n", __FILE__, __LINE__, path);
        return -1;
      }
    }
  }
  return -1;
}

int gadget_get_properties(const char * path, s_ep_props * props) {

  struct dirent * d;

  DIR * dirp = opendir(path);
  if (dirp == NULL) {
    GADGET_PRINT_ERROR("opendir")
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
  if (path != NULL) {
    int fd = open(path, O_RDWR);
    if (fd != -1) {
      ret = add_device(path, fd);
      if (ret == -1) {
        close(fd);
      }
    } else {
      GADGET_PRINT_ERROR("open")
    }
  }
  return ret;
}

int gadget_close(int device) {

  GADGET_CHECK_DEVICE(device, -1)

  close(devices[device].fd);

  free(devices[device].path);

  memset(devices + device, 0x00, sizeof(*devices));

  devices[device].fd = -1;

  return 0;
}

int gadget_configure(int device, s_usb_descriptors * descriptors) {

  GADGET_CHECK_DEVICE(device, -1)

  int ret = -1;

  unsigned char buf[4096] = { 0, 0, 0, 0 };
  unsigned char * ptr = buf + 4;

  size_t size;

  unsigned int descNumber;
  for(descNumber = 0; descNumber < descriptors->device.bNumConfigurations; ++descNumber) {

    // Gadget configuration fails if remote wakeup is set.
    descriptors->configurations[descNumber].descriptor->bmAttributes &= ~USB_CONFIG_ATT_WAKEUP;

    size = descriptors->configurations[descNumber].descriptor->wTotalLength;
    memcpy(ptr, descriptors->configurations[descNumber].raw, size);
    ptr += size;
  }

  size = descriptors->device.bLength;
  memcpy(ptr, &descriptors->device, size);
  ptr += size;

  ret = write(devices[device].fd, buf, ptr - buf);
  if (ret < 0) {
    GADGET_PRINT_ERROR("write")
  }

  // TODO MLA: high speed config

  return ret;
}
