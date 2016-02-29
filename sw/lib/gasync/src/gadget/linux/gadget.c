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
  s_ep_props props;
} devices[GADGET_MAX_DEVICES] = { };

#define PRINT_ERROR(msg) print_error(__FILE__, __LINE__, msg);
void print_error(const char * file, int line, const char * msg) {

  fprintf(stderr, "%s:%d %s failed with error: %m\n", file, line, msg);
}
#define PRINT_ERROR_OTHER(msg) \
  fprintf(stderr, "%s:%d %s\n", __FILE__, __LINE__, msg);

#define PRINT_ERROR_ALLOC_FAILED(func) fprintf(stderr, "%s:%d %s: %s failed\n", __FILE__, __LINE__, __func__, func);

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

static int add_device(const char * path, int fd, const s_ep_props * props) {
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
        devices[i].props = *props;
        return i;
      } else {
        fprintf(stderr, "%s:%d add_device %s: can't duplicate path\n", __FILE__, __LINE__, path);
        return -1;
      }
    }
  }
  return -1;
}

const s_ep_props * gadget_get_properties(int device) {

    GADGET_CHECK_DEVICE(device, NULL)

    return &devices[device].props;
}

static int prope_endpoints(const char * path, s_ep_props * props) {

    struct dirent * d;

    const char * ptr = strrchr(path, '/');
    if (ptr == NULL) {
        return -1;
    }

    char * dir = strndup(path, ptr - path);
    if (dir == NULL) {
        PRINT_ERROR_ALLOC_FAILED("strndup")
        return -1;
    }

    DIR * dirp = opendir(dir);
    if (dirp == NULL) {
        PRINT_ERROR("opendir")
        free(dir);
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
            unsigned short prop;
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
                prop = GUSB_EP_DIR_BIDIR(prop);
                break;
            }
            props->ep[number] |= prop;
            if ((props->ep[number] & GUSB_EP_DIR_OUT(GUSB_EP_CAP_ALL)) && (props->ep[number] & GUSB_EP_DIR_IN(GUSB_EP_CAP_ALL))) {
                props->ep[number] |= GUSB_EP_DIR_BIDIR(0);
            }
        }
    }

    free(dir);
    closedir(dirp);

    return 0;
}

static int probe(int fd, const char * path, s_ep_props * props) {

    union {
        unsigned char buf[0];
        struct PACKED {
            uint32_t tag;
            struct usb_config_descriptor config;
            struct usb_device_descriptor device;
        } value;
    } config = {
            .value = {
                .tag = 0,
                .config = {
                        .bLength = sizeof(struct usb_config_descriptor),
                        .bDescriptorType = USB_DT_CONFIG,
                        .wTotalLength = sizeof(struct usb_config_descriptor),
                        .bNumInterfaces = 0,
                        .bConfigurationValue = 1,
                        .iConfiguration = 0,
                        .bmAttributes = USB_CONFIG_ATT_ONE,
                        .bMaxPower = 0xff // max value
                },
                .device = {
                        .bLength = sizeof(struct usb_device_descriptor),
                        .bDescriptorType = USB_DT_DEVICE,
                        .bcdUSB = 0x0200,
                        .bDeviceClass = 0x00,
                        .bDeviceSubClass = 0x00,
                        .bDeviceProtocol = 0x00,
                        .bMaxPacketSize0 = 8,
                        .idVendor = 0x0001, // fake vendor
                        .idProduct = 0x0001, // fake product
                        .bcdDevice = 0x0000,
                        .iManufacturer = 0,
                        .iProduct = 0,
                        .iSerialNumber = 0,
                        .bNumConfigurations = 1
                }
            }
    };

    int ret = write(fd, config.buf, sizeof(config.value));
    if (ret < 0) {
        PRINT_ERROR("write")
        return -1;
    }

    return prope_endpoints(path, props);
}

int gadget_open(const char * path) {

    if (path == NULL) {
        PRINT_ERROR_OTHER("path is NULL")
        return -1;
    }

    int fd = open(path, O_RDWR);
    if (fd == -1) {
        PRINT_ERROR("open")
        return -1;
    }

    s_ep_props props = { {} };

    int ret = probe(fd, path, &props);

    close(fd);

    if (ret < 0) {
        return -1;
    }

    fd = open(path, O_RDWR);
    if (fd == -1) {

        PRINT_ERROR("open")
        return -1;
    }

    return add_device(path, fd, &props);
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

  if (descriptors->device.bNumConfigurations > 1) {
    PRINT_ERROR_OTHER("Gadgetfs does not support multi-configurations")
    return -1;
  }

  if (descriptors->device.bNumConfigurations == 0) {
    PRINT_ERROR_OTHER("Gadgetfs requires exactly one configuration")
    return -1;
  }

  if (descriptors->configurations[0].descriptor->bmAttributes & USB_CONFIG_ATT_WAKEUP) {
    PRINT_ERROR_OTHER("Gadgetfs does not support remote wakeup")
    return -1;
  }

  unsigned char buf[4096] = { 0, 0, 0, 0 };
  unsigned char * ptr = buf + 4;

  size_t size;

  size = descriptors->configurations[0].descriptor->wTotalLength;
  memcpy(ptr, descriptors->configurations[0].raw, size);
  ptr += size;

  size = descriptors->device.bLength;
  memcpy(ptr, &descriptors->device, size);
  ptr += size;

  int ret = write(devices[device].fd, buf, ptr - buf);
  if (ret < 0) {
    PRINT_ERROR("write")
  }

  // TODO MLA: high speed config

  return ret;
}
