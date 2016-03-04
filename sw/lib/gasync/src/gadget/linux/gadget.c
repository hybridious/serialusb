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
#include <linux/usb/gadgetfs.h>
#include <errno.h>
#include <sys/ioctl.h>

#define GADGET_MAX_DEVICES 8

#define GADGET_MAX_ENDPOINTS USB_ENDPOINT_NUMBER_MASK

#define GADGET_GET_ENDPOINT(DEVICE, ENDPOINT) \
    devices[DEVICE].endpoints[(ENDPOINT) >> 7][((ENDPOINT) & USB_ENDPOINT_NUMBER_MASK) - 1]

typedef struct {
  struct usb_endpoint_descriptor descriptor;
  int fd;
} s_endpoint;

static struct {
  int fd;
  char * path;
  s_ep_props props;
  GPOLL_REGISTER_FD fp_register;
  struct {
    int user;
    USBASYNC_READ_CALLBACK fp_read;
    USBASYNC_WRITE_CALLBACK fp_write;
    USBASYNC_CLOSE_CALLBACK fp_close;
  } callback;
  s_endpoint endpoints[2][GADGET_MAX_ENDPOINTS];
  struct usb_ctrlrequest last_setup;
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

    s_ep_props props = { { } };

    int ret = probe(fd, path, &props);

    close(fd);

    if (ret < 0) {
        return -1;
    }

    fd = open(path, O_RDWR | O_NONBLOCK);
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

static int store_endpoints(int device, struct p_configuration * configuration, uint16_t inEndpoints, uint16_t outEndpoints) {

  unsigned char interfaceIndex;
  for (interfaceIndex = 0; interfaceIndex < configuration->descriptor->bNumInterfaces; ++interfaceIndex) {
    struct p_interface * pInterface = configuration->interfaces + interfaceIndex;
    unsigned char altInterfaceIndex;
    for (altInterfaceIndex = 0; altInterfaceIndex < pInterface->bNumAltInterfaces; ++altInterfaceIndex) {
      struct p_altInterface * pAltInterface = pInterface->altInterfaces + altInterfaceIndex;
      unsigned char endpointIndex;
      for (endpointIndex = 0; endpointIndex < pAltInterface->bNumEndpoints; ++endpointIndex) {
        struct usb_endpoint_descriptor * endpoint =
            configuration->interfaces[interfaceIndex].altInterfaces[altInterfaceIndex].endpoints[endpointIndex];
        if (((endpoint->bEndpointAddress & USB_DIR_IN) ? inEndpoints : outEndpoints)
            & (1 << ((endpoint->bEndpointAddress & USB_ENDPOINT_NUMBER_MASK) - 1)) == 0) {
          continue;
        }
        GADGET_GET_ENDPOINT(device, endpoint->bEndpointAddress).descriptor = *endpoint;
      }
    }
  }

  return 0;
}

static const char * get_endpoint_path(int device, unsigned short endpointProps) {


  return NULL;
}

static int configure_endpoints(int device) {

  unsigned char endpointIndex;
  for (endpointIndex = 0; endpointIndex < GADGET_MAX_ENDPOINTS; ++endpointIndex) {
    s_endpoint * in = GADGET_GET_ENDPOINT(device, USB_DIR_IN | (endpointIndex + 1));
    s_endpoint * out = GADGET_GET_ENDPOINT(device, USB_DIR_OUT | (endpointIndex + 1));
    unsigned short endpointProps = devices[device].props.ep[endpointIndex];
    const char * path = get_endpoint_path(device, endpointProps);

  }

  return 0;
}

int gadget_configure(int device, s_usb_descriptors * descriptors, uint16_t inEndpoints, uint16_t outEndpoints) {

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

  struct p_configuration * full_speed = NULL;
  struct p_configuration * high_speed = NULL;

  switch (descriptors->speed) {
  case GUSB_SPEED_FULL:
    full_speed = descriptors->configurations;
    high_speed = descriptors->other_speed.configurations;
    if (high_speed == NULL) {
      high_speed = full_speed;
    }
    break;
  case GUSB_SPEED_HIGH:
    high_speed = descriptors->configurations;
    full_speed = descriptors->other_speed.configurations;
    if (full_speed == NULL) {
      full_speed = high_speed;
    }
    break;
  default:
    PRINT_ERROR_OTHER("unsupported USB speed")
    return -1;
  }

  size_t size = 4 + full_speed[0].descriptor->wTotalLength + high_speed[0].descriptor->wTotalLength
      + descriptors->device.bLength;
  union {
    uint32_t tag;
    unsigned char buf[size];
  } config;

  config.tag = 0;
  unsigned char * ptr = config.buf + sizeof(config.tag);

  size = full_speed[0].descriptor->wTotalLength;
  memcpy(ptr, full_speed[0].raw, size);
  ptr += size;

  size = high_speed[0].descriptor->wTotalLength;
  memcpy(ptr, high_speed[0].raw, size);
  ptr += size;

  size = descriptors->device.bLength;
  memcpy(ptr, &descriptors->device, size);
  ptr += size;

  int ret = write(devices[device].fd, config.buf, ptr - config.buf);
  if (ret < 0) {
    PRINT_ERROR("write")
    return -1;
  }

  ret = store_endpoints(device, descriptors->configurations, inEndpoints, outEndpoints);
  if (ret < 0) {
    return -1;
  }

  return 0;
}

static int close_callback(int device) {

  GADGET_CHECK_DEVICE(device, -1)

  return devices[device].callback.fp_close(devices[device].callback.user);
}

static int control_callback(int device) {

  GADGET_CHECK_DEVICE(device, -1)

  struct usb_gadgetfs_event event;

  int ret = read(devices[device].fd, &event, sizeof(event));
  if (ret != sizeof(event)) {
    if (ret == -1) {
      PRINT_ERROR("read")
    } else {
      PRINT_ERROR_OTHER("failed to read a gadget event")
    }
    return devices[device].callback.fp_close(devices[device].callback.user);
  }

  switch (event.type) {
  case GADGETFS_NOP:
    break;
  case GADGETFS_CONNECT:
    PRINT_ERROR_OTHER("CONNECT")
    break;
  case GADGETFS_SETUP:
  {
    unsigned char buf[sizeof(event.u.setup) + event.u.setup.wLength];
    memcpy(buf, &event.u.setup, sizeof(event.u.setup));
    unsigned int count = sizeof(event.u.setup);
    if ((event.u.setup.bRequestType & USB_ENDPOINT_DIR_MASK) == USB_DIR_OUT) {
      if (event.u.setup.wLength > 0) {
        ret = read(devices[device].fd, buf + sizeof(event.u.setup), event.u.setup.wLength);
        if (ret == -1) {
          PRINT_ERROR("read")
          return -1;
        }
        count += ret;
      }
    }

    devices[device].last_setup = event.u.setup;

    // When a control transfer is pending the fd is signaled as readable and read() fails with EAGAIN.
    // Therefore remove the fd until the control transfer completes.

    gpoll_remove_fd(devices[device].fd); //TODO MLA

    ret = devices[device].callback.fp_read(devices[device].callback.user, 0, buf, count);
    if (ret == -1) {
      ret = devices[device].fp_register(devices[device].fd, device, control_callback, control_callback, close_callback);
      if (ret < 0) {
        return -1;
      }
      ret = gadget_stall_control(device, event.u.setup.bRequestType & USB_DIR_IN);
      if (ret < 0) {
        return -1;
      }
    }
    break;
  }
  case GADGETFS_DISCONNECT:
    PRINT_ERROR_OTHER("DISCONNECT")
    break;
  case GADGETFS_SUSPEND:
    PRINT_ERROR_OTHER("SUSPEND")
    break;
  default:
    PRINT_ERROR_OTHER("bad event type")
    return -1;
  }

  return 0;
}

int gadget_write(int device, unsigned char endpoint, const void * buf, unsigned int count) {

  GADGET_CHECK_DEVICE(device, -1)

  if (endpoint == 0) {
    int ret = devices[device].fp_register(devices[device].fd, device, control_callback, control_callback, close_callback);
    if (ret < 0) {
      return -1;
    }
  }

  int ret = write(devices[device].fd, buf, count);
  if (ret < 0) {
    PRINT_ERROR("write")
    return -1;
  }
  return 0;
}

int gadget_stall_control(int device, unsigned char direction) {

  GADGET_CHECK_DEVICE(device, -1)

  int ret = devices[device].fp_register(devices[device].fd, device, control_callback, control_callback, close_callback);
  if (ret < 0) {
    return -1;
  }

  PRINT_ERROR_OTHER("gadget_stall_control")

  int status;
  if (direction == USB_DIR_IN) {
    ret = read (devices[device].fd, &status, 0);
    if (ret != -1) {
      PRINT_ERROR_OTHER("can't stall endpoint 0")
      return -1;
    }
    if (errno != EL2HLT) {
      PRINT_ERROR("read")
      return -1;
    }
  } else {
    ret = write (devices[device].fd, &status, 0);
    if (ret != -1) {
      PRINT_ERROR_OTHER("can't stall endpoint 0")
      return -1;
    }
    if (errno != EL2HLT) {
      PRINT_ERROR("write")
      return -1;
    }
  }

  return 0;
}

int gadget_ack_control(int device, unsigned char direction) {

  GADGET_CHECK_DEVICE(device, -1)

  int ret = devices[device].fp_register(devices[device].fd, device, control_callback, control_callback, close_callback);
  if (ret < 0) {
    return -1;
  }

  if ((devices[device].last_setup.bRequestType & USB_ENDPOINT_DIR_MASK) == USB_DIR_OUT
          && devices[device].last_setup.bRequest == USB_REQ_SET_CONFIGURATION) {
    ret = configure_endpoints(device);
    if (ret < 0) {
      return -1;
    }
  }

  PRINT_ERROR_OTHER("ack")

  int status;
  if (direction == USB_DIR_OUT) {
    ret = read (devices[device].fd, &status, 0);
    if (ret == -1) {
      PRINT_ERROR("read")
      return -1;
    }
  } else {
    ret = write (devices[device].fd, &status, 0);
    if (ret == -1) {
      PRINT_ERROR("write")
      return -1;
    }
  }

  return 0;
}

int gadget_register(int device, int user, USBASYNC_READ_CALLBACK fp_read, USBASYNC_WRITE_CALLBACK fp_write,
      USBASYNC_CLOSE_CALLBACK fp_close, GPOLL_REGISTER_FD fp_register) {

  GADGET_CHECK_DEVICE(device, -1)

  int ret = fp_register(devices[device].fd, device, control_callback, control_callback, close_callback);
  if (ret < 0) {
    return -1;
  }

  devices[device].fp_register = fp_register;
  devices[device].callback.user = user;
  devices[device].callback.fp_read = fp_read;
  devices[device].callback.fp_write = fp_write;
  devices[device].callback.fp_close = fp_close;

  return 0;
}
