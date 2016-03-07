/*
 Copyright (c) 2015 Mathieu Laurendeau <mat.lau@laposte.net>
 License: GPLv3
 */

#include <gusb.h>
#include <gadget.h>
#include <gserial.h>
#include <protocol.h>
#include <adapter.h>
#include <allocator.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gpoll.h>
#include <gtimer.h>
#include <names.h>
#include <prio.h>
#include <sys/time.h>
#include <unistd.h>

#define ENDPOINT_MAX_NUMBER USB_ENDPOINT_NUMBER_MASK

#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"

#define PRINT_ERROR_OTHER(MESSAGE) fprintf(stderr, "%s:%d %s: %s\n", __FILE__, __LINE__, __func__, MESSAGE);
#define PRINT_TRANSFER_WRITE_ERROR(ENDPOINT,MESSAGE) fprintf(stderr, "%s:%d %s: write transfer failed on endpoint %hhu with error: %s\n", __FILE__, __LINE__, __func__, ENDPOINT & USB_ENDPOINT_NUMBER_MASK, MESSAGE);
#define PRINT_TRANSFER_READ_ERROR(ENDPOINT,MESSAGE) fprintf(stderr, "%s:%d %s: read transfer failed on endpoint %hhu with error: %s\n", __FILE__, __LINE__, __func__, ENDPOINT & USB_ENDPOINT_NUMBER_MASK, MESSAGE);

static int usb = -1;
static int adapter = -1;
static int gadget = -1;
static int init_timer = -1;

static s_usb_descriptors * descriptors = NULL;
static uint8_t savedNumConfigurations = 0;
static unsigned char desc[MAX_DESCRIPTORS_SIZE] = {};
static unsigned char * pDesc = desc;
static s_descriptorIndex descIndex[MAX_DESCRIPTORS] = {};
static s_descriptorIndex * pDescIndex = descIndex;
static s_endpointConfig endpoints[MAX_ENDPOINTS] = {};
static s_endpointConfig * pEndpoints = endpoints;

static uint8_t descIndexSent = 0;
static uint8_t endpointsSent = 0;

static uint8_t inPending = 0;

static s_endpoint_map endpointMap = { {}, {}, {} };

static struct {
  uint16_t length;
  s_endpointPacket packet;
} inPackets[ENDPOINT_MAX_NUMBER] = {};

static uint8_t inEpFifo[MAX_ENDPOINTS] = {};
static uint8_t nbInEpFifo = 0;

static enum {
  E_GADGET_INIT,
  E_GADGET_CONFIGURING,
  E_GADGET_CONFIGURED
} gadget_state = E_GADGET_INIT;;

static volatile int done;

/*
 * the atmega32u4 supports up to 6 non-control endpoints
 * that can be IN or OUT (not BIDIR),
 * and only the INTERRUPT type is supported.
 */
static s_ep_props avr8Target = {
  {
    GUSB_EP_DIR_IN(GUSB_EP_CAP_INT) | GUSB_EP_DIR_OUT(GUSB_EP_CAP_INT),
    GUSB_EP_DIR_IN(GUSB_EP_CAP_INT) | GUSB_EP_DIR_OUT(GUSB_EP_CAP_INT),
    GUSB_EP_DIR_IN(GUSB_EP_CAP_INT) | GUSB_EP_DIR_OUT(GUSB_EP_CAP_INT),
    GUSB_EP_DIR_IN(GUSB_EP_CAP_INT) | GUSB_EP_DIR_OUT(GUSB_EP_CAP_INT),
    GUSB_EP_DIR_IN(GUSB_EP_CAP_INT) | GUSB_EP_DIR_OUT(GUSB_EP_CAP_INT),
    GUSB_EP_DIR_IN(GUSB_EP_CAP_INT) | GUSB_EP_DIR_OUT(GUSB_EP_CAP_INT),
  }
};

static int send_next_in_packet() {

  if (inPending) {
    return 0;
  }

  if (nbInEpFifo > 0) {
    uint8_t inPacketIndex = ALLOCATOR_ENDPOINT_ADDR_TO_INDEX(inEpFifo[0]);
    int ret = adapter_send(adapter, E_TYPE_IN, (const void *)&inPackets[inPacketIndex].packet, inPackets[inPacketIndex].length);
    if(ret < 0) {
      return -1;
    }
    inPending = inEpFifo[0];
    --nbInEpFifo;
    memmove(inEpFifo, inEpFifo + 1, nbInEpFifo * sizeof(*inEpFifo));
  }

  return 0;
}

static int queue_in_packet(unsigned char endpoint, const void * buf, int transfered) {

  if (nbInEpFifo == sizeof(inEpFifo) / sizeof(*inEpFifo)) {
    PRINT_ERROR_OTHER("no more space in inEpFifo")
    return -1;
  }

  uint8_t inPacketIndex = ALLOCATOR_ENDPOINT_ADDR_TO_INDEX(endpoint);
  inPackets[inPacketIndex].packet.endpoint = ALLOCATOR_S2T_ENDPOINT(&endpointMap, endpoint);
  memcpy(inPackets[inPacketIndex].packet.data, buf, transfered);
  inPackets[inPacketIndex].length = transfered + 1;
  inEpFifo[nbInEpFifo] = endpoint;
  ++nbInEpFifo;

  /*
   * TODO MLA: Poll the endpoint after registering the packet?
   */

  return 0;
}

int usb_read_callback(int user, unsigned char endpoint, const void * buf, int status) {

  switch (status) {
  case E_TRANSFER_TIMED_OUT:
    PRINT_TRANSFER_READ_ERROR(endpoint, "TIMEOUT")
    break;
  case E_TRANSFER_STALL:
    break;
  case E_TRANSFER_ERROR:
    PRINT_TRANSFER_WRITE_ERROR(endpoint, "OTHER ERROR")
    return -1;
  default:
    break;
  }

  if (endpoint == 0) {

    if (status > (int)MAX_PACKET_VALUE_SIZE) {
      PRINT_ERROR_OTHER("too many bytes transfered")
      done = 1;
      return -1;
    }

    int ret = 0;
    if (status >= 0) {
      if (adapter >= 0) {
        ret = adapter_send(adapter, E_TYPE_CONTROL, buf, status);
      } else if (usb >= 0) {
        ret = gadget_write(gadget, 0, buf, status);
      }
    } else {
      if (adapter >= 0) {
        ret = adapter_send(adapter, E_TYPE_CONTROL_STALL, NULL, 0);
      } else if (usb >= 0) {
        ret = gadget_stall_control(gadget, USB_DIR_IN);
      }
    }
    if(ret < 0) {
      return -1;
    }
  } else {

    if (status > MAX_PAYLOAD_SIZE_EP) {
      PRINT_ERROR_OTHER("too many bytes transfered")
      done = 1;
      return -1;
    }

    if (status >= 0) {

      if (adapter >= 0) {
        int ret = queue_in_packet(endpoint, buf, status);
        if (ret < 0) {
          done = 1;
          return -1;
        }

        ret = send_next_in_packet();
        if (ret < 0) {
          done = 1;
          return -1;
        }
      } else if (gadget >= 0) {
        int ret = gadget_write(gadget, ALLOCATOR_S2T_ENDPOINT(&endpointMap, endpoint), buf, status);
        if (ret < 0) {
          done = 1;
          return -1;
        }
        ret = gusb_poll(usb, endpoint);
        if (ret < 0) {
          done = 1;
          return -1;
        }
      }
    }
  }

  return 0;
}

static int poll_all_endpoints() {

  int ret = 0;
  unsigned char i;
  for (i = 0; i < sizeof(*endpointMap.targetToSource) / sizeof(**endpointMap.targetToSource) && ret >= 0; ++i) {
    uint8_t endpoint = ALLOCATOR_T2S_ENDPOINT(&endpointMap, USB_DIR_IN | (i + 1));
    if (endpoint) {
      ret = gusb_poll(usb, endpoint);
    }
  }
  return ret;
}

int usb_write_callback(int user, unsigned char endpoint, int status) {

  switch (status) {
  case E_TRANSFER_TIMED_OUT:
    PRINT_TRANSFER_WRITE_ERROR(endpoint, "TIMEOUT")
    break;
  case E_TRANSFER_STALL:
    if (endpoint == 0) {
      if (adapter >= 0) {
        int ret = adapter_send(adapter, E_TYPE_CONTROL_STALL, NULL, 0);
        if (ret < 0) {
          done = 1;
          return -1;
        }
      } else if (usb >= 0) {
        int ret = gadget_stall_control(usb, USB_DIR_OUT);
        if (ret < 0) {
          done = 1;
          return -1;
        }
      }
    }
    break;
  case E_TRANSFER_ERROR:
    PRINT_TRANSFER_WRITE_ERROR(endpoint, "OTHER ERROR")
    return -1;
  default:
    if (endpoint == 0) {
      if (adapter >= 0) {
        int ret = adapter_send(adapter, E_TYPE_CONTROL, NULL, 0);
        if (ret < 0) {
          done = 1;
          return -1;
        }
      } else if (usb >= 0) {
        int ret = gadget_ack_control(usb, USB_DIR_OUT);
        if (ret < 0) {
          done = 1;
          return -1;
        }
        if (gadget_state == E_GADGET_CONFIGURING) {
          poll_all_endpoints();
          gadget_state = E_GADGET_CONFIGURED;
        }
      }
    }
    break;
  }

  return 0;
}

int usb_close_callback(int user) {

  done = 1;
  return 1;
}

int adapter_send_callback(int user, int transfered) {

  if (transfered < 0) {
    done = 1;
    return 1;
  }

  return 0;
}

int adapter_close_callback(int user) {

  done = 1;
  return 1;
}

static char * usb_select() {

  char * path = NULL;

  s_usb_dev * usb_devs = gusb_enumerate(0x0000, 0x0000);
  if (usb_devs == NULL) {
    fprintf(stderr, "No USB device detected!\n");
    return NULL;
  }
  printf("Available USB devices:\n");
  unsigned int index = 0;
  char vendor[128], product[128];
  s_usb_dev * current;
  for (current = usb_devs; current != NULL; ++current) {
    get_vendor_string(vendor, sizeof(vendor), current->vendor_id);
    get_product_string(product, sizeof(product), current->vendor_id, current->product_id);
    printf("%2d", index++);
    printf(" VID 0x%04x (%s)", current->vendor_id, strlen(vendor) ? vendor : "unknown vendor");
    printf(" PID 0x%04x (%s)", current->product_id, strlen(product) ? product : "unknown product");
    printf(" PATH %s\n", current->path);
    if (current->next == 0) {
      break;
    }
  }

  printf("Select the USB device number: ");
  unsigned int choice = UINT_MAX;
  if (scanf("%d", &choice) == 1 && choice < index) {
    path = strdup(usb_devs[choice].path);
    if(path == NULL) {
      fprintf(stderr, "can't duplicate path.\n");
    }
  } else {
    fprintf(stderr, "Invalid choice.\n");
  }

  gusb_free_enumeration(usb_devs);

  return path;
}

static void get_endpoint_properties(unsigned char configurationIndex, s_ep_props * props) {

  struct p_configuration * pConfiguration = descriptors->configurations + configurationIndex;
  unsigned char interfaceIndex;
  for (interfaceIndex = 0; interfaceIndex < pConfiguration->descriptor->bNumInterfaces; ++interfaceIndex) {
    struct p_interface * pInterface = pConfiguration->interfaces + interfaceIndex;
    unsigned char altInterfaceIndex;
    for (altInterfaceIndex = 0; altInterfaceIndex < pInterface->bNumAltInterfaces; ++altInterfaceIndex) {
      struct p_altInterface * pAltInterface = pInterface->altInterfaces + altInterfaceIndex;
      unsigned char endpointIndex;
      for (endpointIndex = 0; endpointIndex < pAltInterface->bNumEndpoints; ++endpointIndex) {
        struct usb_endpoint_descriptor * endpoint =
                pConfiguration->interfaces[interfaceIndex].altInterfaces[altInterfaceIndex].endpoints[endpointIndex];
        uint8_t epIndex = ALLOCATOR_ENDPOINT_ADDR_TO_INDEX(endpoint->bEndpointAddress);
        uint8_t prop = 0;
        switch (endpoint->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK) {
        case USB_ENDPOINT_XFER_INT:
          prop = GUSB_EP_CAP_INT;
          break;
        case USB_ENDPOINT_XFER_BULK:
          prop = GUSB_EP_CAP_BLK;
          break;
        case USB_ENDPOINT_XFER_ISOC:
          prop = GUSB_EP_CAP_ISO;
          break;
        }
        if ((endpoint->bEndpointAddress & USB_ENDPOINT_DIR_MASK) == USB_DIR_IN) {
          props->ep[epIndex] |= GUSB_EP_DIR_IN(prop);
        } else {
          props->ep[epIndex] |= GUSB_EP_DIR_OUT(prop);
        }
        if ((props->ep[epIndex] & GUSB_EP_DIR_IN(GUSB_EP_CAP_ALL)) && (props->ep[epIndex] & GUSB_EP_DIR_OUT(GUSB_EP_CAP_ALL))) {
          props->ep[epIndex] |= GUSB_EP_DIR_BIDIR(GUSB_EP_CAP_NONE);
        }
      }
    }
  }
}

static void fix_device() {

  if (descriptors->configurations[0].descriptor->bmAttributes & USB_CONFIG_ATT_WAKEUP) {
    printf("Disabled unsupported remote wakeup.\n");
    descriptors->configurations[0].descriptor->bmAttributes &= ~USB_CONFIG_ATT_WAKEUP;
  }

  savedNumConfigurations = descriptors->device.bNumConfigurations;
  if (descriptors->device.bNumConfigurations > 1) {
    printf("Multiple configurations are not supported. Only the first one will be kept.\n");
    descriptors->device.bNumConfigurations = 1;
  }
}

static int fix_configuration(unsigned char configurationIndex) {

  pEndpoints = endpoints;

  if (configurationIndex >= descriptors->device.bNumConfigurations) {
    PRINT_ERROR_OTHER("invalid configuration index")
    return -1;
  }

  struct p_configuration * pConfiguration = descriptors->configurations + configurationIndex;
  printf("configuration: %hhu\n", pConfiguration->descriptor->bConfigurationValue);
  unsigned char interfaceIndex;
  for (interfaceIndex = 0; interfaceIndex < pConfiguration->descriptor->bNumInterfaces; ++interfaceIndex) {
    struct p_interface * pInterface = pConfiguration->interfaces + interfaceIndex;
    unsigned char altInterfaceIndex;
    for (altInterfaceIndex = 0; altInterfaceIndex < pInterface->bNumAltInterfaces; ++altInterfaceIndex) {
      struct p_altInterface * pAltInterface = pInterface->altInterfaces + altInterfaceIndex;
      printf("  interface: %hhu:%hhu\n", pAltInterface->descriptor->bInterfaceNumber, pAltInterface->descriptor->bAlternateSetting);
      unsigned char bNumEndpoints = pAltInterface->bNumEndpoints;
      unsigned char endpointIndex;
      for (endpointIndex = 0; endpointIndex < pAltInterface->bNumEndpoints; ++endpointIndex) {
        struct usb_endpoint_descriptor * endpoint =
            descriptors->configurations[configurationIndex].interfaces[interfaceIndex].altInterfaces[altInterfaceIndex].endpoints[endpointIndex];
        uint8_t sourceEndpoint = endpoint->bEndpointAddress;
        unsigned char targetEndpoint = ALLOCATOR_S2T_ENDPOINT(&endpointMap, sourceEndpoint);
        endpoint->bEndpointAddress = targetEndpoint;
        printf("    endpoint:");
        printf(" %s", ((sourceEndpoint & USB_ENDPOINT_DIR_MASK) == USB_DIR_IN) ? "IN" : "OUT");
        printf(" %s",
            (endpoint->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK) == USB_ENDPOINT_XFER_INT ? "INTERRUPT" :
            (endpoint->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK) == USB_ENDPOINT_XFER_BULK ? "BULK" :
            (endpoint->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK) == USB_ENDPOINT_XFER_ISOC ? "ISOCHRONOUS" : "UNKNOWN");
        printf(" %hu", sourceEndpoint & USB_ENDPOINT_NUMBER_MASK);
        if (sourceEndpoint != targetEndpoint) {
          if (targetEndpoint == 0x00) {
            targetEndpoint = ALLOCATOR_S2T_STUB_ENDPOINT(&endpointMap, sourceEndpoint);
            if (targetEndpoint == 0x00) {
              printf(KRED" -> no stub available"KNRM"\n");
              endpoint->bDescriptorType = 0x00;
              --bNumEndpoints;
            } else {
              printf(KRED" -> %hu (stub)"KNRM, targetEndpoint & USB_ENDPOINT_NUMBER_MASK);
            }
            continue;
          } else {
              printf(KRED" -> %hu"KNRM, targetEndpoint & USB_ENDPOINT_NUMBER_MASK);
          }
        } else {
          printf(" -> %hu", targetEndpoint & USB_ENDPOINT_NUMBER_MASK);
        }
        printf("\n");
        pEndpoints->number = endpoint->bEndpointAddress;
        pEndpoints->type = endpoint->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK;
        pEndpoints->size = endpoint->wMaxPacketSize;
        ++pEndpoints;
      }
      if (bNumEndpoints != pAltInterface->bNumEndpoints) {
          printf(KRED"    bNumEndpoints: %hhu -> %hhu"KNRM"\n", pAltInterface->bNumEndpoints, bNumEndpoints);
          pAltInterface->bNumEndpoints = bNumEndpoints;
      }
    }
  }

  return 0;
}

static int add_descriptor(uint16_t wValue, uint16_t wIndex, uint16_t wLength, void * data) {

  if (pDesc + wLength > desc + MAX_DESCRIPTORS_SIZE || pDescIndex >= descIndex + MAX_DESCRIPTORS) {
    fprintf(stderr, "%s:%d %s: unable to add descriptor wValue=0x%04x wIndex=0x%04x wLength=%u (available=%u)\n",
        __FILE__, __LINE__, __func__, wValue, wIndex, wLength, (unsigned int)(MAX_DESCRIPTORS_SIZE - (pDesc - desc)));
    return -1;
  }

  pDescIndex->offset = pDesc - desc;
  pDescIndex->wValue = wValue;
  pDescIndex->wIndex = wIndex;
  pDescIndex->wLength = wLength;
  memcpy(pDesc, data, wLength);
  pDesc += wLength;
  ++pDescIndex;

  return 0;
}

int send_descriptors() {

  int ret;

  ret = add_descriptor((USB_DT_DEVICE << 8), 0, sizeof(descriptors->device), &descriptors->device);
  if (ret < 0) {
    return -1;
  }

  ret = add_descriptor((USB_DT_STRING << 8), 0, sizeof(descriptors->langId0), &descriptors->langId0);
  if (ret < 0) {
    return -1;
  }

  unsigned int descNumber;
  for(descNumber = 0; descNumber < descriptors->device.bNumConfigurations; ++descNumber) {

    ret = add_descriptor((USB_DT_CONFIG << 8) | descNumber, 0, descriptors->configurations[descNumber].descriptor->wTotalLength, descriptors->configurations[descNumber].raw);
    if (ret < 0) {
      return -1;
    }
  }

  for(descNumber = 0; descNumber < descriptors->nbOthers; ++descNumber) {

    ret = add_descriptor(descriptors->others[descNumber].wValue, descriptors->others[descNumber].wIndex, descriptors->others[descNumber].wLength, descriptors->others[descNumber].data);
    if (ret < 0) {
      return -1;
    }
  }

  ret = adapter_send(adapter, E_TYPE_DESCRIPTORS, desc, pDesc - desc);
  if (ret < 0) {
    return -1;
  }

  return 0;
}

static int send_index() {

  if (descIndexSent) {
    return 0;
  }

  descIndexSent = 1;

  return adapter_send(adapter, E_TYPE_INDEX, (unsigned char *)&descIndex, (pDescIndex - descIndex) * sizeof(*descIndex));
}

static int send_endpoints() {

  if (endpointsSent) {
    return 0;
  }

  endpointsSent = 1;

  return adapter_send(adapter, E_TYPE_ENDPOINTS, (unsigned char *)&endpoints, (pEndpoints - endpoints) * sizeof(*endpoints));
}

static int send_out_packet(s_packet * packet) {

  s_endpointPacket * epPacket = (s_endpointPacket *)packet->value;

  return gusb_write(usb, ALLOCATOR_T2S_ENDPOINT(&endpointMap, epPacket->endpoint), epPacket->data, packet->header.length - 1);
}

static int send_control_packet(s_packet * packet) {

  struct usb_ctrlrequest * setup = (struct usb_ctrlrequest *)packet->value;
  if ((setup->bRequestType & USB_RECIP_MASK) == USB_RECIP_ENDPOINT) {
    if (setup->wIndex != 0) {
      setup->wIndex = ALLOCATOR_T2S_ENDPOINT(&endpointMap, setup->wIndex);
      if (setup->wIndex == 0) {
        PRINT_ERROR_OTHER("control request directed to a stubbed endpoint")
        return 0;
      }
    }
  }

  return gusb_write(usb, 0, packet->value, packet->header.length);
}

static void dump(unsigned char * data, unsigned char length)
{
  int i;
  for (i = 0; i < length; ++i) {
    if(i && !(i % 8)) {
      printf("\n");
    }
    printf("0x%02x ", data[i]);
  }
  printf("\n");
}

static int process_packet(int user, s_packet * packet)
{
  unsigned char type = packet->header.type;

  int ret = 0;

  switch (packet->header.type) {
  case E_TYPE_DESCRIPTORS:
    ret = send_index();
    break;
  case E_TYPE_INDEX:
    ret = send_endpoints();
    break;
  case E_TYPE_ENDPOINTS:
    gtimer_close(init_timer);
    init_timer = -1;
    printf("Proxy started successfully. Press ctrl+c to stop it.\n");
    ret = poll_all_endpoints();
    break;
  case E_TYPE_IN:
    if (inPending > 0) {
      ret = gusb_poll(usb, inPending);
      inPending = 0;
      if (ret != -1) {
        ret = send_next_in_packet();
      }
    }
    break;
  case E_TYPE_OUT:
    ret = send_out_packet(packet);
    break;
  case E_TYPE_CONTROL:
    ret = send_control_packet(packet);
    break;
  case E_TYPE_DEBUG:
    {
      struct timeval tv;
      gettimeofday(&tv, NULL);
      printf("%ld.%06ld debug packet received (size = %d bytes)\n", tv.tv_sec, tv.tv_usec, packet->header.length);
      dump(packet->value, packet->header.length);
    }
    break;
  case E_TYPE_RESET:
    ret = -1;
    break;
  default:
    {
      struct timeval tv;
      gettimeofday(&tv, NULL);
          fprintf(stderr, "%ld.%06ld ", tv.tv_sec, tv.tv_usec);
      fprintf(stderr, "unhandled packet (type=0x%02x)\n", type);
    }
    break;
  }

  if(ret < 0) {
    done = 1;
  }

  return ret;
}

int proxy_init(char * port) {

  char * path = usb_select();

  if(path == NULL) {
    fprintf(stderr, "No USB device selected!\n");
    return -1;
  }

  usb = gusb_open_path(path);

  if (usb < 0) {
    free(path);
    return -1;
  }

  descriptors = gusb_get_usb_descriptors(usb);
  if (descriptors == NULL) {
    free(path);
    return -1;
  }

  printf("Opened device: VID 0x%04x PID 0x%04x PATH %s\n", descriptors->device.idVendor, descriptors->device.idProduct, path);

  free(path);

  if (descriptors->device.bNumConfigurations == 0) {
    PRINT_ERROR_OTHER("missing configuration")
    return -1;
  }

  if (descriptors->configurations[0].descriptor->bNumInterfaces == 0) {
    PRINT_ERROR_OTHER("missing interface")
    return -1;
  }

  if (descriptors->configurations[0].interfaces[0].bNumAltInterfaces == 0) {
    PRINT_ERROR_OTHER("missing altInterface")
    return -1;
  }

  return 0;
}

static int timer_close(int user) {
  done = 1;
  return 1;
}

static int timer_read(int user) {
  /*
   * Returning a non-zero value will make gpoll return,
   * this allows to check the 'done' variable.
   */
  return 1;
}

static void get_descriptor(struct usb_ctrlrequest * setup, void ** data, uint16_t * length) {

  if ((setup->wValue >> 8) ==  USB_DT_STRING && (setup->wValue & 0xff) == 0x00 && setup->wIndex == 0x0000) {
    *data = &descriptors->langId0;
    *length = descriptors->langId0.bLength;
    return;
  } else {
    unsigned int descNumber;
    for(descNumber = 0; descNumber < descriptors->nbOthers; ++descNumber) {
      if (descriptors->others[descNumber].wValue == setup->wValue && setup->wIndex == descriptors->others[descNumber].wIndex) {
        *data = descriptors->others[descNumber].data;
        *length = descriptors->others[descNumber].wLength;
        return;
      }
    }
  }
}

static int gadget_read_callback(int user, unsigned char endpoint, const void * buf, int status) {

  if (endpoint == 0) {

    struct usb_ctrlrequest * setup = (struct usb_ctrlrequest *) buf;

    void * data = NULL;
    uint16_t length = 0;

    fprintf(stderr, "SETUP %02x.%02x v%04x i%04x %d\n",
        setup->bRequestType, setup->bRequest, setup->wValue, setup->wIndex, setup->wLength);

    if (setup->bRequestType == USB_DIR_IN && setup->bRequest == USB_REQ_GET_DESCRIPTOR) {
      get_descriptor(setup, &data, &length);
    }

    if (data != NULL) {
      return gadget_write(gadget, 0, data, length);
    }

    if (setup->bRequestType == USB_DIR_OUT && setup->bRequest == USB_REQ_SET_CONFIGURATION) {
      gadget_state = E_GADGET_CONFIGURING;
    }
  } else {
    endpoint = ALLOCATOR_T2S_ENDPOINT(&endpointMap, endpoint);
    if (endpoint == 0) {
      PRINT_ERROR_OTHER("can't translate endpoint")
      return -1;
    }
  }

  return gusb_write(usb, endpoint, buf, status);
}

static int gadget_write_callback(int user, unsigned char endpoint, int status) {

  if (endpoint == 0) {
    PRINT_ERROR_OTHER("endpoint is 0")
    return -1;
  }

  switch (status) {
  case E_TRANSFER_TIMED_OUT:
    PRINT_TRANSFER_READ_ERROR(endpoint, "TIMEOUT")
    break;
  case E_TRANSFER_STALL:
    break;
  case E_TRANSFER_ERROR:
    PRINT_TRANSFER_WRITE_ERROR(endpoint, "OTHER ERROR")
    return -1;
  default:
    break;
  }

  return gusb_poll(usb, endpoint);
}

static int gadget_close_callback(int user) {

  done = 1;
  return 1;
}

void get_used_endpoints(unsigned short endpoints[2]) {

  unsigned char endpointIndex;
  for (endpointIndex = 0; endpointIndex < ALLOCATOR_MAX_ENDPOINT_NUMBER; ++endpointIndex) {
    if (ALLOCATOR_T2S_ENDPOINT(&endpointMap, USB_DIR_OUT | (endpointIndex + 1))) {
      endpoints[USB_DIR_OUT >> 7] |= (1 << endpointIndex);
    }
    if (ALLOCATOR_T2S_ENDPOINT(&endpointMap, USB_DIR_IN | (endpointIndex + 1))) {
      endpoints[USB_DIR_IN >> 7] |= (1 << endpointIndex);
    }
  }
}

int proxy_start(const char * port, const char * hcd) {

  int ret = set_prio();
  if (ret < 0)
  {
    PRINT_ERROR_OTHER("Failed to set process priority!")
    return -1;
  }

  if (port != NULL) {

      printf("Target capabilities:\n");

      allocator_print_props(&avr8Target);

      s_ep_props source = { { } };
      get_endpoint_properties(0, &source);

      printf("Source requirements:\n");
      allocator_print_props(&source);

      allocator_bind(&source, &avr8Target, &endpointMap);

      if (fix_configuration(0) < 0) {
        return -1;
      }

      adapter = adapter_open(port, process_packet, adapter_send_callback, adapter_close_callback);

      if(adapter < 0) {
        return -1;
      }

      if (send_descriptors() < 0) {
        return -1;
      }

      init_timer = gtimer_start(0, 1000000, timer_close, timer_close, gpoll_register_fd);
      if (init_timer < 0) {
        return -1;
      }
  } else { // hcd != NULL

      gadget = gadget_open(hcd);

      if (gadget < 0) {
          return -1;
      }

      fix_device();

      const s_ep_props * gadgetTarget = gadget_get_properties(gadget);

      if (gadgetTarget == NULL) {
          gadget_close(gadget);
          return -1;
      }

      s_ep_props target = *gadgetTarget;

      printf("Target capabilities:\n");

      allocator_print_props(&target);

      //TODO MLA: fix configuration (maybe we need to set bMaxPower...)

      s_ep_props source = { { } };
      get_endpoint_properties(0, &source);

      printf("Source requirements:\n");
      allocator_print_props(&source);

      allocator_bind(&source, &target, &endpointMap);

      if (fix_configuration(0) < 0) {
        gadget_close(gadget);
        return -1;
      }

      unsigned short endpoints[2] = {};
      get_used_endpoints(endpoints);

      ret = gadget_configure(gadget, descriptors, endpoints);
      if (ret < 0) {
          gadget_close(gadget);
          return -1;
      }

      ret = gadget_register(gadget, 0, gadget_read_callback, gadget_write_callback, gadget_close_callback, gpoll_register_fd);
      if (ret < 0) {
          gadget_close(gadget);
          return -1;
      }
  }

  ret = gusb_register(usb, 0, usb_read_callback, usb_write_callback, usb_close_callback, gpoll_register_fd);
  if (ret < 0) {
    return -1;
  }

  int timer = gtimer_start(0, 10000, timer_read, timer_close, gpoll_register_fd);
  if (timer < 0) {
    return -1;
  }

  while (!done) {
    gpoll();
  }

  gtimer_close(timer);

  if (adapter >= 0) {
      adapter_send(adapter, E_TYPE_RESET, NULL, 0);
      usleep(10000); // leave time for the reset packet to be sent
      adapter_close(adapter);
  }

  if (gadget >= 0) {
      gadget_close(gadget);
  }

  descriptors->device.bNumConfigurations = savedNumConfigurations; // make sure all memory is freed
  gusb_close(usb);

  if (init_timer >= 0) {
    PRINT_ERROR_OTHER("Failed to start the proxy: initialization timeout expired!")
    gtimer_close(init_timer);
    return -1;
  }

  return 0;
}

void proxy_stop() {
  done = 1;
}
