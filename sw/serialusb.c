/*
 Copyright (c) 2015 Mathieu Laurendeau <mat.lau@laposte.net>
 License: GPLv3
 */

#include <proxy.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <info.h>
#include <getopt.h>

static const char * port = NULL;
static const char * hcd = NULL;

static void usage()
{
  printf("Usage: sudo serialusb <--port /dev/ttyUSB0> <--gadget /dev/gadget/dummy_hcd>\n");
}

int args_read(int argc, char *argv[]) {

  int ret = 0;
  int c;

  struct option long_options[] = {
    /* These options don't set a flag. We distinguish them by their indices. */
    { "gadget",  optional_argument, 0, 'g' },
    { "help",    no_argument,       0, 'h' },
    { "version", no_argument,       0, 'v' },
    { "port",    optional_argument, 0, 'p' },
    { 0, 0, 0, 0 }
  };

  while (1) {
    /* getopt_long stores the option index here. */
    int option_index = 0;

    c = getopt_long(argc, argv, "g:hp:v", long_options, &option_index);

    /* Detect the end of the options. */
    if (c == -1)
      break;

    switch (c) {

    case 'g':
      hcd = optarg;
      break;


    case 'h':
      usage();
      exit(0);
      break;

    case 'p':
      port = optarg;
      break;

    case 'v':
      printf("serialusb %s %s\n", INFO_VERSION, INFO_ARCH);
      exit(0);
      break;

    case '?':
      usage();
      exit(-1);
      break;

    default:
      printf("unrecognized option: %c\n", c);
      ret = -1;
      break;
    }
  }

  return ret;
}

static void terminate(int sig) {
  proxy_stop();
}

int main(int argc, char * argv[]) {

  (void) signal(SIGINT, terminate);
  (void) signal(SIGTERM, terminate);

  int ret;

  ret = args_read(argc, argv);
  if(ret < 0) {
    return -1;
  }

  ret = proxy_init();

  if (ret == 0 && (port != NULL || hcd != NULL)) {
    ret = proxy_start(port, hcd);
  }

  return ret;
}
