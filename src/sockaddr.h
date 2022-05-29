#include <sys/socket.h>

#include <linux/atalk.h>
#include <linux/atm.h>
#include <linux/ax25.h>
#include <linux/caif/caif_socket.h>
#include <linux/can.h>
#include <linux/dn.h>
#include <linux/if_alg.h>
#include <linux/if_packet.h>
// #include <linux/if_pppox.h>
// #include <linux/if_xdp.h>
#include <linux/in6.h>
#include <linux/in.h>
#include <linux/l2tp.h>
#include <linux/llc.h>
#include <linux/netlink.h>
#include <linux/nfc.h>
#include <linux/phonet.h>
#include <linux/qrtr.h>
#include <linux/rose.h>
#include <linux/rxrpc.h>
#include <linux/tipc.h>
#include <linux/un.h>
#include <linux/vm_sockets.h>
#include <linux/x25.h>

#include <inttypes.h>

/* Apparently, ipx.h is no longer generally available. */

#define IPX_NODE_LEN	6

struct sockaddr_ipx
{
  sa_family_t sipx_family;
  uint16_t sipx_port;
  uint32_t sipx_network;
  unsigned char sipx_node[IPX_NODE_LEN];
  uint8_t sipx_type;
  unsigned char sipx_zero;
};
