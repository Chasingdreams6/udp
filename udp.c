/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define DATA_LENGTH 32

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.max_rx_pkt_len = RTE_ETHER_MAX_LEN,
	},
};

/* udp.c: Basic DPDK-udp sender, it's based on skeleton. */

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0) {
		printf("Error during getting device (port %u) info: %s\n",
				port, strerror(-retval));
		return retval;
	}

	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			DEV_TX_OFFLOAD_MBUF_FAST_FREE;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct rte_ether_addr addr;
	retval = rte_eth_macaddr_get(port, &addr);
	if (retval != 0)
		return retval;

	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	retval = rte_eth_promiscuous_enable(port);
	if (retval != 0)
		return retval;

	return 0;
}

static uint16_t get_udp_checksum(struct rte_udp_hdr* udpHdr) {
    uint16_t res = 0;
    res = udpHdr->dst_port * 241 + udpHdr->src_port * 73 + udpHdr->dgram_len * 19;
    return res;
}

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */
static __rte_noreturn void
lcore_main(struct rte_mempool *mbuf_pool)
{
	uint16_t port;

	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	RTE_ETH_FOREACH_DEV(port)
		if (rte_eth_dev_socket_id(port) >= 0 &&
				rte_eth_dev_socket_id(port) !=
						(int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n", port);

	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
			rte_lcore_id());

	/* Run until the application is quit or killed. */
	for (;;) {
        port = 0; // send by port 0
        struct rte_mbuf *bufs[BURST_SIZE];
        struct rte_ether_hdr *etherHdr;
        struct rte_ipv4_hdr *ipv4Hdr;
        struct rte_udp_hdr *udpHdr;
        /*init header and data for udp*/
        char udp_data[DATA_LENGTH] = "This is message from udp";
        rte_be16_t src_port = 1234; // src port
        rte_be16_t dst_port = 1234; // dst port
        rte_be16_t udp_len = DATA_LENGTH + 8;
        /*construct ethernet dst mac address*/
        struct rte_ether_addr dst_mac;
        dst_mac.addr_bytes[0] = 0x11;
        dst_mac.addr_bytes[1] = 0x22;
        dst_mac.addr_bytes[2] = 0x33;
        dst_mac.addr_bytes[3] = 0x44;
        dst_mac.addr_bytes[4] = 0x55;
        dst_mac.addr_bytes[5] = 0x66;
        /*construct ethernet src mac address*/
        struct rte_ether_addr src_mac;
        rte_eth_macaddr_get(port, &src_mac);

        int ret = rte_pktmbuf_alloc_bulk(mbuf_pool, bufs, BURST_SIZE);
        if (ret != 0)
            printf("alloc bulk failed!\n");
        for (int i = 0; i < BURST_SIZE; ++i) {
            /*construct the data*/
            char *tmp = rte_pktmbuf_append(bufs[i], DATA_LENGTH);
            if (tmp == NULL)
                return -1;
            rte_memcpy(tmp, udp_data, DATA_LENGTH);

            /*package udp head*/
            udpHdr = (struct rte_udp_hdr *) rte_pktmbuf_prepend(bufs[i], sizeof(struct rte_udp_hdr));
            udpHdr->src_port = rte_cpu_to_be_16(src_port); // to big-endian
            udpHdr->dst_port = rte_cpu_to_be_16(dst_port);
            udpHdr->dgram_len = rte_cpu_to_be_16(udp_len);
            udpHdr->dgram_cksum = rte_cpu_to_be_16(get_udp_checksum(udpHdr));

            /*package ip head*/
            ipv4Hdr = (struct rte_ipv4_hdr *) rte_pktmbuf_prepend(bufs[i], sizeof(struct rte_ipv4_hdr));
            ipv4Hdr->src_addr = rte_cpu_to_be_32(RTE_IPV4(192,168,1,1));
            ipv4Hdr->dst_addr = rte_cpu_to_be_32(RTE_IPV4(192,168,0,101));
            ipv4Hdr->next_proto_id = 0x11; // 17 is UDP
            ipv4Hdr->version_ihl = 0x45; // ipv4 + (0101), 0101 * 4 = 20Byte, corresponding sizeof(rte_ipv4_hdr);
            ipv4Hdr->time_to_live = 0x20; // 32's ttl
            ipv4Hdr->total_length = rte_cpu_to_be_32(udp_len + sizeof(struct rte_ipv4_hdr));
            ipv4Hdr->hdr_checksum = rte_ipv4_cksum(ipv4Hdr);

            /*package ethernet header*/
            etherHdr = (struct rte_ether_hdr *) rte_pktmbuf_prepend(bufs[i], sizeof(struct rte_ether_hdr));
            etherHdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
            rte_ether_addr_copy( &dst_mac, &etherHdr->d_addr);
            rte_ether_addr_copy(&src_mac, &etherHdr->s_addr);

        }
        const uint16_t nb_tx = rte_eth_tx_burst(port, 0, bufs, 1); // send a packet
        printf("sent %d pktmbufs\n", nb_tx);
        sleep(1); // sleep 1 second
	}
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	unsigned nb_ports;
	uint16_t portid;

	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

    /*get available ports number*/
	nb_ports = rte_eth_dev_count_avail();

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initialize all ports. */
	//RTE_ETH_FOREACH_DEV(portid)
    portid = 0; // just use one port to send
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
					portid);

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	/* Call lcore_main on the main core only. */
	lcore_main(mbuf_pool);

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}
