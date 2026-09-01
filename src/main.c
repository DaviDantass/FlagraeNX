#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <pcap.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")

#define ETHERNET_HEADER_SIZE 14
#define MAX_PACKET_SIZE 65535
#define HEXDUMP_SIZE 64

struct ethernet_header {
  uint8_t destination[6];
  uint8_t source[6];
  uint16_t ether_type;
};

struct ipv4_header {
  uint8_t version_ihl;
  uint8_t tos;
  uint16_t total_length;
  uint16_t identification;
  uint16_t flags_fragment;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t checksum;
  uint32_t source;
  uint32_t destination;
};

/ struct tcp_header {
  uint16_t source_port;
  uint16_t destination_port;

  uint32_t sequence;
  uint32_t acknowledgement;

  uint8_t data_offset_reserved;
  uint8_t flags;

  uint16_t window;
  uint16_t checksum;
  uint16_t urgent_pointer;
};

struct udp_header {
  uint16_t source_port;
  uint16_t destination_port;

  uint16_t length;
  uint16_t checksum;
};

void print_mac(const uint8_t *mac) {
  printf("%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3],
         mac[4], mac[5]);
}
*/

    void hex_dump(const uint8_t *data, size_t size) {
  size_t limit = size;

  if (limit > HEXDUMP_SIZE)
    limit = HEXDUMP_SIZE;

  for (size_t i = 0; i < limit; i++) {
    printf("%02X ", data[i]);

    if ((i + 1) % 16 == 0)
      printf("\n");
  }

  if (limit > 0 && limit % 16 != 0)
    printf("\n");

  if (size > HEXDUMP_SIZE)
    printf("... (%zu bytes restantes)\n", size - HEXDUMP_SIZE);
}

void print_tcp_flags(uint8_t flags) {
  printf("Flags: ");

  if (flags & 0x01)
    printf("FIN ");

  if (flags & 0x02)
    printf("SYN ");

  if (flags & 0x04)
    printf("RST ");

  if (flags & 0x08)
    printf("PSH ");

  if (flags & 0x10)
    printf("ACK ");

  if (flags & 0x20)
    printf("URG ");

  if (flags & 0x40)
    printf("ECE ");

  if (flags & 0x80)
    printf("CWR ");

  printf("\n");
}

int main(void) {
  char error_buffer[PCAP_ERRBUF_SIZE];

  pcap_if_t *interfaces = NULL;
  pcap_if_t *device = NULL;

  if (pcap_findalldevs(&interfaces, error_buffer) == -1) {
    fprintf(stderr, "Erro ao encontrar interfaces: %s\n", error_buffer);

    return EXIT_FAILURE;
  }

  printf("\n");
  printf("========================================\n");
  printf("          NETWORK SNIFFER\n");
  printf("========================================\n\n");

  int interface_count = 0;

  for (device = interfaces; device != NULL; device = device->next) {
    interface_count++;

    printf("[%d] %s\n", interface_count, device->name);

    if (device->description != NULL) {
      printf("    %s\n", device->description);
    }

    printf("\n");
  }

  if (interface_count == 0) {
    printf("Nenhuma interface encontrada.\n");

    pcap_freealldevs(interfaces);

    return EXIT_FAILURE;
  }

  int selected;

  printf("Escolha a interface: ");

  if (scanf("%d", &selected) != 1) {
    printf("Entrada invalida.\n");

    pcap_freealldevs(interfaces);

    return EXIT_FAILURE;
  }

  if (selected < 1 || selected > interface_count) {
    printf("Interface invalida.\n");

    pcap_freealldevs(interfaces);

    return EXIT_FAILURE;
  }

  device = interfaces;

  for (int i = 1; i < selected; i++) {
    device = device->next;
  }

  printf("\n");
  printf("Interface selecionada:\n");
  printf("%s\n\n", device->name);

  /*
   * Abre a interface para captura.
   *
   * 65535 = tamanho maximo do pacote capturado
   * 1      = modo promiscuo
   * 1000   = timeout em ms
   */

  pcap_t *handle =
      pcap_open_live(device->name, MAX_PACKET_SIZE, 1, 1000, error_buffer);

  if (handle == NULL) {
    fprintf(stderr, "Erro ao abrir interface: %s\n", error_buffer);

    pcap_freealldevs(interfaces);

    return EXIT_FAILURE;
  }

  pcap_freealldevs(interfaces);

  int datalink = pcap_datalink(handle);

  if (datalink != DLT_EN10MB) {
    printf("Aviso: link-layer nao e Ethernet (DLT=%d).\n", datalink);
  }

  printf("========================================\n");
  printf("CAPTURA INICIADA\n");
  printf("Pressione CTRL+C para parar.\n");
  printf("========================================\n");

  while (1) {
    struct pcap_pkthdr *packet_header;

    const uint8_t *packet;

    int result = pcap_next_ex(handle, &packet_header, &packet);

    if (result == 0) {

      continue;
    }

    if (result == -1) {
      fprintf(stderr, "Erro durante captura: %s\n", pcap_geterr(handle));

      break;
    }

    if (result == -2) {

      break;
    }

    printf("\n");
    printf("----------------------------------------\n");

    printf("Packet: %u bytes\n", packet_header->caplen);

    if (packet_header->caplen < ETHERNET_HEADER_SIZE) {
      continue;
    }

    // Interpretamos os primeiros bytes como Ethernet.

    struct ethernet_header *ethernet = (struct ethernet_header *)packet;

    printf("\n[ETHERNET]\n");

    printf("Source MAC: ");
    print_mac(ethernet->source);

    printf("\n");

    printf("Destination MAC: ");
    print_mac(ethernet->destination);

    printf("\n");

    printf("EtherType: 0x%04X\n", ntohs(ethernet->ether_type));

    /*
     * Verifica se e IPv4.
     */

    if (ntohs(ethernet->ether_type) != 0x0800) {
      printf("Nao e IPv4.\n");

      continue;
    }
    if (packet_header->caplen <
        ETHERNET_HEADER_SIZE + sizeof(struct ipv4_header)) {
      continue;
    }

    struct ipv4_header *ip =
        (struct ipv4_header *)(packet + ETHERNET_HEADER_SIZE);

    uint8_t ip_header_length = (ip->version_ihl & 0x0F) * 4;

    uint8_t ip_version = (ip->version_ihl >> 4);

    if (ip_version != 4) {
      continue;
    }

    /*
     * Verifica se o pacote tem
     * o header inteiro.
     */

    if (packet_header->caplen < ETHERNET_HEADER_SIZE + ip_header_length) {
      continue;
    }

    char source_ip[INET_ADDRSTRLEN];
    char destination_ip[INET_ADDRSTRLEN];

    struct in_addr source_address;
    struct in_addr destination_address;

    source_address.s_addr = ip->source;

    destination_address.s_addr = ip->destination;

    inet_ntop(AF_INET, &source_address, source_ip, sizeof(source_ip));

    inet_ntop(AF_INET, &destination_address, destination_ip,
              sizeof(destination_ip));

    printf("\n[IPv4]\n");

    printf("Source:      %s\n", source_ip);

    printf("Destination: %s\n", destination_ip);

    printf("TTL:         %u\n", ip->ttl);

    printf("Protocol:    %u\n", ip->protocol);

    printf("Total size:  %u bytes\n", ntohs(ip->total_length));
    /*
     * Descobre onde começa o protocolo
     * TCP/UDP.
     */
    const uint8_t *transport = packet + ETHERNET_HEADER_SIZE + ip_header_length;

    size_t transport_offset = ETHERNET_HEADER_SIZE + ip_header_length;
    // tcp
    if (ip->protocol == 6) {
      printf("\n[TCP]\n");

      if (packet_header->caplen <
          transport_offset + sizeof(struct tcp_header)) {
        continue;
      }

      struct tcp_header *tcp = (struct tcp_header *)transport;

      uint16_t source_port = ntohs(tcp->source_port);

      uint16_t destination_port = ntohs(tcp->destination_port);

      printf("Source port:      %u\n", source_port);

      printf("Destination port: %u\n", destination_port);

      uint8_t tcp_header_length = ((tcp->data_offset_reserved >> 4) * 4);

      printf("Header size:      %u bytes\n", tcp_header_length);

      print_tcp_flags(tcp->flags);
      // tcp
      size_t payload_offset = transport_offset + tcp_header_length;

      if (payload_offset < packet_header->caplen) {
        size_t payload_size = packet_header->caplen - payload_offset;

        printf("Payload: %zu bytes\n", payload_size);

        if (payload_size > 0) {
          printf("\n[PAYLOAD HEX]\n");

          hex_dump(packet + payload_offset, payload_size);
        }
      }
    }
    // udp
    else if (ip->protocol == 17) {
      printf("\n[UDP]\n");

      if (packet_header->caplen <
          transport_offset + sizeof(struct udp_header)) {
        continue;
      }
      struct udp_header *udp = (struct udp_header *)transport;

      printf("Source port:      %u\n", ntohs(udp->source_port));

      printf("Destination port: %u\n", ntohs(udp->destination_port));

      printf("Length:            %u bytes\n", ntohs(udp->length));

      size_t payload_offset = transport_offset + sizeof(struct udp_header);

      if (payload_offset < packet_header->caplen) {
        size_t payload_size = packet_header->caplen - payload_offset;

        printf("Payload: %zu bytes\n", payload_size);

        if (payload_size > 0) {
          printf("\n[PAYLOAD HEX]\n");

          hex_dump(packet + payload_offset, payload_size);
        }
      }
    }

    else if (ip->protocol == 1) {
      printf("\n[ICMP]\n");
    }

    else {
      printf("\n[UNKNOWN PROTOCOL]\n");
    }
  }

  pcap_close(handle);

  return EXIT_SUCCESS;
}