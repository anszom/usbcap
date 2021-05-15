#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <pcap/usb.h>
#include <pcap/dlt.h>
#include <inttypes.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

void usage(const char *av0)
{
	fprintf(stderr, "USB pcap filter, allows capturing data to/from a single USB device\n\n"
			"Usage:\n"
			"\t%s -i usbmonX [devicenum or vid:pid]\n"
			"\t%s -r capture.pcap [devicenum or vid:pid]\n"
			"\n"
			"The output will be written to stdout. To view, use %s (options) | tcpdump -r - -x\n",
			av0, av0, av0);
}

int main(int ac, char **av)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* cap;
	int devnum = -1, vid = 0, pid = 0;
	uint64_t get_desc_req = 0;
	bool live = false;

	if(av[1] && !strcmp(av[1], "-r") && av[2]) {
		cap = pcap_open_offline(av[2], errbuf);
		if(!cap) {
			fprintf(stderr, "Can't open file %s: %s\n", av[2], errbuf);
			return 1;
		}
	} else if(av[1] && !strcmp(av[1], "-i") && av[2]) {
		live = true;
		cap = pcap_open_live(av[2], 128, 0, -1, errbuf);
		if(!cap) {
			fprintf(stderr, "Can't open interface %s: %s\n", av[2], errbuf);
			return 1;
		}

	} else {
		usage(av[0]);
		return 1;
	}

	if(av[3]) {
		if(strchr(av[3], ':')) {
			sscanf(av[3], "%x:%x", &vid, &pid);
			fprintf(stderr, "Waiting for device %04x:%04x\n", vid, pid);
			devnum = 0;

		} else {
			devnum = atoi(av[3]);
			fprintf(stderr, "Capturing device %d\n", devnum);
		}
	}

	int dlt = pcap_datalink(cap);
	int headerlen = 0;

	switch(dlt) {
	case DLT_USB_LINUX:
		headerlen = sizeof(pcap_usb_header);
		break;
	
	case DLT_USB_LINUX_MMAPPED:
		headerlen = sizeof(pcap_usb_header_mmapped);
		break;

	default:
		fprintf(stderr, "Input stream is not usbmon\n");
		return 1;
	}

	pcap_dumper_t *dump = pcap_dump_fopen(cap, stdout);
	if(!dump) {
		fprintf(stderr, "Can't create output stream\n");
		return 1;
	}

	for(;;) {
		struct pcap_pkthdr hdr;
		const unsigned char *packet = pcap_next(cap, &hdr);
		
		if(!packet) 
			break;

		// in the mmapped variant, the header prefix is the same
		pcap_usb_header usb;
		memcpy(&usb, packet, sizeof(usb));

		if(vid && pid) {
			// scan for GET_DESCRIPTOR Request Device
			if(usb.event_type == 'S' && usb.transfer_type == URB_CONTROL && usb.endpoint_number == 0x80 
					&& usb.setup.bmRequestType == 0x80 && usb.setup.bRequest == 6
					&& usb.setup.wValue == 0x0100 && usb.setup.wIndex == 0) {
				get_desc_req = usb.id;
			}

			if(usb.event_type == 'C' && usb.id == get_desc_req && hdr.caplen >= headerlen + 18) {
				get_desc_req = 0;

				int new_vid = packet[headerlen+8] | (packet[headerlen+9]<<8);
				int new_pid = packet[headerlen+10] | (packet[headerlen+11]<<8);

				if(new_vid == vid && new_pid == pid && usb.device_address != 0) {
					devnum = usb.device_address;
					fprintf(stderr, "Now capturing device %d\n", devnum);
				}
			}
		}

		if((devnum >= 0 || (vid && pid)) && usb.device_address != devnum)
			continue;

		pcap_dump((unsigned char*)dump, &hdr, packet);
		if(live)
			pcap_dump_flush(dump);
	}

	return 0;
}
