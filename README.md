# usbcap

This is a simple tool to selectively capture data from linux' usbmon interface.

A regular capture using tcpdump/dumpcap/wireshark returns all traffic from
a single USB host, which can be very noisy at times. This tool allows you to
filter data by usb device number or VID/PID pair. 

Captured data is output to stdout in pcap format, it can be redirected to a
file or piped to tcpdump in order to display captured data. It should also
be possible to configure wireshark to read from usbcap, but I haven't tried it.

## Running

The basic invocation options are:

	./usbcap -i usbmonX [filter]
	./usbcap -r usbmon.pcap [filter]

The first variant opens a live capture interface (obviously you need to have
the usbmon module loaded and permission to open the capture interface).
The second variant reads data from a pcap-formatted file.

The filter can be either a decimal USB device address (such as 123) or
hexadecimal vid:pid pair (such as 0123:4567). Filtering by device address is
straightforward, filtering by vid:pid requires that the tool is able to capture
the GET DEVICE DESCRIPTOR request. For some reason, libpcap triggers such
requests (if permissions allow), so usually you should have no problem with
this limitation. Re-plugging the device is also a sure way to trigger
detection. After the device is detected, it's followed by its address,
currently only one device will be tracked even if multiple devices with the
same vid/pid are connected.

If the filter is empty, all packets are returned, this is equivalent to
	
	tcpdump -i usbmonX -s 128 -w -

## Examples

Capturing data from a USB mouse (by address):

	# lsusb
	...
	Bus 002 Device 001: ID 1d6b:0003 Linux Foundation 3.0 root hub
	Bus 001 Device 002: ID 046d:c077 Logitech, Inc. M105 Optical Mouse <- here 002 is the device address
	Bus 001 Device 001: ID 1d6b:0002 Linux Foundation 2.0 root hub
	...
	# ./usbcap -i usbmon1 2 | tcpdump -r -
	Capturing device 2
	Reading from file -, link-type USB_LINUX_MMAPPED (USB with padded Linux header)
	20:34:46.632906 CONTROL SUBMIT to 1:2:0
	20:34:46.633417 CONTROL COMPLETE from 1:2:0
	20:34:48.997711 INTERRUPT COMPLETE to 1:2:1
	...


By ID:

	# ./usbcap -i usbmon1 046d:c077 | tcpdump -r -
	Waiting for device 046d:c077
	Now capturing device 2
	reading from file -, link-type USB_LINUX_MMAPPED (USB with padded Linux header)
	20:35:10.605437 CONTROL COMPLETE from 1:2:0
	20:35:11.253579 INTERRUPT COMPLETE to 1:2:1
	20:35:11.253607 INTERRUPT SUBMIT from 1:2:1
	20:35:11.269558 INTERRUPT COMPLETE to 1:2:1

