
A wireshark dissector for the [BLIP](https://github.com/couchbaselabs/BLIP-Cpp) protocol.

![screenshot](https://user-images.githubusercontent.com/296876/37130256-8122e29a-2237-11e8-8c22-caaf65889f22.png)

## Binary Installation Instructions

A Developer Preview can be downloaded from the [Wireshark Developer Preview Downloads](https://www.wireshark.org/download/automated) page.

## Source Installation Instructions

The source code of the BLIP dissector is included in the Wireshark source tree.

Use the [official instructions](https://wiki.wireshark.org/BuildingAndInstalling#macOS) to download and build Wireshark from source. 

## Usage Instructions

* You must capture traffic from both the Couchbase Lite client and the Sync Gateway server, otherwise it will not recognized the Websocket upgrade handshake and packets will not be properly dissected as `BLIP` packets.
* You must start the capture before the Websocket upgrade handshake for the connection(s) you are interested in, or else any packets part of the connection will not be dissected as `BLIP` packets.

