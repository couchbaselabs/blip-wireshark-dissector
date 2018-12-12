
A wireshark dissector for the [BLIP](https://github.com/couchbaselabs/BLIP-Cpp) protocol.

![screenshot](https://user-images.githubusercontent.com/296876/37130256-8122e29a-2237-11e8-8c22-caaf65889f22.png)

## Binary Installation Instructions

A Developer Preview can be downloaded from the [Wireshark Developer Preview Downloads](https://www.wireshark.org/download/automated) page.

## Source Installation Instructions

Build wireshark from source.

Use the [official instructions](https://wiki.wireshark.org/BuildingAndInstalling#macOS) with the **Building with Homebrew** instructions to download the wireshark source code and tools used for building the wireshare. Then follows the below instructions.

1. `brew install libgcrypt`
2. Copy packet-blip.c to epan/dissectors
3. Add `${CMAKE_CURRENT_SOURCE_DIR}/packet-blip.c` to `CMakeLists.txt ` under the `DISSECTOR_SRC` section
4. From the wireshark root folder, `mkdir build && cd build && cmake ../ && make`

## Usage Instructions

* You must capture traffic from both the Couchbase Lite client and the Sync Gateway server, otherwise it will not recognized the Websocket upgrade handshake and packets will not be properly dissected as `BLIP` packets.
* You must start the capture before the Websocket upgrade handshake for the connection(s) you are interested in, or else any packets part of the connection will not be dissected as `BLIP` packets.

