
A wireshark dissector for the [BLIP](https://github.com/couchbaselabs/BLIP-Cpp) protocol.

![screenshot](https://user-images.githubusercontent.com/296876/37130256-8122e29a-2237-11e8-8c22-caaf65889f22.png)

## Installation Instructions

Build wireshark from source.

Use the [official instructions](https://wiki.wireshark.org/BuildingAndInstalling#macOS) with the **Building without a third-party package source** instructions to download the wireshark source code and tools used for building the wireshare. Then follows the below instructions.

1. `brew install libgcrypt`
2. Copy packet-blip.c to epan/dissectors
3. Add `${CMAKE_CURRENT_SOURCE_DIR}/packet-blip.c` to `CMakeLists.txt ` under the `DISSECTOR_SRC` section
4. From the wireshark root folder, `mkdir build && cd build && cmake ../ && make`

## Usage Instructions

If you aren't able to capture traffic directly using the custom-built Wireshark, then capture via `tcpdump` and open the capture file using Wireshark.

## TODO

1. Submit this to the Wireshark Repo for being [included in Wireshark](https://www.wireshark.org/docs/wsdg_html_chunked/ChSrcContribute.html) by default
