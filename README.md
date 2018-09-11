
A wireshark dissector for the [BLIP](https://github.com/couchbaselabs/BLIP-Cpp) protocol.

![screenshot](https://user-images.githubusercontent.com/296876/37130256-8122e29a-2237-11e8-8c22-caaf65889f22.png)

## Installation Instructions

Build wireshark from source.

Use the [official instructions](https://wiki.wireshark.org/BuildingAndInstalling#macOS) with the **Building without a third-party package source** instructions, with the following changes:

1. `brew install libgcrypt`
1. Add explicit path to python executable: `cmake -DPYTHON_EXECUTABLE:FILEPATH=/usr/bin/python ../ && make`

Copy `packet-blip.c` into the dissectors directory.

Add `packet-blip.c` to the cmakelists.txt file.

Build + Run.

## Usage Instructions

If you aren't able to capture traffic directly using the custom-built Wireshark, then capture via `tcpdump` and open the capture file using Wireshark.

## TODO

1. Submit this to the Wireshark Repo for being [included in Wireshark](https://www.wireshark.org/docs/wsdg_html_chunked/ChSrcContribute.html) by default
