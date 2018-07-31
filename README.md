
A wireshark dissector for the [BLIP](https://github.com/couchbaselabs/BLIP-Cpp) protocol.

![screenshot](https://user-images.githubusercontent.com/296876/37130256-8122e29a-2237-11e8-8c22-caaf65889f22.png)

Work-in-progress.

## Installation Instructions

Build wireshark from source.

Differences from [official instructions](https://wiki.wireshark.org/BuildingAndInstalling#macOS) 

1. `brew install libgcrypt`
1. Add explicit path to python executable: `cmake -DPYTHON_EXECUTABLE:FILEPATH=/usr/bin/python ../ && make`

Copy `packet-blip.c` into the dissectors directory.

Add to the cmakelists.txt file.

Build + Run.

## Usage Instructions

If you aren't able to capture traffic directly using the custom-built Wireshark, then capture via `tcpdump` and open the capture file using Wireshark.

## TODO

1. Expand flags to be more readable (currently just shows decimal version)
1. Handle compressed messages
1. Submit this to the Wireshark Repo for being [included in Wireshark](https://www.wireshark.org/docs/wsdg_html_chunked/ChSrcContribute.html) by default
