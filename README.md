You need [vitasdk](https://vitasdk.org/).

1. `make` the payload
2. Copy `fat.bin` to `installer/res`
3. CMake the installer `mkdir build && cd build && cmake .. && make`

Firmware specific offsets are in first.c and nsbl.h. Logo is raw framebuffer data gzipped. If you make this too big (bigger than original logo size), you WILL perma-brick your Vita.

The source is for advanced users only. Users should download the [prebuilt package](https://enso.henkaku.xyz/). If something goes wrong, you WILL perma-brick your Vita. There is no recovery, even if you have a hardware mod. The only possible recovery is if you have a hardware mod and you dump the eMMC _before_ getting bricked, then you can restore the dump. Dumps are device-specific and encrypted with a device-specific key.

Again, even if you just change the logo, there's a good chance you will perma-brick your Vita. You have been warned.
