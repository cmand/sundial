Sundial Zmap module
Erik Rye <rye@cmand.org>
===================
0. Background.  Sundial is a project to expose properties of Internet
   devices via ICMP timestamp messages.  For full details, or to 
   cite this work, please see:
     E.C. Rye and R. Beverly "Sundials in the Shade", PAM 2019
     (https://www.cmand.org/sundial/)

1. Dependencies.  Zmap itself requires several dependencies; a handy list 
   of debian packages that are pre-requisites include:
     $ sudo apt-get install build-essential cmake libgmp3-dev gengetopt libpcap-dev flex byacc libjson-c-dev pkg-config libunistring-dev

2. Building.  Follow these steps:
    - Copy packet.*, probe_modules.*, and module_sundial.c to 
      zmap/src/probe_modules/
    - Add probe_modules/module_sundial.c to set(EXTRA_PROBE_MODULES) in
      zmap/src/CMakeLists.txt
    - Copy md5.h to zmap/lib
    - cd zmap && mkdir build && cd build
    - cmake ..
    - make -j4
    - sudo make install

3. Running.
    $ zmap -M sundial --probe-args=X

    where X in:
     1 Standard Probe (default)
     2 Bad Clock
     3 Bad Checksum
     4 Duplicate TS
