# Sundial Zmap module

<https://www.cmand.org/sundial/>


0. **Background**:  Sundial is a project to expose properties of Internet
   devices via ICMP timestamp messages.  For full details, or to
   cite this work, please see:
     E.C. Rye and R. Beverly "Sundials in the Shade," PAM 2019

1. **Dependencies**:  Zmap itself requires several dependencies; a handy list
   of debian packages that are pre-requisites include:

     `$ sudo apt-get install build-essential cmake libgmp3-dev gengetopt libpcap-dev flex byacc`

2. **Building**:  Follow these steps to build Zmap with Sundial support:
    - Clone Zmap (https://github.com/zmap/zmap)
    - Copy packet.\*, probe\_modules.\*, and module\_sundial.c to
      zmap/src/probe_modules/
    - Add probe\_modules/module\_sundial.c to set(EXTRA\_PROBE\_MODULES) in
      zmap/src/CMakeLists.txt
    - Copy md5.h to zmap/lib
    - cd zmap && mkdir build && cd build
    - cmake ..
    - make -j4
    - sudo make install

3. **Running**:

    `$ zmap -M sundial --probe-args=X -I listofips`

    where X = 1 (Standard Probe), 2 (Bad Clock), 3 (Bad Checksum), 4 (Duplicate TS)

4. **Analysis**:
    - Build analyze from timestampAnalyzer.c using included Makefile
    - Analysis scripts require a pcap capture of the Zmap run (ICMP probes and responses)
    - Analysis scripts assume pcap contains *all* 4 probe types 
    - Assuming the captured pcap `zmap_sundial.pcap`:
       - `analyze zmap_sundial.pcap`
       - `python sundialClassifier.py -i zmap_sundial.pcap_results.txt`
   - Use `python sundialClassifier.py -h` for a list of analysis options
