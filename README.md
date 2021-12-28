# Host-Discoverer
Simple C++ script that is able to found up hosts in local network. Very fast, light and accurate.

## Installation
> Manual
```
cd src/
g++ HostDiscoverer.cpp Kping.cpp -o HostDiscoverer
```
> CMake
```
mkdir build
cd build
cmake ../
cmake --build .
```
## Usage
```
sudo ./HostDiscoverer [Ipv4 address] [Netmask]
```
or 

```
sudo ./HostDiscoverer [Ipv4 address]/[CIDR Netmask]
```
## Requirements
- g++
- CMake ( Optional )
