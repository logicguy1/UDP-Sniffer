# UDP-Sniffer
A UDP Packet sniffer for sniffing omegle ips (or other services)

## Installation

Run the following commands in bash

```pip install requests```

Then go into the project file and open the script

## Configureation

To configure the scipt change the values in config.json, here is a breakdown of what they do

```json
{
  "delay" : 5, // The amount of time taken between displaying the same packet over and over, each destination ip as its own countdown timer
  "noise" : 200, // The amount of noise to filter, the higher the value the longer it will take to fetch a packet
  "location" : false // Should the script fetch location data on the ip? true or false
}
```

## Usage for Omegle

I will here show you how eazy and insecure omegle is, this is **educational only**

If you run the scrip and fire up omegle video chat it will start picking up packets, if you set `"location": true` in the configureation it will also display location data, if its able to fetch it

