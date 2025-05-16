# ShadowSniff Documentation

## Introduction

ShadowSniff is a non-intrusive network sniffer tool that captures and analyzes network packets. It allows users to monitor various network protocols and provides valuable insights into the network traffic.

## Features

- Packet Capturing: Captures network packets for analysis.
- Protocol Support: Recognizes and processes the following protocols:
  - ICMP (Internet Control Message Protocol)
  - DNS (Domain Name System)
  - ARP (Address Resolution Protocol)
  - TCP (Transmission Control Protocol)
  - UDP (User Datagram Protocol)
- Real-time Display: Displays packet information and statistics in real-time during the packet capture process.
- Logging: Logs captured packet information to a file (`log.txt`) for later analysis.
- Customizable Capture Duration: Allows users to specify the duration (in seconds) for capturing packets.
- User-friendly Interface: Provides an easy-to-use command-line interface for interacting with the tool.

## Usage

Clone the repository using the following command:  
`git clone https://github.com/omkardeodhar/Shadow_Sniff.git`  

Navigate into the project directory:  
`cd shadowsniff`  

Install the required dependencies:  
`pip install scapy colorama`  
or  
`pip3 install scapy colorama`  

If Python is not installed, install it using:  
`sudo apt install python`  
or  
`sudo apt install python3`  

Create a file named `log.txt` in the project directory (if it doesn't already exist):  
`touch log.txt`  

⚠️ **Warning**: Run the tool using superuser privileges only.  

To start capturing packets, run:  
`sudo python sniff.py`  
or  
`sudo python3 sniff.py`  

> **Note**: This tool is compatible only with **Linux** systems. It does not work on **Windows** due to permission conflicts and the unavailability of required libraries.

## Log File Details

This tool logs the captured packet information to a file named `log.txt`. The log file contains the following details for each packet:

- Packet count: Total number of packets captured  
- Timestamp: Date and Time  
- Protocol-specific information:
  - ICMP: ICMP type, ICMP code, packet length, source IP, destination IP.
  - DNS: DNS query, packet length, source IP, destination IP.
  - ARP: ARP source IP, ARP destination IP, ARP operations, packet length.
  - TCP: Source port, destination port, packet length, source IP, destination IP, protocol (TCP).
  - UDP: Source port, destination port, packet length, source IP, destination IP, protocol (UDP).
