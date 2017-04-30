# WARNING: This is a public repository. Do not, under any circumstances or for any period of time, commit or push sensitive information such as credentials or personal information of the team members.

## What is this?
This repository is set up for the group project for CS158A-01 at SJSU with Faramarz Mortezaie. The reason it is public is so that it can be showcased to prospective employers. Please re-read the warning at the begining.

## Coding Style
We will be coding in Python3 for this project, so please read and adhere to the guidelines described here (https://google.github.io/styleguide/pyguide.html).

## Usage
To use this network sniffer, you must have python3 and https(scapy://github.com/phaethon/scapy) installed.

To run the network sniffer, clone this repository, go to the correct directory, and then run:
	`sudo python3 sniffer.py` 

	!It is important to run with `sudo`, so that the sniffer has ROOT privileges!

## Requirements breakdown
* Python Network Sniffer
  * Network Sniffer
    * Continuously monitor the Traffic (Until told to stop by user)
    * "Sniff" any traffic on the socket
      * Parse packets sniffed without altering data
      * Display Data to user
      * Store data for later use
