#! /usr/bin/env python3
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# import scapy library
from scapy.all import *

def sniffer():
	print("Would you like to-\n\t1: Choose how many packets to sniff\n\t2: Choose how long sniffer runs\n\t3: Choose both how many packets to sniff and how long")
	howToSniff = input("Enter your choice 1[# of Packets], 2[amount of time to sniff], or 3[Both]: ")
	hasntSniffed = True
	while(hasntSniffed):
		if(howToSniff.isdigit() and int(howToSniff) < 4):
			howToSniff = int(howToSniff)
			if(howToSniff == 1):
				numPackets = input("How many packets would you like to sniff? ")
				if(numPackets.isdigit()):
					packetsSniffed = sniff(count=int(numPackets))
					hasntSniffed = False
				else:
					print("Error: %s is not a digit" % numPackets)
			elif(howToSniff == 2):
				timeToSniff = input("How longwould you like to sniff packets? ")
				if(timeToSniff.isdigit()):
					packetsSniffed = sniff(count=int(timeToSniff))
					hasntSniffed = False
				else:
					print("Error: %s is not a digit" % timeToSniff)
			elif(howToSniff == 3):
				numPackets = input("How many packets would you like to sniff? ")
				timeToSniff = input("How longwould you like to sniff packets? ")
				if(numPackets.isdigit() and timeToSniff.isdigit()):
					packetsSniffed = sniff(count=numPackets, timeout=timeToSniff)
					hasntSniffed = False
				else:
					print("Error: %s or %s is not a digit" % numPackets, timeToSniff)
		else:
			print("Error: %s is an invalid choice, choose a valid operation(1, 2, or 3)." % howToSniff)
			howToSniff = str(input("Enter your choice: "))
	print(packetsSniffed.show())

def main():
	print('Network Sniffer')
	exist = True
	while exist:
		print("Would you like to-\n\tSniff: Sniff packets\n\tQuit: quit packet sniffer?")
		choice = input("Enter your choice [Sniff or Quit]: ")
		if(choice.lower() == "sniff"):
			sniffer()
		elif(choice.lower() == "quit"):
			print("Network Sniffer has been quit")
			exist = False
		else: 
			print("Error: %s is an invalid operation, choose a valid operation[Sniff or Quit].\n" % choice)
main()
