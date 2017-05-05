#! /usr/bin/env python3
# Prevent scapy from throwing IPv6 ERROR
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# import scapy library
from scapy.all import *

## Customize the output to be more readable
packetCount = 0
def customOutput(packet):
	global packetCount
	packetCount += 1
	return "Packet #%s: %s ===>\t%s" % (packetCount, packet[0][1].src, packet[0][1].dst)

# Sniffer will ask user how they want packets over netowork scanned
# User can choose to:
#	1 Choose how many pakcets to sniff
#	2 Choose how long to sniff  pakcets
#	3 Choose both how many packets to sniff or how long to sniff  packets
#		* Option 3 will stop sniffing when either time is up or number of packets to sniff is reached
def sniffer():
	#if(input("Would you like to sniff packets filtered or unfiltered?").lower() == 'filtered'): filtered = True
	#else: filtered = False			//Need to implement filtering (Use sniff(filter="UserDefinedFilter")
	print("\nWould you like to-\n\t1: Choose how many packets to sniff\n\t2: Choose how long sniffer runs\n\t3: Choose both how many packets to sniff and how long")
	howToSniff = input("Enter your choice 1[# of Packets], 2[amount of time to sniff], or 3[Both]: ")
	hasntSniffed = True		# Loop while method hasn't sniffed
	outputSetting = input("\nOutput Settings:\n\t1: Raw Output\n\t2: Readable Output\nOutput Choice: ")  # Ask user if they want raw output or an easier to read output

	while hasntSniffed:
		if howToSniff.isdigit() and int(howToSniff) < 4 and int(outputSetting) <= 2:
			global packetCount
			howToSniff = int(howToSniff)	# Determine which option user chose
			if howToSniff == 1:
				print("\n====================================================================================")
				numPackets = input("\nHow many packets would you like to sniff? ")
				if numPackets.isdigit():
					# Give users a choice on how to output the sniffed packet
					if int(outputSetting) == 1:
						packetsSniffed = sniff(count=int(numPackets))
						packetsSniffed.nsummary()
					elif int(outputSetting) == 2:
						packetsSniffed = sniff(count=int(numPackets), filter="ip", prn=customOutput)
					print("\n====================================================================================")
					packetCount = 0
					hasntSniffed = False
				else:
					print("Error: %s is not a digit" % numPackets)
					howToSniff = str(howToSniff)
			elif howToSniff == 2:
				timeToSniff = input("\nHow long would you like to sniff packets? ")
				if(timeToSniff.isdigit()):
					packetsSniffed = sniff(timeout=int(timeToSniff))
					hasntSniffed = False
				else:
					print("Error: %s is not a digit" % timeToSniff)
					howToSniff = str(howToSniff)
			elif howToSniff == 3:
				numPackets = input("\nHow many packets would you like to sniff? ")
				timeToSniff = input("How long would you like to sniff packets? ")
				if(numPackets.isdigit() and timeToSniff.isdigit()):
					# Give users a choice on how to output the sniffed packet
					if int(outputSetting) == 1:
						packetsSniffed = sniff(count=int(numPackets), timeout=int(timeToSniff))
						packetsSniffed.nsummary()
					elif int(outputSetting) == 2:
						packetsSniffed = sniff(count=int(numPackets), timeout=int(timeToSniff), filter="ip", prn=customOutput)
					hasntSniffed = False
				else:
					print("Error: %s or %s is not a digit" % (numPackets, timeToSniff))
					howToSniff = str(howToSniff)
		else:
			print("Error: %s is an invalid choice, choose a valid operation (1, 2, or 3)." % howToSniff)
			howToSniff = input("Enter your choice: ")
	#packetsSniffed.show()
	packetCount = 0 # Reset the global packet count - remove if we want to keep the count (which we probably will)
	return packetsSniffed

# Main loop of program, user can either sniff or quit program
def main():
	print("Network Sniffer")
	exist = True
	while exist:
		print("\nWould you like to-\n\tSniff: Sniff packets\n\tQuit: quit packet sniffer?")
		sniffOrQuit = input("Enter your choice [Sniff or Quit]: ")
		if sniffOrQuit.lower() == "sniff":
			packets = sniffer()
			#getDetails = True
			#while(getDetails):
				#getDetails = input("Would you like to get more information about any of the sniffed packets?(Pick 1 or 2)\n\t1: Yes\n\t2: No")
				# Need to implement getting details about already sniffed packets.
				# Use packets, and ask repeatedly ask User what packet and display until user says to stop
		elif sniffOrQuit.lower() == "quit":
			print("\nNetwork Sniffer has been terminated.")
			exist = False
		else:
			print("Error: %s is an invalid operation, choose a valid operation [Sniff or Quit]." % sniffOrQuit)
main()
