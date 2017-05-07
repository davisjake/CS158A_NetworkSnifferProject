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
	return "Packet #%s: [Type] %s/%s [Source] %s ===> [Destination] %s" % (packetCount, packet.getlayer(1).name, packet.getlayer(2).name, packet[0][1].src, packet[0][1].dst)

def customOutput2(packet):
	global packetCount
	packetCount += 1
	print("Packet #", packetCount)
	packet.show()
	print("\n")



# Sniffer will ask user how they want packets over netowork scanned
# User can choose to:
#	1 Choose how many packets to sniff
#	2 Choose how long to sniff packets
#	3 Choose both how many packets to sniff or how long to sniff  packets
#		* Option 3 will stop sniffing when either time is up or number of packets to sniff is reached
def sniffer():
	#if(input("Would you like to sniff packets filtered or unfiltered?").lower() == 'filtered'): filtered = True
	#else: filtered = False			//Need to implement filtering (Use sniff(filter="UserDefinedFilter")
	hasntSniffed = True		# Loop while method hasn't sniffed
	print("\nWould you like to-\n\t1: Choose how many packets to sniff\n\t2: Choose how long sniffer runs\n\t3: Choose both how many packets to sniff and how long")
	howToSniff = input("Enter your choice 1 [# of Packets], 2 [Amount of Time], or 3 [Both Options(Stops when either option is acheived)]: ")
	if not howToSniff.isdigit() or int(howToSniff) > 3 or int(howToSniff) < 1:
		while not howToSniff.isdigit() or int(howToSniff) > 3 or int(howToSniff) < 1:
			print("Error: %s is an invalid sniffing option, choose a valid option (1, 2, or 3)." % howToSniff)
			howToSniff = input("Enter new choice: ")
	outputSetting = input("\nOutput Settings:\n\t1: Raw Output\n\t2: Readable Output\n\t3: Detailed Output\n Output Choice: ")  # Ask user if they want raw output or an easier to read output
	if not outputSetting.isdigit() or int(outputSetting) > 3 or int(outputSetting) < 1:
		while not outputSetting.isdigit() or int(outputSetting) > 3 or int(outputSetting) < 1:
			print("Error: %s is an invalid output setting option, choose a valid option (1 or 2)." % outputSetting)
			outputSetting = input("Enter new output setting option: ")
	while hasntSniffed:
		global packetCount
		howToSniff = int(howToSniff)	# Determine which option user chose
		# Sniff certain amount of packets
		if howToSniff == 1:
			print("\n...")
			numPackets = input("\nHow many packets would you like to sniff? ")
			if numPackets.isdigit():
				# Output style depending on user input
				if int(outputSetting) == 1:
					packetsSniffed = sniff(count=int(numPackets))
					packetsSniffed.nsummary()
				elif int(outputSetting) == 2:
					packetsSniffed = sniff(count=int(numPackets), prn=customOutput)
				elif int(outputSetting) == 3:
					packetsSniffed = sniff(count=int(numPackets), prn=customOutput2)
				print("\n...")
				packetCount = 0
				hasntSniffed = False
			else:
				print("Error: %s is not a digit" % numPackets)
				howToSniff = str(howToSniff)
		# Sniff for a certain amount of time
		elif howToSniff == 2:
			print("\n...")
			timeToSniff = input("\nHow long would you like to sniff packets? ")
			if(timeToSniff.isdigit()):
				packetsSniffed = sniff(timeout=int(timeToSniff))
				hasntSniffed = False
			else:
				print("Error: %s is not a digit" % timeToSniff)
				howToSniff = str(howToSniff)
			if(timeToSniff.isdigit()):
				# Output style depending on user input
				if int(outputSetting) == 1:
					packetsSniffed = sniff(timeout=int(timeToSniff))
					packetsSniffed.nsummary()
				elif int(outputSetting) == 2:
					packetsSniffed = sniff(timeout=int(timeToSniff), prn=customOutput)
				print("\n...")
				packetCount = 0
				hasntSniffed = False
		# Sniff for either a certain amount of packets or time
		elif howToSniff == 3:
			print("\n...")
			numPackets = input("\nHow many packets would you like to sniff? ")
			timeToSniff = input("How long would you like to sniff packets? ")
			if(numPackets.isdigit() and timeToSniff.isdigit()):
				# Output style depending on user input
				if int(outputSetting) == 1:
					packetsSniffed = sniff(count=int(numPackets), timeout=int(timeToSniff))
					packetsSniffed.nsummary()
				elif int(outputSetting) == 2:
					packetsSniffed = sniff(count=int(numPackets), timeout=int(timeToSniff), prn=customOutput)
				print("\n...")
				packetCount = 0
				hasntSniffed = False
			else:
				print("Error: %s or %s is not a digit" % (numPackets, timeToSniff))
				howToSniff = str(howToSniff)		
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
			sniffer() #packets =
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
