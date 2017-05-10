#! /usr/bin/env python3
# Prevent scapy from throwing IPv6 ERROR
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# import scapy library
from scapy.all import *

# Customize the output to be more readable
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

def getHowToSniff():
	print("\nWould you like to-\n\t1: Choose how many packets to sniff\n\t2: Choose how long sniffer runs\n\t3: Choose both how many packets to sniff and how long")
	howToSniff = input("Enter your choice 1, 2, or 3(Stops when either option is acheived): ")
	if not howToSniff.isdigit() or int(howToSniff) > 3 or int(howToSniff) < 1:
		while not howToSniff.isdigit() or int(howToSniff) > 3 or int(howToSniff) < 1:
			print("Error: %s is an invalid sniffing option, choose a valid option (1, 2, or 3)." % howToSniff)
			howToSniff = input("Enter new choice: ")
	return howToSniff

def getOutputSettings():
	outputSetting = input("\nSelect Output Settings:\n\t1: Raw Output\n\t2: Readable Output (Only IP Connections)\n\t3: Detailed Output\n Output Choice: ")  # Ask user if they want raw output or an easier to read output
	if not outputSetting.isdigit() or int(outputSetting) > 3 or int(outputSetting) < 1:
		while not outputSetting.isdigit() or int(outputSetting) > 3 or int(outputSetting) < 1:
			print("Error: %s is an invalid output setting option, choose a valid option (1, 2, or 3)." % outputSetting)
			outputSetting = input("Enter new output setting option: ")
	return outputSetting
	

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
	
	# Check how user wants to sniff packets
	howToSniff =  getHowToSniff()
	
	# Check how user wants to have output
	outputSetting = getOutputSettings()
	
	# Loop until Sniff is complete 
	while hasntSniffed:
		global packetCount
		howToSniff = int(howToSniff)	# Determine which option user chose
		
		# Sniff certain amount of packets
		if howToSniff == 1:
			numPackets = input("\nHow many packets would you like to sniff? ")
			if numPackets.isdigit():
				print("\n...Sniffing...\n")
				# Output style depending on user input
				if int(outputSetting) == 1:
					packetsSniffed = sniff(count=int(numPackets))
					packetsSniffed.nsummary()
				elif int(outputSetting) == 2:
					packetsSniffed = sniff(count=int(numPackets), filter="ip", prn=customOutput)
				else:
					packetsSniffed = sniff(count=int(numPackets), prn=customOutput2)
				packetCount = 0
				hasntSniffed = False
			else:
				print("Error: %s is not a digit" % numPackets)
				howToSniff = str(howToSniff)
		
		# Sniff for a certain amount of time
		elif howToSniff == 2:
			timeToSniff = input("\nHow long would you like to sniff packets? ")
			if(timeToSniff.isdigit()):
				print("\n...Sniffing...\n")
				if int(outputSetting) == 1:
					packetsSniffed = sniff(timeout=int(timeToSniff))
					packetsSniffed.nsummary()
				elif int(outputSetting) == 2:
					packetsSniffed = sniff(timeout=int(timeToSniff), filter="ip", prn=customOutput)
				else:
					packetsSniffed = sniff(timeout=int(timeToSniff), prn=customOutput2)
				packetCount = 0
				hasntSniffed = False
			else:
				print("Error: %s is not a digit" % timeToSniff)
				howToSniff = str(howToSniff)
		
		# Sniff for either a certain amount of packets or time
		elif howToSniff == 3:
			numPackets = input("\nHow many packets would you like to sniff? ")
			timeToSniff = input("How long would you like to sniff packets? ")
			if(numPackets.isdigit() and timeToSniff.isdigit()):
				print("\n...Sniffing...\n")
				if int(outputSetting) == 1:
					packetsSniffed = sniff(count=int(numPackets), timeout=int(timeToSniff))
					packetsSniffed.nsummary()
				elif int(outputSetting) == 2:
					packetsSniffed = sniff(count=int(numPackets), filter="ip", timeout=int(timeToSniff), prn=customOutput)
				else:
					packetsSniffed = sniff(count=int(numPackets), prn=customOutput2)
				packetCount = 0
				hasntSniffed = False
			else:
				print("Error: Either %s or %s is not a digit" % (numPackets, timeToSniff))
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
			print("\n...Choose Sniffer Settings...")
			packets = sniffer()
			wrpcap('sniffed.pcap', packets)
			print("\n...Sniffing Done...")			
			wantDetails = True
			while(wantDetails):
				# Getting details about already sniffed packets.
				wantDetails = input("Would you like to get more information about any of the sniffed packets?\n\t1: Yes\n\t2: No\n(Pick 1 or 2): ")
				if not wantDetails.isdigit() or int(wantDetails) > 2 or int(wantDetails) < 1:
					while not wantDetails.isdigit() or int(wantDetails) > 2 or int(wantDetails) < 1:
						print("Error: %s is an invalid option, choose a valid option (1 or 2)." % wantDetails)
						wantDetails = input("Enter new output setting option: ")
				if int(wantDetails) == 1:
					whatPacket = input("Enter the packet # that you want details on(Range 1 - %d: " % len(packets))
					if not whatPacket.isdigit() or int(whatPacket) > len(packets) or int(whatPacket) < 1:
						while not whatPacket.isdigit() or int(whatPacket) > len(packets) or int(whatPacket) < 1:
							print("Error: %s is an invalid option, choose a valid option (range 1 to %d)." % (whatPacket, len(packets)))
							whatPacket = input("Enter new output setting option: ")
					packets[int(whatPacket)-1].show()
				else:
					wantDetails = False

		elif sniffOrQuit.lower() == "quit":
			print("\nNetwork Sniffer has been terminated.")
			exist = False
		else:
			print("Error: %s is an invalid operation, choose a valid operation [Sniff or Quit]." % sniffOrQuit)
main()
