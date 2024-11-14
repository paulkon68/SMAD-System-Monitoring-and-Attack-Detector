from scapy.all import sniff
import datetime
from tkinter import INSERT


class ArpPoisoningDetector:

	def __init__(self, gui: None = None, MAC_Mapping: dict[str, str] = {}):

		# Store the IP - MAC mappings so that any other mappings discovered in packets would be considered an anomaly
		self.IP_MAC_Map = MAC_Mapping
		# Create an instance variable containing the GUI class instance
		self.gui = gui

	def process_packets(self, packet):

		# If the packet has ARP layer
		if packet.haslayer("ARP"):

			# Retrieve the source IP from ARP packet
			src_IP = packet['ARP'].psrc

			# Retrieve the source MAC address sending the ARP packet
			src_MAC = packet['Ether'].src

			# Check if the source MAC address exists in the IP_MAC_Map dictionary
			if src_MAC in self.IP_MAC_Map.keys():

				# If it exists, check the mapping.
				# Wrong mapping could indicate ARP Spoofing / MITM Attack
				try:
					# If the mapping isn't correct
					if self.IP_MAC_Map[src_MAC] != src_IP :
						# Retrieve the attacker's IP
						old_IP = self.IP_MAC_Map[src_MAC]

						# Record the time of event
						time_frame = datetime.datetime.now()
						time_frame = time_frame.strftime("%H:%M:%S - %d/%m/%Y")

						# Format the related message
						message = (f"\nTime of Event: [{time_frame}]\nPossible ARP Poisoning attack detected\n"
								   f"It is possible that the machine with IP address:\n"
								   f"[{str(old_IP)}] is pretending to be {str(src_IP)}\n")

						# If GUI class instance is provided
						if self.gui:
							# Record the event on the alert box on the GUI instance
							self.gui.alert_textbox.config(state="normal")
							self.gui.alert_textbox.insert(INSERT, message)
							self.gui.alert_textbox.config(state="disabled")

				except KeyError:
					message = f"\nError: Mapping was not defined\n"

			else:
				# If MAC-IP mapping was not found, add it to the dictionary
				self.IP_MAC_Map[src_MAC] = src_IP

if __name__ == '__main__':

	# Initialize the class instance
	arp_p_det = ArpPoisoningDetector()

	# Sniff and process ARP Protocol packets indefinitely
	sniff(count=0, filter="arp", store = 0, prn = arp_p_det.process_packets)
