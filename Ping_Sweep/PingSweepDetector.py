from scapy.all import sniff
import datetime
from tkinter import INSERT


class PingSweepDetector:

    def __init__(self, gui: None = None, ip_stats: dict[str, int] = {}):
        self.IP_ICMP_Stats = ip_stats  # Store the ICMP stats, if provided
        self.gui = gui  # store the GUI class instance, if provided

    def process_packets(self, packet):

        if packet.haslayer("ICMP"):

            # ICMP packet source IP
            icmp_src_ip = packet.getlayer('IP').src

            # Set the default value to zero, if it does not exist
            self.IP_ICMP_Stats.setdefault(icmp_src_ip, 0)

            # Increase the value of ICMP packets sent from a source IP
            self.IP_ICMP_Stats[icmp_src_ip] += 1

            # If ICMP messages pass a specific threshold
            if int(self.IP_ICMP_Stats[icmp_src_ip]) >= 3:

                # Record the time of event
                time_frame = datetime.datetime.now()
                time_frame = time_frame.strftime("%H:%M:%S - %d/%m/%Y")

                # Format the related message
                message = (f"\nTime of Event: [{time_frame}]\nPossible Ping Sweep attack detected\n"
                           f"It is possible that the machine with IP address:\n"
                           f"[{str(icmp_src_ip)}] is trying to identify active hosts on the network\n")

                # If GUI class instance is provided
                if self.gui:

                    # Record the event on the alert box on the GUI instance
                    self.gui.alert_textbox.config(state="normal")
                    self.gui.alert_textbox.insert(INSERT, message)
                    self.gui.alert_textbox.config(state="disabled")

                # Reset the ICMP counter to zero for the specific IP
                self.IP_ICMP_Stats[icmp_src_ip] = 0

if __name__ == '__main__':

    # Initialize the class instance
    psd = PingSweepDetector()

    # Sniff and process ICMP packets indefinitely
    sniff(count=0, store = 0, prn = psd.process_packets, filter="icmp")
