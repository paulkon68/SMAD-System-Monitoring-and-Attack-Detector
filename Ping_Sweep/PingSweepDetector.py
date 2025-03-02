from scapy.all import sniff
import datetime
from tkinter import INSERT


class PingSweepDetector:

    def __init__(self, gui: None = None, ip_stats: dict[str, int] = {}):
        self.IP_ICMP_Stats = ip_stats  # Store the ICMP stats, if provided
        self.gui = gui  # store the GUI class instance, if provided
        self.start_time = 0
        self.help_check_time = 0

    def process_packets(self, packet):

        # Filter for ICMP request packets
        if packet.haslayer("ICMP") and packet.getlayer("ICMP").type == 8:

            # ICMP packet source IP
            icmp_src_ip = packet.getlayer('IP').src

            # Set the default value to zero, if it does not exist
            self.IP_ICMP_Stats.setdefault(icmp_src_ip, 0)

            # ---

            # Check if the ping request time frame is bigger than 30 seconds, reset the counter

            if self.help_check_time == 0:
                self.start_time = datetime.datetime.now()
                self.help_check_time = 1

            y = datetime.datetime.now()
            print(f"y: {y}, start_time: {self.start_time}, {self.IP_ICMP_Stats[icmp_src_ip]}")

            if (y - self.start_time).seconds > 30:
                self.IP_ICMP_Stats[icmp_src_ip] = 0
                self.start_time = y

            # ---

            # Increase the value of ICMP packets sent from a source IP
            self.IP_ICMP_Stats[icmp_src_ip] += 1

            # If ICMP messages pass a specific limit
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
