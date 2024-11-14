from scapy.all import sniff
import datetime
from scapy.layers.dot11 import Dot11Deauth
from tkinter import INSERT

# https://www.researchgate.net/publication/343472668_Practically_Detecting_WiFi_Deauthentication_Attack_80211_Deauth_Packets_using_Python_and_Scapy

class DeauthDetector:

    def __init__(self, gui: None = None):

        # Create an instance variable containing the GUI class instance
        self.gui = gui


    def process_packets(self, pkt):

        # If the packet has a De-authentication Layer
        if pkt.haslayer(Dot11Deauth):

            # Record the time of event
            time_frame = datetime.datetime.now()
            time_frame = time_frame.strftime("%H:%M:%S - %d/%m/%Y")

            # Format the related message
            message = (f"\nTime of Event: [{time_frame}]\nPossible Deauthentication attack detected\n"
                       f"Attacking Machine's IP is: {pkt.getlayer} and the target system is: {pkt.addr2}\n"
                       )

            # If GUI class instance is provided
            if self.gui:
                # Record the event on the alert box on the GUI instance
                self.gui.alert_textbox.config(state="normal")
                self.gui.alert_textbox.insert(INSERT, message)
                self.gui.alert_textbox.config(state="disabled")
            else:
                return message

if __name__ == '__main__':

    # Initialize the class instance
    deauth_det = DeauthDetector()

    # Sniff and process Deauth packets indefinitely
    sniff(count=0, store = 0, prn = deauth_det.process_packets)
