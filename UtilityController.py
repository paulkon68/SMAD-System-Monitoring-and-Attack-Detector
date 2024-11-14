from ARP.ArpPoisoningDetector import ArpPoisoningDetector
from Ping_Sweep.PingSweepDetector import PingSweepDetector
from Deauth.DeauthDetector import DeauthDetector


class UtilityController:

    """
    This class is responsible for initializing the utilities used in the GUI class instance based on
    a dictionary provided.
    The dictionary utility_dict specifies which utility classes should be initialized based on the preference of the
    user.
    """

    def __init__(self, gui, utility_dict: dict[str, int]):
        self.arppd = None
        self.pingsd = None
        self.deauthd = None
        self.ud = utility_dict

        # Create class instances of the utilities
        try:
            if utility_dict["ARP"]:
                self.arppd = ArpPoisoningDetector(gui)
        except KeyError:
            pass
        try:
            if utility_dict["PingS"]:
                self.pingsd = PingSweepDetector(gui)
        except KeyError:
            pass
        try:
            if utility_dict["DeauthD"]:
                self.deauthd = DeauthDetector(gui)
        except KeyError:
            pass

    def joined_capture(self, pkt):

        """
        This method is used for processing the packets and detecting the attacks based on the detectors specified
        by the user in the GUI
        """

        # The process_packets methods of all selected utilities are called to process the packets
        try:
            if self.ud["ARP"]:
                self.arppd.process_packets(pkt)
        except KeyError:
            pass
        try:
            if self.ud["PingS"]:
                self.pingsd.process_packets(pkt)
        except KeyError:
            pass
        try:
            if self.ud["DeauthD"]:
                self.deauthd.process_packets(pkt)
        except KeyError:
            pass
