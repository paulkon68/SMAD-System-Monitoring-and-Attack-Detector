from tkinter import *
from tkinter import messagebox
from tkinter.scrolledtext import ScrolledText
import threading
from scapy.sendrecv import sniff
from UtilityController import UtilityController



class GUI:

    def __init__(self):

        """
        The Graphical User Interface of the SMAD Program
        """

        self.tool_state = {}  # Dictionary instance variable to store which utilities are enabled
        self.UC = None  # This will hold the instance of UtilityController
        self.start_b = None  # The "Start Detector" button
        self.export_b = None  # The export data button
        self.data = None  # The log data that will be exported
        self.sniff_thread = None  # The threading object

        self.window = Tk()  # The window of the gui object
        self.window.title("SMAD: System Monitoring & Attack Detector")
        self.window.minsize(width=1000, height=500)
        self.window.config(padx=20, pady=20)  # , bg=BLACK)
        self.raise_above_all()

        self.scrt = None  # ScrolledText object
        self.cst1 = None  # CheckButton Value 1 (Arp Poisoning Detector) [CheckButton State]
        self.cst2 = None  # CheckButton Value 2 (Ping Sweep Detector)
        self.cst3 = None  # CheckButton Value 3 (Deauth Detector)

        # state values
        self.cb1 = None  # Checkbutton objects
        self.cb2 = None
        self.cb3 = None

        # Objects comprising the GUI
        self.alert_textbox = None
        self.alert_label = None
        self.info_label = None

        # Setting up the GUI
        self.setup_labels()
        self.setup_buttons()
        self.setup_alert_area()
        self.window.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Window main loop listener
        self.window.mainloop()

    def on_closing(self):

        """
        This method is used when closing the window
        """

        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.window.destroy()

    def setup_labels(self) -> None:
        """
        Sets up the Labels used in the program
        :return: None
        """
        self.info_label = Label(text="Security Utilities", fg="#CAE1FF", bg="#007FFF", font=("ARIAL", 14, "bold"))
        self.info_label.grid(row=0, column=0)
        self.alert_label = Label(text="Alerts", fg="#CAE1FF", bg="#800000", font=("ARIAL", 14, "bold"))
        self.alert_label.grid(row=0, column=1)

    def checkbutton_used(self, button, util):
        """
        Changes the color of the words of the pressed buttons
        :param button: IntVar
        :param util: String
        :return: None
        """

        value = button.get()
        if util == "ARPD" and value:
            self.cb1.config(bg="lawngreen", fg="black")
            # start utility
            self.tool_state["ARP"] = 1

        elif util == "ARPD":
            self.cb1.config(bg="#383c4a", fg="white")
            # stop utility
            self.tool_state["ARP"] = 0
        if util == "PingS" and value:
            self.cb2.config(bg="lawngreen", fg="black")
            # start utility
            self.tool_state["PingS"] = 1

        elif util == "PingS":
            self.cb2.config(bg="#383c4a", fg="white")
            # stop utility
            self.tool_state["PingS"] = 0

        if util == "DeauthD" and value:
            self.cb3.config(bg="lawngreen", fg="black")
            # start utility
            self.tool_state["DeauthD"] = 1
        elif util == "DeauthD":
            self.cb3.config(bg="#383c4a", fg="white")
            # stop utility
            self.tool_state["DeauthD"] = 0

    def packet_sniffer(self):
        """
        This method is used to create instances of the utilities with the help of
        the UtilityController class.
        The self.tool_state specifies the utilities which will be used (user-specified)
        """

        self.UC = UtilityController(self, self.tool_state)

        # Captures and processes the packets using the joined_capture method of the UtilityController class instance
        sniff(count=0, store=0, prn=self.UC.joined_capture)


    def start_capture(self):
        """
        This method is used to create a thread that will be used to capture and process network packets
        """

        # Disable the buttons when capturing mode is enabled
        self.cb1.config(state="disabled")
        self.cb2.config(state="disabled")
        self.cb3.config(state="disabled")

        # Create the thread for packet capturing and processing
        self.sniff_thread = threading.Thread(target=self.packet_sniffer)

        # When the last non-daemon thread (e.g., the main thread) terminates, all daemon threads
        # are automatically killed.
        self.sniff_thread.daemon = True
        self.sniff_thread.start()

        # Disable the "Start Detector" button
        self.start_b.config(state="disabled")

    def export_data(self):

        """
        Exports data from the alert_box field of the GUI
        """

        # Store all data from the alert_box field of the GUI
        self.data = self.alert_textbox.get("1.0",END)
        with open("Attack_Log.txt", "w") as file:
            file.write(self.data)

    def setup_buttons(self):
        """
        Sets up the Buttons used in the program GUI
        :return: None
        """

        self.start_b = Button(text="Start Detector", width=20, highlightthickness=0,
                              command=self.start_capture, fg="black")
        self.start_b.grid(row=2, column=0)
        self.export_b = Button(text="Export Data", width=20, highlightthickness=0,
                              command=self.export_data, fg="black")
        self.export_b.grid(row=2, column=1)

        self.scrt = ScrolledText(self.window, width=30, height=10, state=DISABLED)
        self.scrt.grid(row=1, column=0)

        # Sets up the state variables for the utility buttons
        self.cst1 = IntVar()
        self.cst2 = IntVar()
        self.cst3 = IntVar()


        self.cb1 = Checkbutton(text="Arp Poisoning Detector", selectcolor="lawngreen", variable=self.cst1,
                               command=lambda: self.checkbutton_used(self.cst1, "ARPD"), activebackground='lawngreen',
                               highlightcolor='#7CFC00', activeforeground='black',
                               font=("ARIAL", 11, "bold"), offrelief="raised", overrelief="ridge", indicatoron=bool(0))
        self.cb2 = Checkbutton(text="Ping Sweep Detector", selectcolor="lawngreen", variable=self.cst2,
                               command=lambda: self.checkbutton_used(self.cst2, "PingS"), activebackground='lawngreen',
                               highlightcolor='#7CFC00', activeforeground='black',
                               font=("ARIAL", 11, "bold"), offrelief="raised", overrelief="ridge", indicatoron=bool(0))
        self.cb3 = Checkbutton(text="Wi-Fi Deauthentication Detector", selectcolor="lawngreen", variable=self.cst3,
                               command=lambda: self.checkbutton_used(self.cst3, "DeauthD"), activebackground='lawngreen',
                               highlightcolor='#7CFC00', activeforeground='black',
                               font=("ARIAL", 11, "bold"), offrelief="raised", overrelief="ridge", indicatoron=bool(0))

        # Place the buttons of the utilities inside the ScrolledText object
        self.scrt.window_create('end', window=self.cb1)
        self.scrt.window_create('end', window=self.cb2)
        self.scrt.window_create('end', window=self.cb3)
        self.scrt.insert('end', '\n')

    def setup_alert_area(self):
        """
        Sets up the Alert Area of the GUI
        """
        self.alert_textbox = ScrolledText(self.window,width=70, height=10, font=("ARIAL",12, "bold"), fg="brown3")
        self.alert_textbox.grid(row=1, column=1, pady = 10, padx = 30)
        self.alert_textbox.config(state="normal")
        self.alert_textbox.insert(INSERT, "")
        self.alert_textbox.config(state="disabled")

    def raise_above_all(self):

        """
        Raises the program window above all windows
        :return: None
        """

        '''
        win.attributes('-topmost', 1): This sets the window to be always on top of all other windows.
        win.attributes('-topmost', 0): This immediately resets the "topmost" attribute, making the window lose
        its always-on-top status but still remaining in front of other windows momentarily.
        '''

        self.window.attributes('-topmost', 1)
        self.window.attributes('-topmost', 0)


if __name__ == '__main__':
    win = GUI()
