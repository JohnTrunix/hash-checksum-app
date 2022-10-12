"""
Virustotal Page
"""

from configparser import ConfigParser
import tkinter as tk
from tkinter import ttk
from tkinter.filedialog import askopenfilename
import matplotlib.pyplot as plt
import requests as r
from modules.available_hashes import sha256_hash


class VirustotalPage(tk.Frame):
    """
    Hasher/Checksum Verifier Frame Config
    """

    def __init__(self, container):
        super().__init__(container)
        self.frame_padx = 20
        self.frame_pady = 20
        self.widget_padx = 10
        self.widget_pady = 10
        self.columnconfigure(0, weight=1)

        # Frame Configs
        self.filepath_frame = ttk.LabelFrame(
            self, text='File Path:')
        self.filepath_frame.grid(
            row=0, column=0, padx=self.frame_padx, pady=self.frame_pady, sticky='ew')
        self.filepath_frame.columnconfigure(0, weight=1)
        self.filepath_frame.columnconfigure(1, weight=1)
        self.filepath_frame.columnconfigure(2, weight=1)

        self.filepath_textbox = tk.Text(
            self.filepath_frame, height=1)
        self.filepath_textbox.grid(row=0, column=0, columnspan=3, padx=self.widget_padx,
                                   pady=self.widget_pady, sticky='ew')

        self.filepath_button = ttk.Button(
            self.filepath_frame, text='Browse', command=self.browse_file)
        self.filepath_button.grid(row=1, column=0, padx=self.widget_padx,
                                  pady=self.widget_pady, sticky='ew')

        self.get_report_button = ttk.Button(
            self.filepath_frame, text='Get Report', command=self.get_report)
        self.get_report_button.grid(
            row=1, column=1, padx=self.widget_padx, pady=self.widget_pady, sticky='ew')

        self.quit_button = ttk.Button(
            self.filepath_frame, text='Quit', command=container.master.destroy)
        self.quit_button.grid(
            row=1, column=2, padx=self.widget_padx, pady=self.widget_pady, sticky='ew')

    def get_report(self):
        """
        Hash file, post request and get report from virustotal
        """
        config = ConfigParser()
        config.read('config.ini')
        api_key = config['main_settings']['api_key']
        filepath = self.filepath_textbox.get('1.0', 'end').strip()
        hash_result = sha256_hash(filepath)
        response = r.get('https://www.virustotal.com/api/v3/files/' +
                         hash_result, headers={'x-apikey': api_key}, timeout=30)
        result = response.json().get('data').get(
            'attributes').get('last_analysis_stats')
        labels = result.keys()
        sizes = result.values()
        self.plot(labels, sizes)

    def plot(self, labels, sizes):
        """
        Plot Bar Chart with labels and save as png
        """
        # dict_keys(['harmless', 'type-unsupported', 'suspicious', 'confirmed-timeout', 'timeout', 'failure', 'malicious', 'undetected'])
        # dict_values([0, 4, 0, 0, 0, 0, 0, 72])
        # create plot and safe as png
        print(labels, sizes)
        plt.bar(labels, sizes)
        plt.savefig('plot.png')

    def browse_file(self):
        """
        Browse for file
        """
        file_path = askopenfilename()
        if file_path is not None:
            self.filepath_textbox.delete('1.0', 'end')
            self.filepath_textbox.insert('1.0', file_path)
