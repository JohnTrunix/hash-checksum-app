"""
Virustotal Page
"""

from configparser import ConfigParser
import tkinter as tk
from tkinter import ttk
from tkinter.filedialog import askopenfilename
import requests as r

from modules.popup import Popup
from modules.available_hashes import sha256_hash


class VirustotalPage(tk.Frame):
    """
    Hasher/Checksum Verifier Frame Config
    """

    def __init__(self, container):
        super().__init__(container)
        self.frame_padx: int = 20
        self.frame_pady: int = 20
        self.widget_padx: int = 10
        self.widget_pady: int = 10
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)
        self.columnconfigure(2, weight=1)
        self.columnconfigure(3, weight=1)
        self.columnconfigure(4, weight=1)

        self.filepath: str = None
        self.api_id_url: str = 'https://www.virustotal.com/api/v3/files/'
        self.result: dict = {}

        # Frame Configs
        self.filepath_frame: object = ttk.LabelFrame(
            self, text='File Path:')
        self.filepath_frame.grid(
            row=0, column=0, columnspan=5, padx=self.frame_padx, pady=self.frame_pady, sticky='ew')
        self.filepath_frame.columnconfigure(0, weight=1)
        self.filepath_frame.columnconfigure(1, weight=1)
        self.filepath_frame.columnconfigure(2, weight=1)
        self.filepath_frame.columnconfigure(3, weight=1)
        self.filepath_frame.columnconfigure(4, weight=1)

        self.filepath_textbox: object = tk.Text(
            self.filepath_frame, height=1)
        self.filepath_textbox.grid(row=0, column=0, columnspan=5, padx=self.widget_padx,
                                   pady=self.widget_pady, sticky='ew')

        self.clear_button: object = ttk.Button(
            self.filepath_frame, text='Clear', command=self.clear)
        self.clear_button.grid(
            row=1, column=2, padx=self.widget_padx, pady=self.widget_pady, sticky='ew')

        self.filepath_button: object = ttk.Button(
            self.filepath_frame, text='Browse', command=self.browse_file)
        self.filepath_button.grid(row=1, column=3, padx=self.widget_padx,
                                  pady=self.widget_pady, sticky='ew')

        self.get_report_button: object = ttk.Button(
            self.filepath_frame, text='Get Report', command=self.get_report)
        self.get_report_button.grid(
            row=1, column=4, padx=self.widget_padx, pady=self.widget_pady, sticky='ew')

        self.tree: object = ttk.Treeview(self, columns=(
            'flag', 'values'), show='headings')
        self.tree.heading('flag', text='Flag')
        self.tree.heading('values', text='Values')
        self.tree.column('values', anchor='center')
        self.tree.grid(row=1, column=0, columnspan=5, padx=self.frame_padx,
                       pady=self.frame_pady, sticky='ew')

        # General Buttons
        self.help_button: object = ttk.Button(
            self, text='Help', command=self.help)
        self.help_button.grid(
            row=2, column=3, padx=self.frame_padx, pady=self.frame_pady, sticky='ew')

        self.quit_button: object = ttk.Button(
            self, text='Quit', command=container.master.destroy)
        self.quit_button.grid(
            row=2, column=4, padx=(0, self.frame_padx), pady=self.frame_pady, sticky='ew')

    def help(self) -> None:
        """
        Help Button Function
        """
        Popup(
            1,
            'Help',
            'On this Tab you can calculate hashes of files and get online feedback from Virustotal. \n\nNote: You need to setup an API key in the settings.'
        ).create_popup()

    def clear(self) -> None:
        """
        Clear Button Function
        """
        self.filepath: str = None
        self.filepath_textbox.delete('1.0', 'end')
        self.tree.delete(*self.tree.get_children())

    def browse_file(self) -> None:
        """
        Browse for file
        """
        file_path = askopenfilename()
        if file_path:
            self.filepath_textbox.delete('1.0', 'end')
            self.filepath_textbox.insert('1.0', file_path)

    def get_report(self) -> None:
        """
        Hash file, post request and get report from virustotal
        """
        try:
            self.filepath: str = self.filepath_textbox.get(
                '1.0', 'end').strip()
            if self.filepath:
                config: object = ConfigParser()
                config.read('config.ini')
                api_key: str = config['MAIN']['api_key']
                hash_result: str = sha256_hash(self.filepath)
                response: dict = r.get(self.api_id_url + hash_result,
                                       headers={'x-apikey': api_key}, timeout=30)
                self.result: dict = response.json().get('data').get(
                    'attributes').get('last_analysis_stats')
                self.refresh_treeview()
            else:
                raise ValueError('No file selected')
        except (FileNotFoundError, ValueError):
            Popup(3, 'Error', 'Please enter a valid file path.').create_popup()

    def refresh_treeview(self) -> None:
        """
        Refresh treeview
        """
        self.tree.delete(*self.tree.get_children())
        for key, value in self.result.items():
            self.tree.insert('', 'end', values=(key, value))
