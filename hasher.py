"""
This is an Tkinter App that hashes a file and compares it to a known hash.
You can select betwen MD5, SHA1, SHA256, SHA512 and BLAKE2b.
"""
import re
import hashlib
import requests as r
import tkinter as tk
from tkinter import ttk
from tkinter.filedialog import askopenfilename
from tkinter.messagebox import showinfo


class Hasher(tk.Tk):
    """
    Tkinter App
    """

    def __init__(self):
        super().__init__()
        # App Version
        APP_VERSION = ('1.0')

        # Tkinter Window Settings
        self.title(f'File Hasher / Checksum Verifier (V{APP_VERSION})')
        self.iconbitmap('hash.ico')
        self.geometry('600x500')
        self.resizable(False, False)
        self.attributes('-topmost', True)

        # Notebook Settings
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill='both', expand=True)
        self.frame_home = ttk.Frame(self.notebook)
        self.frame_virustotal = ttk.Frame(self.notebook)
        self.frame_home.pack(fill='both', expand=True)
        self.frame_virustotal.pack(fill='both', expand=True)
        self.notebook.add(self.frame_home, text='Hash Checker / Verifier')
        self.notebook.add(self.frame_virustotal, text='VirusTotal Scan')

        # Column Settings
        self.frame_home.columnconfigure(0, weight=1)
        self.frame_home.columnconfigure(1, weight=1)
        self.frame_home.columnconfigure(2, weight=1)
        self.frame_virustotal.columnconfigure(0, weight=1)
        self.frame_virustotal.columnconfigure(1, weight=1)
        self.frame_virustotal.columnconfigure(2, weight=1)

        # Variables
        self.home_selected_file = None
        self.home_selected_hash = None
        self.home_checksum = None

        self.virustotal_selected_file = None
        self.virustotal_api_key = None

        self.create_home_frame_widgets()
        self.create_virustotal_frame_widgets()

    def create_home_frame_widgets(self):
        """
        Hashing and Checksum Frame
        """
        # File Selection Button
        self.home_select_file_button = ttk.Button(
            self.frame_home, text='Select File', command=self.select_file)
        self.home_select_file_button.grid(
            row=0, column=0, columnspan=1, padx=20, pady=10, sticky='ew')

        # Hast Type Selection Dropdown
        self.home_hash_dropdown_options = [
            'SHA-256',
            'SHA-512',
            'SHA-1',
            'MD5'
        ]
        self.home_selected_hash_option = tk.StringVar()
        self.home_selected_hash_option.set(self.home_hash_dropdown_options[0])
        self.home_hash_dropdown = tk.OptionMenu(
            self.frame_home, self.home_selected_hash_option, *self.home_hash_dropdown_options, command=self.get_selected_hash)
        self.home_hash_dropdown.grid(
            row=0, column=1, columnspan=2, padx=20, pady=10, sticky='ew')

        # File Textbox Title
        self.home_output_title = ttk.Label(self.frame_home, text='File Path:')
        self.home_output_title.grid(
            row=1, column=0, columnspan=3, padx=20, sticky='ew')

        # File Path Textbox
        self.home_output_frame = tk.Text(
            self.frame_home, state='disabled', height=1, width=50, font='Arial 10')
        self.home_output_frame.grid(row=2, column=0, columnspan=3,
                                    padx=20, pady=10, sticky='ew')

        # Checksum Textbox Title
        self.home_checksum_title = ttk.Label(
            self.frame_home, text='Type in your Checksum (optional):')
        self.home_checksum_title.grid(
            row=3, column=0, columnspan=3, padx=20, sticky='ew')

        # Checksum Input Textbox
        self.home_checksum_input = tk.Text(
            self.frame_home, height=5, width=50, font='Arial 10')
        self.home_checksum_input.grid(
            row=4, column=0, columnspan=3, padx=20, pady=10, sticky='ew')

        # Quit Button
        self.home_quit_button = ttk.Button(
            self.frame_home, text='Quit', command=self.destroy)
        self.home_quit_button.grid(row=5, column=0, columnspan=1,
                                   padx=20, pady=10, sticky='ew')

        # Help Button
        self.home_help_button = ttk.Button(
            self.frame_home, text='Help', command=self.help)
        self.home_help_button.grid(row=5, column=1, columnspan=1,
                                   padx=20, pady=10, sticky='ew')

        # Check Button
        self.home_check_button = ttk.Button(
            self.frame_home, text='Check', command=self.check)
        self.home_check_button.grid(
            row=5, column=2, columnspan=1,  padx=20, pady=10, sticky='ew')

        # Result Textbox
        self.home_result_frame = tk.Text(
            self.frame_home, state='disabled', height=10, width=50, font='Arial 10')
        self.home_result_frame.grid(row=6, column=0, columnspan=3,
                                    padx=20, pady=10, sticky='ew')

    def create_virustotal_frame_widgets(self):
        """
        Virustoal Frame
        """
        # API Key Textbox Title
        self.virustotal_api_key_title = ttk.Label(
            self.frame_virustotal, text='Virustotal API Key:')
        self.virustotal_api_key_title.grid(
            row=0, column=0, columnspan=3, padx=20, pady=(20, 0), sticky='ew')

        # API Key Textbox
        self.virustotal_api_key_frame = tk.Text(
            self.frame_virustotal, state='normal', height=1, width=50, font='Arial 10')
        self.virustotal_api_key_frame.grid(row=1, column=0, columnspan=3,
                                           padx=20, pady=(0, 20), sticky='ew')

        # File Path Textbox
        self.virustotal_output_frame = tk.Text(
            self.frame_virustotal, state='disabled', height=1, width=50, font='Arial 10')
        self.virustotal_output_frame.grid(row=2, column=0, columnspan=3,
                                          padx=20, sticky='ew')

        # File Selection Button
        self.virustotal_select_file_button = ttk.Button(
            self.frame_virustotal, text='Select File', command=self.select_file)
        self.virustotal_select_file_button.grid(
            row=3, column=0, columnspan=1, padx=20, pady=10, sticky='ew')

        # Request Full Scan Button
        self.virustotal_request_full_scan_button = ttk.Button(
            self.frame_virustotal, text='Request Scan', command=self.request_fullscan)
        self.virustotal_request_full_scan_button.grid(
            row=3, column=1, columnspan=1, padx=20, pady=10, sticky='ew')

        # Request Hash Check Button
        self.virustotal_request_hash_check_button = ttk.Button(
            self.frame_virustotal, text='Request Hash Check', command=self.request_hash_check)
        self.virustotal_request_hash_check_button.grid(
            row=3, column=2, columnspan=1, padx=20, pady=10, sticky='ew')

        # Result Textbox
        self.virustotal_result_frame = tk.Text(
            self.frame_virustotal, state='disabled', height=15, width=50, font='Arial 10')
        self.virustotal_result_frame.grid(
            row=4, column=0, columnspan=3, padx=20, pady=10, sticky='ew')

        # Quit Button
        self.virustotal_quit_button = ttk.Button(
            self.frame_virustotal, text='Quit', command=self.destroy)
        self.virustotal_quit_button.grid(row=10, column=2, columnspan=1,
                                         padx=20, pady=10, sticky='ew')

    def select_file(self):
        """
        Open File Dialog and select a file
        """
        file = askopenfilename()
        file = file.strip()
        if self.notebook.tab(self.notebook.select(), 'text') == 'Hash Checker / Verifier':
            self.home_output_frame.config(state='normal')
            self.home_output_frame.replace('1.0', 'end', file)
            self.home_output_frame.config(state='disabled')
            self.home_selected_file = file
        elif self.notebook.tab(self.notebook.select(), 'text') == 'VirusTotal Scan':
            self.virustotal_output_frame.config(state='normal')
            self.virustotal_output_frame.replace('1.0', 'end', file)
            self.virustotal_output_frame.config(state='disabled')
            self.virustotal_selected_file = file
        else:
            pass

    def get_selected_hash(self, choice):
        """
        Hash Dropdown changed
        """
        choice = self.home_selected_hash_option.get()
        self.home_selected_hash = choice

    def get_checksum(self):
        """
        Get Checksum from Input
        """
        self.home_checksum = self.home_checksum_input.get('1.0', 'end-1c')
        self.home_checksum = re.sub(r"[\n\t\s]*", "", self.home_checksum)
        if len(self.home_checksum) == 0:
            self.home_checksum = None

    def help(self):
        """
        Help Popup
        """
        showinfo(
            'Help', 'This is an Tkinter App that can hash a file and compare it to a Checksum')

    def check(self):
        """
        Hash selected file and compare it to the Checksum (optional)
        """
        self.get_checksum()
        self.get_selected_hash(self.home_selected_hash_option)
        if self.home_selected_file is not None:
            hash_value = None
            if self.home_selected_hash == 'SHA-256':
                hash_value = self.sha256_hash(self.home_selected_file)
            elif self.home_selected_hash == 'SHA-512':
                hash_value = self.sha512_hash(self.home_selected_file)
            elif self.home_selected_hash == 'SHA-1':
                hash_value = self.sha1_hash(self.home_selected_file)
            elif self.home_selected_hash == 'MD5':
                hash_value = self.md5_hash(self.home_selected_file)
            else:
                hash_value = 'No hash selected'

            self.home_result_frame.config(state='normal')
            if self.home_checksum is not None and hash_value != 'No hash selected':
                home_checksum_match = self.home_checksum == hash_value
                self.home_result_frame.replace(
                    '1.0', 'end', f'Hash Value ({self.home_selected_hash}): \n{hash_value} \n\nChecksum is identic: {home_checksum_match}')
            else:
                self.home_result_frame.replace(
                    '1.0', 'end', f'Hash Value ({self.home_selected_hash}): \n{hash_value}')
            self.home_result_frame.config(state='disabled')
        else:
            self.home_result_frame.config(state='normal')
            self.home_result_frame.replace('1.0', 'end', 'No file selected')
            self.home_result_frame.config(state='disabled')

    def request_fullscan(self):
        """
        Request a VirusTotal Scan
        """
        pass

    def request_hash_check(self):
        """
        Request a VirusTotal Hash Check
        """
        self.virustotal_api_key = self.virustotal_api_key_frame.get(
            '1.0', 'end-1c')
        self.virustotal_api_key = re.sub(
            r"[\n\t\s]*", "", self.virustotal_api_key)
        if len(self.virustotal_api_key) == 0:
            self.virustotal_api_key = None
            self.virustotal_result_frame.config(state='normal')
            self.virustotal_result_frame.replace(
                '1.0', 'end', 'No VirusTotal API Key provided')
            self.virustotal_result_frame.config(state='disabled')

        elif self.virustotal_selected_file is not None:
            file_hash = self.sha256_hash(self.virustotal_selected_file)
            response = r.get('https://www.virustotal.com/api/v3/files/' +
                             file_hash, headers={'x-apikey': self.virustotal_api_key}, timeout=30)
            if response.status_code == 200:
                result = response.json().get('data').get(
                    'attributes').get('last_analysis_stats')
                # create variable for result with all values per row
                result = f'harmless: {result["harmless"]}\ntype-unsupported: {result["type-unsupported"]}\nsuspicious: {result["suspicious"]}\nconfirmed-timeout: {result["confirmed-timeout"]}\ntimeout: {result["timeout"]}\nfailure: {result["failure"]}\nmalicious: {result["malicious"]}\nundetected: {result["undetected"]}'

                self.virustotal_result_frame.config(state='normal')
                self.virustotal_result_frame.replace(
                    '1.0', 'end', result)
                self.virustotal_result_frame.config(state='disabled')
            else:
                self.virustotal_result_frame.config(state='normal')
                self.virustotal_result_frame.replace(
                    '1.0', 'end', 'Error while requesting VirusTotal')
                self.virustotal_result_frame.config(state='disabled')
        else:
            self.virustotal_result_frame.config(state='normal')
            self.virustotal_result_frame.replace(
                '1.0', 'end', 'No file selected')
            self.virustotal_result_frame.config(state='disabled')

    def sha256_hash(self, path):
        """
        SHA256 Hash
        """
        sha256_hash = hashlib.sha256()
        with open(path, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b''):
                sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()

    def sha512_hash(self, path):
        """
        SHA512 Hash
        """
        sha512_hash = hashlib.sha512()
        with open(path, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b''):
                sha512_hash.update(byte_block)
            return sha512_hash.hexdigest()

    def sha1_hash(self, path):
        """
        SHA1 Hash
        """
        sha1_hash = hashlib.sha1()
        with open(path, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b''):
                sha1_hash.update(byte_block)
            return sha1_hash.hexdigest()

    def md5_hash(self, path):
        """
        MD5 Hash
        """
        md5_hash = hashlib.md5()
        with open(path, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b''):
                md5_hash.update(byte_block)
            return md5_hash.hexdigest()


if __name__ == '__main__':
    app = Hasher()
    app.mainloop()
