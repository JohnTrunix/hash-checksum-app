"""
This is an Tkinter App that hashes a file and compares it to a known hash.
You can select betwen MD5, SHA1, SHA256, SHA512 and BLAKE2b.
"""
import re
import hashlib
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
        APP_VERSION = ('1.0')
        self.title(f'File Hasher / Checksum Verifier (V{APP_VERSION})')
        self.iconbitmap('hash.ico')
        self.geometry('500x500')
        self.resizable(False, False)
        self.attributes('-topmost', True)
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)
        self.columnconfigure(2, weight=1)

        self.selected_file = None
        self.selected_hash = None
        self.checksum = None

        self.create_widgets()

    def create_widgets(self):
        """
        Create App Layout with all widgets
        """
        # File Selection Button
        self.select_file_button = ttk.Button(
            self, text='Select File', command=self.select_file)
        self.select_file_button.grid(
            row=0, column=0, columnspan=1, padx=20, pady=10, sticky='ew')

        # Hast Type Selection Dropdown
        self.hash_dropdown_options = [
            'SHA-256',
            'SHA-512',
            'SHA-1',
            'MD5'
        ]
        self.selected_hash_option = tk.StringVar()
        self.selected_hash_option.set(self.hash_dropdown_options[0])
        self.hash_dropdown = tk.OptionMenu(
            self, self.selected_hash_option, *self.hash_dropdown_options, command=self.get_selected_hash)
        self.hash_dropdown.grid(
            row=0, column=1, columnspan=2, padx=20, pady=10, sticky='ew')

        # File Textbox Title
        self.output_title = ttk.Label(self, text='File Path:')
        self.output_title.grid(
            row=1, column=0, columnspan=3, padx=20, sticky='ew')

        # File Path Textbox
        self.output_frame = tk.Text(
            self, state='disabled', height=3, width=50, font='Arial 10')
        self.output_frame.grid(row=2, column=0, columnspan=3,
                               padx=20, pady=10, sticky='ew')

        # Checksum Textbox Title
        self.checksum_title = ttk.Label(
            self, text='Type in your Checksum (optional):')
        self.checksum_title.grid(
            row=3, column=0, columnspan=3, padx=20, sticky='ew')

        # Checksum Input Textbox
        self.checksum_input = tk.Text(
            self, height=5, width=50, font='Arial 10')
        self.checksum_input.grid(
            row=4, column=0, columnspan=3, padx=20, pady=10, sticky='ew')

        # Quit Button
        self.quit_button = ttk.Button(self, text='Quit', command=self.destroy)
        self.quit_button.grid(row=5, column=0, columnspan=1,
                              padx=20, pady=10, sticky='ew')

        # Help Button
        self.help_button = ttk.Button(self, text='Help', command=self.help)
        self.help_button.grid(row=5, column=1, columnspan=1,
                              padx=20, pady=10, sticky='ew')

        # Check Button
        self.check_button = ttk.Button(
            self, text='Check', command=self.check)
        self.check_button.grid(
            row=5, column=2, columnspan=1,  padx=20, pady=10, sticky='ew')

        # Result Textbox
        self.result_frame = tk.Text(
            self, state='disabled', height=10, width=50, font='Arial 10')
        self.result_frame.grid(row=6, column=0, columnspan=3,
                               padx=20, pady=10, sticky='ew')

    def select_file(self):
        """
        Open File Dialog and select a file
        """
        file = askopenfilename()
        file = file.strip()
        self.output_frame.config(state='normal')
        self.output_frame.replace('1.0', 'end', file)
        self.output_frame.config(state='disabled')
        self.selected_file = file

    def get_selected_hash(self, choice):
        """
        Hash Dropdown changed
        """
        choice = self.selected_hash_option.get()
        self.selected_hash = choice

    def get_checksum(self):
        """
        Get Checksum from Input
        """
        self.checksum = self.checksum_input.get('1.0', 'end-1c')
        self.checksum = re.sub(r"[\n\t\s]*", "", self.checksum)
        if len(self.checksum) == 0:
            self.checksum = None

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
        self.get_selected_hash(self.selected_hash_option)
        if self.selected_file is not None:
            hash_value = None
            if self.selected_hash == 'SHA-256':
                hash_value = self.sha256_hash()
            elif self.selected_hash == 'SHA-512':
                hash_value = self.sha512_hash()
            elif self.selected_hash == 'SHA-1':
                hash_value = self.sha1_hash()
            elif self.selected_hash == 'MD5':
                hash_value = self.md5_hash()
            else:
                hash_value = 'No hash selected'

            self.result_frame.config(state='normal')
            if self.checksum is not None and hash_value != 'No hash selected':
                checksum_match = self.checksum == hash_value
                self.result_frame.replace(
                    '1.0', 'end', f'Hash Value ({self.selected_hash}): \n{hash_value} \n\nChecksum is identic: {checksum_match}')
            else:
                self.result_frame.replace(
                    '1.0', 'end', f'Hash Value ({self.selected_hash}): \n{hash_value}')
            self.result_frame.config(state='disabled')
        else:
            self.result_frame.config(state='normal')
            self.result_frame.replace('1.0', 'end', 'No file selected')
            self.result_frame.config(state='disabled')

    def sha256_hash(self):
        """
        SHA256 Hash
        """
        sha256_hash = hashlib.sha256()
        with open(self.selected_file, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b''):
                sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()

    def sha512_hash(self):
        """
        SHA512 Hash
        """
        sha512_hash = hashlib.sha512()
        with open(self.selected_file, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b''):
                sha512_hash.update(byte_block)
            return sha512_hash.hexdigest()

    def sha1_hash(self):
        """
        SHA1 Hash
        """
        sha1_hash = hashlib.sha1()
        with open(self.selected_file, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b''):
                sha1_hash.update(byte_block)
            return sha1_hash.hexdigest()

    def md5_hash(self):
        """
        MD5 Hash
        """
        md5_hash = hashlib.md5()
        with open(self.selected_file, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b''):
                md5_hash.update(byte_block)
            return md5_hash.hexdigest()


if __name__ == '__main__':
    app = Hasher()
    app.mainloop()
