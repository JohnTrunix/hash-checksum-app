"""
Hash and Checksum Validator Page
"""
import tkinter as tk
from tkinter import ttk
from tkinter.filedialog import askopenfilename

from modules.popup import Popup
from modules.available_hashes import *


class HashValidatorPage(tk.Frame):
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

        self.filepath: str = None
        self.checksum: str = None
        self.hash_algorithm: str = None
        self.hash_result: str = None
        self.checksum_result: str = None

        # Frame Configs
        self.fh_filepath_frame: object = ttk.LabelFrame(
            self, text='File Path:')
        self.fh_filepath_frame.grid(
            row=0, column=0, padx=self.frame_padx, pady=self.frame_pady, sticky='ew')
        self.fh_filepath_frame.columnconfigure(0, weight=10)
        self.fh_filepath_frame.columnconfigure(1, weight=1)

        self.fh_checksum_frame: object = ttk.LabelFrame(
            self, text='Checksum (optional):')
        self.fh_checksum_frame.grid(
            row=1, column=0, padx=self.frame_padx, pady=(0, self.frame_pady), sticky='ew')
        self.fh_checksum_frame.columnconfigure(0, weight=1)

        self.fh_hash_frame: object = ttk.LabelFrame(
            self, text='Select Hash Algorithm:')
        self.fh_hash_frame.grid(
            row=2, column=0, padx=self.frame_padx, pady=(0, self.frame_pady), sticky='ew')
        self.fh_hash_frame.columnconfigure(0, weight=1)

        self.fh_action_buttons_frame: object = ttk.Frame(self)
        self.fh_action_buttons_frame.grid(
            row=3, column=0, padx=self.frame_padx, pady=(0, self.frame_pady), sticky='ew')
        self.fh_action_buttons_frame.columnconfigure(0, weight=1)
        self.fh_action_buttons_frame.columnconfigure(1, weight=1)
        self.fh_action_buttons_frame.columnconfigure(2, weight=1)
        self.fh_action_buttons_frame.columnconfigure(3, weight=1)

        # fh_filepath_frame Widgets
        self.fh_filepath_textbox: object = tk.Text(
            self.fh_filepath_frame, height=1)
        self.fh_filepath_textbox.grid(row=0, column=0, padx=self.widget_padx,
                                      pady=self.widget_pady, sticky='ew')

        self.fh_filepath_button: object = ttk.Button(
            self.fh_filepath_frame, text='Browse', command=self.browse_file)
        self.fh_filepath_button.grid(row=0, column=1, padx=self.widget_padx,
                                     pady=self.widget_pady, sticky='ew')

        # fh_checksum_frame Widgets
        self.fh_checksum_textbox: object = tk.Text(
            self.fh_checksum_frame, height=6)
        self.fh_checksum_textbox.grid(
            row=0, column=0, padx=self.widget_padx, pady=self.widget_pady, sticky='ew')

        # fh_hash_frame Widgets
        self.fh_hash_combobox_options: list = [
            'SHA-256',
            'SHA-512',
            'SHA-1',
            'MD5'
        ]

        self.fh_hash_combobox: object = ttk.Combobox(
            self.fh_hash_frame, values=self.fh_hash_combobox_options, state='readonly')
        self.fh_hash_combobox.grid(
            row=0, column=0, padx=self.widget_padx, pady=self.widget_pady, sticky='ew')
        self.fh_hash_combobox.current(0)

        # fh_action_buttons_frame Widgets
        self.fh_quit_button: object = ttk.Button(
            self.fh_action_buttons_frame, text='Quit', command=container.master.destroy)
        self.fh_quit_button.grid(
            row=0, column=0, padx=self.widget_padx, pady=self.widget_pady, sticky='ew')

        self.fh_help_button: object = ttk.Button(
            self.fh_action_buttons_frame, text='Help', command=self.help)
        self.fh_help_button.grid(
            row=0, column=1, padx=self.widget_padx, pady=self.widget_pady, sticky='ew')

        self.fh_clear_button: object = ttk.Button(
            self.fh_action_buttons_frame, text='Clear', command=self.clear)
        self.fh_clear_button.grid(
            row=0, column=2, padx=self.widget_padx, pady=self.widget_pady, sticky='ew')

        self.fh_verify_button: object = ttk.Button(
            self.fh_action_buttons_frame, text='Verify', command=self.verify)
        self.fh_verify_button.grid(
            row=0, column=3, padx=self.widget_padx, pady=self.widget_pady, sticky='ew')

        # fh_frame Output Widget
        self.fh_output_textbox: object = tk.Text(
            self, height=12, state='disabled')
        self.fh_output_textbox.grid(
            row=4, column=0, padx=self.frame_padx+self.widget_padx,
            pady=(0, self.frame_pady), sticky='ew')

    def browse_file(self) -> None:
        """
        Browse for file
        """
        file_path: str = askopenfilename()
        if file_path:
            self.fh_filepath_textbox.delete('1.0', 'end')
            self.fh_filepath_textbox.insert('1.0', file_path)

    def help(self) -> None:
        """
        Help Button Function
        """
        Popup(
            1,
            'Help',
            'On this Tab you can calculate hashes of files and check with the checksum'
        ).create_popup()

    def clear(self) -> None:
        """
        Clear Button Function
        """
        self.fh_filepath_textbox.delete('1.0', 'end')
        self.fh_checksum_textbox.delete('1.0', 'end')
        self.fh_hash_combobox.current(0)
        self.fh_output_textbox.config(state='normal')
        self.fh_output_textbox.delete('1.0', 'end')

    def verify(self) -> None:
        """
        Verify Button Function
        """
        try:
            self.filepath: str = self.fh_filepath_textbox.get('1.0', 'end-1c')
            self.checksum: str = self.fh_checksum_textbox.get('1.0', 'end-1c')
            self.hash_algorithm: str = self.fh_hash_combobox.get()

            if self.filepath and self.hash_algorithm:
                if self.hash_algorithm == 'SHA-256':
                    self.hash_result: str = sha256_hash(self.filepath)
                elif self.hash_algorithm == 'SHA-512':
                    self.hash_result: str = sha512_hash(self.filepath)
                elif self.hash_algorithm == 'SHA-1':
                    self.hash_result: str = sha1_hash(self.filepath)
                elif self.hash_algorithm == 'MD5':
                    self.hash_result: str = md5_hash(self.filepath)
                if self.checksum:
                    self.checksum_result: bool = self.checksum == self.hash_result
                    self.fh_output_textbox.config(state='normal')
                    self.fh_output_textbox.delete('1.0', 'end')
                    self.fh_output_textbox.insert(
                        'end', f'Hash: \n{self.hash_result}\n\nChecksum: \n{self.checksum}\n\nChecksum Test Result: \n{self.checksum_result}')
                    self.fh_output_textbox.config(state='disabled')
                else:
                    self.fh_output_textbox.config(state='normal')
                    self.fh_output_textbox.delete('1.0', 'end')
                    self.fh_output_textbox.insert(
                        'end', f'Hash: \n{self.hash_result}')
                    self.fh_output_textbox.config(state='disabled')
            else:
                raise ValueError('Please select a file and a hash algorithm')

        except (FileNotFoundError, ValueError):
            Popup(
                3,
                'Error',
                'Please select a file and a hash algorithm'
            ).create_popup()
