"""
Hash and Checksum Validator Page
"""
import tkinter as tk
from tkinter import ttk

from modules.popup import Popup


class HashValidatorPage(tk.Frame):
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
        self.fh_filepath_frame = ttk.LabelFrame(
            self, text='File Path:')
        self.fh_filepath_frame.grid(
            row=0, column=0, padx=self.frame_padx, pady=self.frame_pady, sticky='ew')
        self.fh_filepath_frame.columnconfigure(0, weight=10)
        self.fh_filepath_frame.columnconfigure(1, weight=1)

        self.fh_checksum_frame = ttk.LabelFrame(
            self, text='Checksum (optional):')
        self.fh_checksum_frame.grid(
            row=1, column=0, padx=self.frame_padx, pady=(0, self.frame_pady), sticky='ew')
        self.fh_checksum_frame.columnconfigure(0, weight=1)

        self.fh_hash_frame = ttk.LabelFrame(
            self, text='Select Hash Algorithm:')
        self.fh_hash_frame.grid(
            row=2, column=0, padx=self.frame_padx, pady=(0, self.frame_pady), sticky='ew')
        self.fh_hash_frame.columnconfigure(0, weight=1)

        self.fh_action_buttons_frame = ttk.Frame(self)
        self.fh_action_buttons_frame.grid(
            row=3, column=0, padx=self.frame_padx, pady=(0, self.frame_pady), sticky='ew')
        self.fh_action_buttons_frame.columnconfigure(0, weight=1)
        self.fh_action_buttons_frame.columnconfigure(1, weight=1)
        self.fh_action_buttons_frame.columnconfigure(2, weight=1)
        self.fh_action_buttons_frame.columnconfigure(3, weight=1)

        # fh_filepath_frame Widgets
        self.fh_filepath_textbox = tk.Text(
            self.fh_filepath_frame, height=1)
        self.fh_filepath_textbox.grid(row=0, column=0, padx=self.widget_padx,
                                      pady=self.widget_pady, sticky='ew')

        self.fh_filepath_button = ttk.Button(
            self.fh_filepath_frame, text='Browse')
        self.fh_filepath_button.grid(row=0, column=1, padx=self.widget_padx,
                                     pady=self.widget_pady, sticky='ew')

        # fh_checksum_frame Widgets
        self.fh_checksum_textbox = tk.Text(
            self.fh_checksum_frame, height=6)
        self.fh_checksum_textbox.grid(
            row=0, column=0, padx=self.widget_padx, pady=self.widget_pady, sticky='ew')

        # fh_hash_frame Widgets
        self.fh_hash_combobox_options = [
            'SHA-256',
            'SHA-512',
            'SHA-1',
            'MD5'
        ]

        self.fh_hash_combobox = ttk.Combobox(
            self.fh_hash_frame, values=self.fh_hash_combobox_options, state='readonly')
        self.fh_hash_combobox.grid(
            row=0, column=0, padx=self.widget_padx, pady=self.widget_pady, sticky='ew')
        self.fh_hash_combobox.current(0)

        # fh_action_buttons_frame Widgets
        self.fh_quit_button = ttk.Button(
            self.fh_action_buttons_frame, text='Quit', command=container.master.destroy)
        self.fh_quit_button.grid(
            row=0, column=0, padx=self.widget_padx, pady=self.widget_pady, sticky='ew')

        self.fh_help_button = ttk.Button(
            self.fh_action_buttons_frame, text='Help', command=self.help)
        self.fh_help_button.grid(
            row=0, column=1, padx=self.widget_padx, pady=self.widget_pady, sticky='ew')

        self.fh_clear_button = ttk.Button(
            self.fh_action_buttons_frame, text='Clear', command=self.clear)
        self.fh_clear_button.grid(
            row=0, column=2, padx=self.widget_padx, pady=self.widget_pady, sticky='ew')

        self.fh_verify_button = ttk.Button(
            self.fh_action_buttons_frame, text='Verify', command=self.verify)
        self.fh_verify_button.grid(
            row=0, column=3, padx=self.widget_padx, pady=self.widget_pady, sticky='ew')

        # fh_frame Output Widget
        self.fh_output_textbox = tk.Text(
            self, height=12, state='disabled')
        self.fh_output_textbox.grid(
            row=4, column=0, padx=self.frame_padx+self.widget_padx, pady=(0, self.frame_pady), sticky='ew')

    def help(self):
        """
        Help Button Function
        """
        Popup(1, 'Help', 'On this Tab you can calculate hashes of files and check with the checksum').create_popup()

    def clear(self):
        """
        Clear Button Function
        """
        print('Clear')

    def verify(self):
        """
        Verify Button Function
        """
        if self.fh_hash_combobox.get():
            print(self.fh_hash_combobox.get())
        else:

            print('pop up error message')
