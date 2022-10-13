"""
Settings Page
"""
import os
import tkinter as tk
from tkinter import ttk
from configparser import ConfigParser

from modules.popup import Popup


class SettingsPage(tk.Frame):
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

        # Frame Config
        self.settings_frame: object = ttk.LabelFrame(
            self, text='Settings:')
        self.settings_frame.grid(
            row=0, column=0, columnspan=4, padx=self.frame_padx, pady=self.frame_pady, sticky='ew')
        self.settings_frame.columnconfigure(0, weight=1)
        self.settings_frame.columnconfigure(1, weight=8)

        # Settings Frame Widgets
        self.label_api_key: object = ttk.Label(
            self.settings_frame, text='Virustotal API Key:')
        self.label_api_key.grid(
            row=0, column=0, padx=self.widget_padx, pady=self.widget_pady, sticky='w')
        self.settings_textbox: object = tk.Entry(
            self.settings_frame)
        self.settings_textbox.grid(
            row=0, column=1, padx=self.widget_padx, pady=self.widget_pady, sticky='ew')
        self.label_version_title: object = ttk.Label(
            self.settings_frame, text='Version:')
        self.label_version_title.grid(
            row=1, column=0, padx=self.widget_padx, pady=self.widget_pady, sticky='w')
        self.label_version: object = ttk.Label(
            self.settings_frame, text=f'V{container.master.__version__}')
        self.label_version.grid(
            row=1, column=1, padx=self.frame_padx, pady=(0, self.frame_pady), sticky='ew')

        # Buttons
        self.button_quit: object = ttk.Button(
            self, text='Quit', command=container.master.destroy)
        self.button_quit.grid(
            row=1, column=0, padx=self.frame_padx, pady=self.widget_pady, sticky='ew')
        self.button_delete_settings: object = ttk.Button(
            self, text='Delete Settings', command=self.delete_settings)
        self.button_delete_settings.grid(
            row=1, column=1, padx=self.frame_padx, pady=self.widget_pady, sticky='ew')
        self.button_cancel: object = ttk.Button(
            self, text='Cancel', command=self.load_settings)
        self.button_cancel.grid(
            row=1, column=2, padx=self.frame_padx, pady=self.widget_pady, sticky='ew')
        self.button_save: object = ttk.Button(
            self, text='Save', command=self.save_settings)
        self.button_save.grid(
            row=1, column=3, padx=self.frame_padx, pady=self.widget_pady, sticky='ew')

        # Load Settings
        self.load_settings()

    def load_settings(self) -> None:
        """
        Load Settings
        """
        config: object = ConfigParser()
        if not os.path.isfile('config.ini'):
            config.add_section('main_settings')
            config.set('main_settings', 'api_key', 'None')
            with open('config.ini', 'w', encoding='utf8') as configfile:
                config.write(configfile)
        config.read('config.ini')
        self.main_settings: list = config['main_settings']
        self.api_key: str = self.main_settings['api_key']

        self.settings_textbox.delete(0, tk.END)
        self.settings_textbox.insert(0, self.api_key)

    def save_settings(self) -> None:
        """
        Save Settings
        """
        config = ConfigParser()
        config.read('config.ini')
        config.set('main_settings', 'api_key', self.settings_textbox.get())
        with open('config.ini', 'w', encoding='utf8') as configfile:
            config.write(configfile)

    def delete_settings(self) -> None:
        """
        Delete Settings
        """
        response = Popup(
            4, 'Confirm', 'Are you sure you want to delete the settings?').create_popup()
        if response == 1 and os.path.isfile('config.ini'):
            os.remove('config.ini')
            self.load_settings()
