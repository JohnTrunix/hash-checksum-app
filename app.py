"""
Hash-Checksum-App
Author: JohnTrunix
Version: 2.0.0
"""
import os
import tkinter as tk
from tkinter import ttk

from modules.hash_validator import HashValidatorPage
from modules.virustotal import VirustotalPage
from modules.settings import SettingsPage


class App(tk.Tk):
    """
    Tkinter App Instance
    """
    __version__ = '2.0.0'

    def __init__(self):
        super().__init__()
        self.icon_path = os.path.join(os.path.dirname(__file__), 'hash.ico')

        # Tkinter Window Basci Config
        self.title(f'Hasher / Checksum Verifier (v{self.__version__})')
        self.iconbitmap(default=self.icon_path)
        self.geometry('700x800')
        self.resizable(False, False)
        self.attributes('-topmost', True)

        # Tkinter Notebook Config
        self.notebook: object = ttk.Notebook(self)
        self.notebook.pack(fill='both', expand=True, padx=5, pady=5)
        self.f_hasher: object = HashValidatorPage(self.notebook)
        self.f_virustotal: object = VirustotalPage(self.notebook)
        self.f_settings: object = SettingsPage(self.notebook)
        self.notebook.add(self.f_hasher, text='Hasher/Checksum Verifier')
        self.notebook.add(self.f_virustotal, text='VirusTotal Scanner')
        self.notebook.add(self.f_settings, text='Settings')

        # temporary disable Pages
        #self.notebook.tab(0, state='disabled')
        #self.notebook.tab(1, state='disabled')
        #self.notebook.tab(2, state='disabled')

        # self.check_update()

    def check_update(self) -> None:
        """
        Check if there is a new version available on GitHub
        """
        pass


if __name__ == '__main__':
    app = App()
    app.mainloop()
