import tkinter as tk
from tkinter import ttk

from modules.hash_validator import HashValidatorPage
from modules.virustotal import VirustotalPage
from modules.settings import SettingsPage


class App(tk.Tk):
    """
    Tkinter App Instance
    """
    __version__ = '1.2.0'

    def __init__(self):
        super().__init__()

        # Tkinter Window Basci Config
        self.title(f'Hasher / Checksum Verifier (V{self.__version__})')
        self.iconbitmap('hash.ico')
        self.geometry('700x800+800+200')
        self.resizable(False, False)
        self.attributes('-topmost', True)

        # Tkinter Notebook Config
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill='both', expand=True, padx=5, pady=5)
        self.f_hasher = HashValidatorPage(self.notebook)
        self.f_virustotal = VirustotalPage(self.notebook)
        self.f_settings = SettingsPage(self.notebook)
        self.notebook.add(self.f_hasher, text='Hasher/Checksum Verifier')
        self.notebook.add(self.f_virustotal, text='VirusTotal Scanner')
        self.notebook.add(self.f_settings, text='Settings')

        # temporary disable Pages
        #self.notebook.tab(0, state='disabled')
        #self.notebook.tab(1, state='disabled')
        #self.notebook.tab(2, state='disabled')


if __name__ == '__main__':
    app = App()
    app.mainloop()
