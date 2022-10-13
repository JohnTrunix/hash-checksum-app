"""
Class for the popup window
"""
import tkinter as tk
from tkinter import ttk


class Popup(tk.Toplevel):
    """
    Popup Window
    """

    def __init__(self, container, title: str, text: str, ok_button: bool, cancel_button: bool):
        super().__init__(container)
        self.padx = 20
        self.pady = 20
        self.title_value = title
        self.text_value = text
        self.geometry('300x300')
        self.title(self.title_value)
        self.resizable(False, False)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        self._label = ttk.Label(
            self, text=self.text_value, wraplength=260, justify='left', anchor='center')
        self._label.grid(
            row=0, column=0, columnspan=2, padx=self.padx, pady=self.pady, sticky='ew')

        if ok_button:
            self._ok_button = ttk.Button(
                self, text='OK')
            self._ok_button.grid(
                row=1, column=0, padx=self.padx, pady=self.pady, sticky='ew')

        if cancel_button:
            self._cancel_button = ttk.Button(
                self, text='Cancel')
            self._cancel_button.grid(
                row=1, column=1, padx=self.padx, pady=self.pady, sticky='ew')

        self.mainloop()
