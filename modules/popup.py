"""
Class for the popup window
"""
import tkinter as tk
from tkinter import messagebox


class Popup():
    """
    Popup Window
    """

    def __init__(self, message_type: int, title: str, text: str):
        super().__init__()
        self.title_value = title
        self.text_value = text
        self.message_type = message_type

    def create_popup(self):
        """
        Creates Messagebox Popup
        """
        if self.message_type == 1:
            messagebox.showinfo(self.title_value, self.text_value)
        elif self.message_type == 2:
            messagebox.showwarning(
                self.title_value, self.text_value)
        elif self.message_type == 3:
            messagebox.showerror(self.title_value, self.text_value)
        elif self.message_type == 4:
            answer = messagebox.askyesno(self.title_value, self.text_value)
            return answer
        elif self.message_type == 5:
            answer = messagebox.askokcancel(
                self.title_value, self.text_value)
            return answer
