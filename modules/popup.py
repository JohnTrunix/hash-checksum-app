"""
Class for the popup window
"""
from tkinter import messagebox


class Popup():
    """
    Popup Window
    """

    def __init__(self, message_type: int, title: str, text: str):
        super().__init__()
        self.title_value: str = title
        self.text_value: str = text
        self.message_type: int = message_type

    def create_popup(self) -> bool or None:
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
            answer: bool = messagebox.askyesno(
                self.title_value, self.text_value)
            return answer
        elif self.message_type == 5:
            answer: bool = messagebox.askokcancel(
                self.title_value, self.text_value)
            return answer
