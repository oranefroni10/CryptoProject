import tkinter as tk, threading
from pathlib import Path
from typing import Optional

from gui.widget import CryptoGUI
from core.file_cipher import FileCipher


class Controller:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.view = CryptoGUI(root, self)
        self.input: Optional[Path] = None
        self.output: Optional[Path] = None

    # ---------- callbacks ----------------------------------------------------
    def select_input(self):
        p = tk.filedialog.askopenfilename()
        if p:
            self.input = Path(p);
            self.view.in_entry.config(state='normal')
            self.view.in_entry.delete(0, 'end');
            self.view.in_entry.insert(0, p)
            self.view.in_entry.config(state='readonly')

    def select_output(self):
        p = tk.filedialog.asksaveasfilename()
        if p:
            self.output = Path(p);
            self.view.out_entry.config(state='normal')
            self.view.out_entry.delete(0, 'end');
            self.view.out_entry.insert(0, p)
            self.view.out_entry.config(state='readonly')

    def run(self):
        if not self.input or not self.output:
            tk.messagebox.showerror("Error", "Select both files first");
            return
        key = self.view.key_entry.get()
        if not key:
            tk.messagebox.showerror("Error", "Enter a password");
            return
        encrypt = self.view.op_var.get() == 'Encrypt'
        fc = FileCipher(str(self.input), str(self.output), key, encrypt,
                        progress=self._update_progress)
        th = threading.Thread(target=lambda: (self._log("Running…"), fc.run(),
                                              self._log("Done!")))
        th.start()

    # ---------- helpers ------------------------------------------------------
    def _update_progress(self, frac: float):
        self.view.pbar['value'] = frac * 100
        self.root.update_idletasks()

    def _log(self, msg: str):
        t = self.view.status
        t.config(state='normal');
        t.insert('end', f'{msg}\n')
        t.see('end');
        t.config(state='disabled')


def launch():
    root = tk.Tk();
    root.title("IDEA cipher");
    root.resizable(False, False)
    Controller(root);
    root.mainloop()
