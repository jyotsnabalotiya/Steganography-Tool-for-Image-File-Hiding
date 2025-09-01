#!/usr/bin/env python3
import os, tkinter as tk
from tkinter import filedialog, messagebox, ttk
from stego import embed, extract

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("LSB Steganography (PNG/BMP)")
        self.geometry("700x520")
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True)

        self.embed_frame = ttk.Frame(nb); nb.add(self.embed_frame, text="Embed")
        self.extract_frame = ttk.Frame(nb); nb.add(self.extract_frame, text="Extract")

        self._build_embed_tab(self.embed_frame)
        self._build_extract_tab(self.extract_frame)

    def _build_embed_tab(self, root):
        pad = {"padx": 8, "pady": 6}
        ttk.Label(root, text="Cover Image (PNG/BMP):").grid(row=0, column=0, sticky="w", **pad)
        self.cover_path = tk.StringVar()
        ttk.Entry(root, textvariable=self.cover_path, width=50).grid(row=0, column=1, **pad)
        ttk.Button(root, text="Browse", command=self._choose_cover).grid(row=0, column=2, **pad)

        self.mode = tk.StringVar(value="text")
        ttk.Radiobutton(root, text="Text", variable=self.mode, value="text").grid(row=1, column=0, sticky="w", **pad)
        ttk.Radiobutton(root, text="File", variable=self.mode, value="file").grid(row=1, column=1, sticky="w", **pad)

        ttk.Label(root, text="Message:").grid(row=2, column=0, sticky="nw", **pad)
        self.msg = tk.Text(root, width=60, height=6)
        self.msg.grid(row=2, column=1, columnspan=2, **pad)

        ttk.Label(root, text="File to hide:").grid(row=3, column=0, sticky="w", **pad)
        self.file_path = tk.StringVar()
        ttk.Entry(root, textvariable=self.file_path, width=50).grid(row=3, column=1, **pad)
        ttk.Button(root, text="Browse", command=self._choose_payload).grid(row=3, column=2, **pad)

        ttk.Label(root, text="Password (optional):").grid(row=4, column=0, sticky="w", **pad)
        self.password = tk.StringVar()
        ttk.Entry(root, textvariable=self.password, width=30, show="*").grid(row=4, column=1, sticky="w", **pad)

        ttk.Label(root, text="Output stego PNG:").grid(row=5, column=0, sticky="w", **pad)
        self.out_path = tk.StringVar(value="stego_output.png")
        ttk.Entry(root, textvariable=self.out_path, width=50).grid(row=5, column=1, **pad)
        ttk.Button(root, text="Save As", command=self._choose_out).grid(row=5, column=2, **pad)

        ttk.Button(root, text="Embed", command=self._do_embed).grid(row=6, column=1, sticky="e", **pad)

    def _build_extract_tab(self, root):
        pad = {"padx": 8, "pady": 6}
        ttk.Label(root, text="Stego Image (PNG):").grid(row=0, column=0, sticky="w", **pad)
        self.stego_path = tk.StringVar()
        ttk.Entry(root, textvariable=self.stego_path, width=50).grid(row=0, column=1, **pad)
        ttk.Button(root, text="Browse", command=self._choose_stego).grid(row=0, column=2, **pad)

        ttk.Label(root, text="Password (if protected):").grid(row=1, column=0, sticky="w", **pad)
        self.password_x = tk.StringVar()
        ttk.Entry(root, textvariable=self.password_x, width=30, show="*").grid(row=1, column=1, sticky="w", **pad)

        ttk.Label(root, text="Save extracted file as (if file):").grid(row=2, column=0, sticky="w", **pad)
        self.out_file = tk.StringVar(value="extracted.bin")
        ttk.Entry(root, textvariable=self.out_file, width=50).grid(row=2, column=1, **pad)
        ttk.Button(root, text="Save As", command=self._choose_out_file).grid(row=2, column=2, **pad)

        ttk.Button(root, text="Extract", command=self._do_extract).grid(row=3, column=1, sticky="e", **pad)

        ttk.Label(root, text="Extracted text (if any):").grid(row=4, column=0, sticky="nw", **pad)
        self.text_out = tk.Text(root, width=60, height=8)
        self.text_out.grid(row=4, column=1, columnspan=2, **pad)

    def _choose_cover(self):
        p = filedialog.askopenfilename(filetypes=[("Images", "*.png *.bmp *.jpg *.jpeg"), ("All", "*.*")])
        if p: self.cover_path.set(p)

    def _choose_payload(self):
        p = filedialog.askopenfilename()
        if p: self.file_path.set(p)

    def _choose_out(self):
        p = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Image", "*.png")])
        if p: self.out_path.set(p)

    def _choose_stego(self):
        p = filedialog.askopenfilename(filetypes=[("PNG Image", "*.png"), ("All", "*.*")])
        if p: self.stego_path.set(p)

    def _choose_out_file(self):
        p = filedialog.asksaveasfilename()
        if p: self.out_file.set(p)

    def _do_embed(self):
        try:
            cover = self.cover_path.get().strip()
            outp  = self.out_path.get().strip()
            pwd   = self.password.get().strip() or None
            if not cover or not outp:
                messagebox.showerror("Error", "Select cover image and output path")
                return
            if self.mode.get() == "text":
                msg = self.msg.get("1.0", "end-1c")
                if not msg:
                    messagebox.showerror("Error", "Enter a message")
                    return
                embed(cover, outp, message=msg, file_path=None, password=pwd)
            else:
                fpath = self.file_path.get().strip()
                if not fpath:
                    messagebox.showerror("Error", "Choose a file to hide")
                    return
                embed(cover, outp, message=None, file_path=fpath, password=pwd)
            messagebox.showinfo("Success", f"Embedded successfully to:\n{outp}")
        except Exception as e:
            messagebox.showerror("Embed Failed", str(e))

    def _do_extract(self):
        try:
            stego = self.stego_path.get().strip()
            pwd   = self.password_x.get().strip() or None
            outf  = self.out_file.get().strip() or None
            data, meta = extract(stego, password=pwd)
            if meta.is_file:
                if not outf:
                    outf = os.path.splitext(stego)[0] + f"_extracted.{meta.ext or 'bin'}"
                with open(outf, "wb") as f:
                    f.write(data)
                messagebox.showinfo("File Extracted", f"Saved to:\n{outf}")
            else:
                try:
                    text = data.decode("utf-8")
                except Exception:
                    text = repr(data)
                self.text_out.delete("1.0", "end")
                self.text_out.insert("1.0", text)
                messagebox.showinfo("Text Extracted", "Text extracted successfully. See the textbox.")
        except Exception as e:
            messagebox.showerror("Extract Failed", str(e))

if __name__ == "__main__":
    App().mainloop()
