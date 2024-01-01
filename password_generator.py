import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import random
import string
import pyperclip

class PasswordGeneratorApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Password Generator")
        self.master.geometry("500x400")
        self.master.configure(bg="#006c67")

        self.frame_color = "#FFFFFF"
        self.button_color = "#00FF00"
        self.label_color = "#000000"
        self.checkbutton_color = "#000000"

        style = ttk.Style()
        style.configure('TFrame', background=self.frame_color)
        style.configure('TButton', background=self.button_color, font=('Times New Roman', 12), foreground=self.label_color)
        style.configure('TLabel', background=self.frame_color, font=('Times New Roamn', 12), foreground=self.label_color)
        style.configure('TCheckbutton', background=self.frame_color, font=('Times New Roamn', 12), foreground=self.checkbutton_color)

        self.password_var = tk.StringVar()
        self.complexity_var = tk.StringVar()
        self.include_uppercase_var = tk.BooleanVar()
        self.include_lowercase_var = tk.BooleanVar()
        self.include_digits_var = tk.BooleanVar()
        self.include_special_var = tk.BooleanVar()
        self.password_length_var = tk.StringVar()
        self.password_length_var.set("8")

        self.create_widgets()

    def create_widgets(self):
        frame = ttk.Frame(self.master, style='TFrame')
        frame.place(relx=0.5, rely=0.5, anchor='center')

        title_label = ttk.Label(frame, text="Password Generator", style='TLabel', font=('Times New Roamn', 20, 'bold'))
        title_label.grid(row=0, column=0, columnspan=2, pady=20)

        password_entry = ttk.Entry(frame, textvariable=self.password_var, state="readonly", font=('Times New Roamn', 14))
        password_entry.grid(row=1, column=0, columnspan=2, pady=10, padx=10, ipadx=10, sticky="ew")

        complexity_label = ttk.Label(frame, text="Complexity:", style='TLabel')
        complexity_label.grid(row=2, column=0, padx=10, pady=5, sticky="w")

        complexity_combobox = ttk.Combobox(frame, values=["Low", "Medium", "High"], textvariable=self.complexity_var, font=('Helvetica', 12))
        complexity_combobox.set("Medium")
        complexity_combobox.grid(row=2, column=1, padx=10, pady=5, sticky="ew")

        rules_frame = ttk.LabelFrame(frame, text="Security Rules", style='TFrame')
        rules_frame.grid(row=3, column=0, columnspan=2, pady=10, padx=10, sticky="ew")

        include_uppercase_checkbox = ttk.Checkbutton(rules_frame, text="Include Uppercase", variable=self.include_uppercase_var, style='TCheckbutton')
        include_uppercase_checkbox.grid(row=0, column=0, sticky="w")

        include_lowercase_checkbox = ttk.Checkbutton(rules_frame, text="Include Lowercase", variable=self.include_lowercase_var, style='TCheckbutton')
        include_lowercase_checkbox.grid(row=1, column=0, sticky="w")

        include_digits_checkbox = ttk.Checkbutton(rules_frame, text="Include Digits", variable=self.include_digits_var, style='TCheckbutton')
        include_digits_checkbox.grid(row=2, column=0, sticky="w")

        include_special_checkbox = ttk.Checkbutton(rules_frame, text="Include Special Characters", variable=self.include_special_var, style='TCheckbutton')
        include_special_checkbox.grid(row=3, column=0, sticky="w")

        length_label = ttk.Label(frame, text="Password Length:", style='TLabel')
        length_label.grid(row=4, column=0, padx=10, pady=5, sticky="w")

        length_entry = ttk.Entry(frame, textvariable=self.password_length_var, font=('Helvetica', 12))
        length_entry.grid(row=4, column=1, padx=10, pady=5, sticky="ew")

        generate_button = ttk.Button(frame, text="Generate Password", command=self.generate_password, style='TButton')
        generate_button.grid(row=5, column=0, columnspan=2, pady=15)

        copy_button = ttk.Button(frame, text="Copy to Clipboard", command=self.copy_to_clipboard, style='TButton')
        copy_button.grid(row=6, column=0, columnspan=2, pady=10)

    def generate_password(self):
        complexity_str = self.complexity_var.get()
        complexity = self.get_complexity_value(complexity_str)

        try:
            length = int(self.password_length_var.get())
        except ValueError:
            messagebox.showwarning("Invalid Length", "Please enter a valid numeric length.")
            return

        if length < 4:
            messagebox.showwarning("Invalid Length", "Password length should be at least 4 characters.")
            return

        password_characters = self.get_allowed_characters()
        generated_password = self.generate_random_password(length, password_characters)
        self.password_var.set(generated_password)

    def get_password_length(self, complexity):
        if complexity == 0:
            return 0
        else:
            return complexity

    def get_complexity_value(self, complexity_str):
        complexity_mapping = {"Low": 8, "Medium": 12, "High": 16}
        return complexity_mapping.get(complexity_str, 0)

    def get_allowed_characters(self):
        characters = ""
        if self.include_uppercase_var.get():
            characters += string.ascii_uppercase
        if self.include_lowercase_var.get():
            characters += string.ascii_lowercase
        if self.include_digits_var.get():
            characters += string.digits
        if self.include_special_var.get():
            characters += string.punctuation
        return characters

    def generate_random_password(self, length, characters):
        if not characters:
            messagebox.showwarning("No Rules Selected", "Please select at least one rule.")
            return ""

        generated_password = ''.join(random.choice(characters) for _ in range(length))
        return generated_password

    def copy_to_clipboard(self):
        password = self.password_var.get()
        if password:
            pyperclip.copy(password)
            messagebox.showinfo("Copied to Clipboard", "Password copied to clipboard.")
        else:
            messagebox.showwarning("No Password", "Generate a password first.")

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordGeneratorApp(root)
    root.mainloop()
