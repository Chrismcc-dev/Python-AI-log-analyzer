import tkinter as tk
from tkinter import filedialog, scrolledtext
from analyzer import analyze_log, generate_report


class LogAnalyzerApp:

    def __init__(self, root):

        self.root = root
        self.root.title("AI Log Analyzer")
        self.root.geometry("800x600")

        open_button = tk.Button(
            root,
            text="Open Log File",
            command=self.open_file
        )

        open_button.pack(pady=10)

        self.output = scrolledtext.ScrolledText(root)
        self.output.pack(fill="both", expand=True)

    def open_file(self):

        file_path = filedialog.askopenfilename()

        if not file_path:
            return

        results = analyze_log(file_path)

        report = generate_report(results)

        self.output.delete("1.0", tk.END)

        self.output.insert(tk.END, report)