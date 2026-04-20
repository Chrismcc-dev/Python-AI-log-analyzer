import tkinter as tk
from tkinter import filedialog, messagebox
from analyzer import analyze_log


class LogAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Python GUI Log Analyzer")
        self.root.geometry("900x650")
        self.root.configure(bg="#f4f6f8")

        self.selected_file = None

        title_label = tk.Label(
            root,
            text="Python GUI Log Analyzer",
            font=("Arial", 18, "bold"),
            bg="#f4f6f8",
            fg="#1f2937",
        )
        title_label.pack(pady=(15, 5))

        subtitle_label = tk.Label(
            root,
            text="Upload a log file to detect errors, failures, timeouts, and exceptions",
            font=("Arial", 10),
            bg="#f4f6f8",
            fg="#4b5563",
        )
        subtitle_label.pack(pady=(0, 10))

        self.file_label = tk.Label(
            root,
            text="Selected file: None",
            font=("Arial", 10, "italic"),
            bg="#f4f6f8",
            fg="#2563eb",
        )
        self.file_label.pack(pady=(0, 10))

        button_frame = tk.Frame(root, bg="#f4f6f8")
        button_frame.pack(pady=10)

        self.open_button = tk.Button(
            button_frame,
            text="Open Log File",
            font=("Arial", 10, "bold"),
            width=16,
            command=self.open_file,
        )
        self.open_button.grid(row=0, column=0, padx=8)

        self.analyze_button = tk.Button(
            button_frame,
            text="Run Analysis",
            font=("Arial", 10, "bold"),
            width=16,
            command=self.run_analysis,
        )
        self.analyze_button.grid(row=0, column=1, padx=8)

        self.clear_button = tk.Button(
            button_frame,
            text="Clear Results",
            font=("Arial", 10, "bold"),
            width=16,
            command=self.clear_results,
        )
        self.clear_button.grid(row=0, column=2, padx=8)

        self.status_label = tk.Label(
            root,
            text="Status: Waiting for file",
            font=("Arial", 10, "bold"),
            bg="#f4f6f8",
            fg="#047857",
        )
        self.status_label.pack(pady=(5, 10))

        self.result_box = tk.Text(
            root,
            wrap="word",
            font=("Courier", 11),
            bg="white",
            fg="#111827",
            relief="solid",
            bd=1,
        )
        self.result_box.pack(fill="both", expand=True, padx=15, pady=(0, 15))

    def open_file(self):
        file_path = filedialog.askopenfilename(
            title="Select a log file",
            filetypes=[("Log files", "*.log *.txt"), ("All files", "*.*")]
        )

        if file_path:
            self.selected_file = file_path
            self.file_label.config(text=f"Selected file: {file_path}")
            self.status_label.config(text="Status: File loaded successfully")

    def run_analysis(self):
        if not self.selected_file:
            messagebox.showwarning("No File Selected", "Please choose a log file first.")
            self.status_label.config(text="Status: No file selected")
            return

        try:
            results = analyze_log(self.selected_file)

            self.result_box.delete("1.0", tk.END)

            counts = results["counts"]
            matches = results["matches"]
            total = results["total_matches"]

            output = []
            output.append("=== ANALYSIS SUMMARY ===\n")
            output.append(f"Total Issues Found: {total}\n")

            if counts:
                output.append("Issue Breakdown:")
                for k, v in counts.items():
                    output.append(f"- {k.upper()}: {v}")
            else:
                output.append("No issues detected.")

            output.append("\n=== MATCHING LOG ENTRIES ===")
            output.extend(matches[:100])

            self.result_box.insert(tk.END, "\n".join(output))
            self.status_label.config(text="Status: Analysis complete")

        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.status_label.config(text="Status: Error occurred")

    def clear_results(self):
        self.result_box.delete("1.0", tk.END)
        self.status_label.config(text="Status: Cleared")
