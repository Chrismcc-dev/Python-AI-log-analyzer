import tkinter as tk
from tkinter import filedialog, messagebox
from analyzer import analyze_log


class LogAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Python GUI Log Analyzer")
        self.root.geometry("980x720")
        self.root.configure(bg="#f4f6f8")

        self.selected_file = None
        self.current_output_lines = []

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
            text="Upload a log file to detect errors, warnings, failures, timeouts, and exceptions",
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
        self.file_label.pack(pady=(0, 8))

        controls_frame = tk.Frame(root, bg="#f4f6f8")
        controls_frame.pack(pady=8)

        self.open_button = tk.Button(
            controls_frame,
            text="Open Log File",
            font=("Arial", 10, "bold"),
            width=16,
            command=self.open_file,
        )
        self.open_button.grid(row=0, column=0, padx=6)

        self.analyze_button = tk.Button(
            controls_frame,
            text="Run Analysis",
            font=("Arial", 10, "bold"),
            width=16,
            command=self.run_analysis,
        )
        self.analyze_button.grid(row=0, column=1, padx=6)

        self.clear_button = tk.Button(
            controls_frame,
            text="Clear Results",
            font=("Arial", 10, "bold"),
            width=16,
            command=self.clear_results,
        )
        self.clear_button.grid(row=0, column=2, padx=6)

        filter_frame = tk.Frame(root, bg="#f4f6f8")
        filter_frame.pack(pady=(4, 10))

        filter_label = tk.Label(
            filter_frame,
            text="Filter Results:",
            font=("Arial", 10, "bold"),
            bg="#f4f6f8",
            fg="#1f2937",
        )
        filter_label.grid(row=0, column=0, padx=(0, 8))

        self.filter_entry = tk.Entry(filter_frame, font=("Arial", 10), width=30)
        self.filter_entry.grid(row=0, column=1, padx=4)

        self.filter_button = tk.Button(
            filter_frame,
            text="Apply Filter",
            font=("Arial", 10, "bold"),
            command=self.apply_filter,
        )
        self.filter_button.grid(row=0, column=2, padx=6)

        self.show_all_button = tk.Button(
            filter_frame,
            text="Show All",
            font=("Arial", 10, "bold"),
            command=self.show_all_results,
        )
        self.show_all_button.grid(row=0, column=3, padx=6)

        self.status_label = tk.Label(
            root,
            text="Status: Waiting for file",
            font=("Arial", 10, "bold"),
            bg="#f4f6f8",
            fg="#047857",
        )
        self.status_label.pack(pady=(0, 10))

        text_frame = tk.Frame(root, bg="#f4f6f8")
        text_frame.pack(fill="both", expand=True, padx=15, pady=(0, 15))

        scrollbar = tk.Scrollbar(text_frame)
        scrollbar.pack(side="right", fill="y")

        self.result_box = tk.Text(
            text_frame,
            wrap="word",
            font=("Courier", 11),
            bg="white",
            fg="#111827",
            relief="solid",
            bd=1,
            yscrollcommand=scrollbar.set,
        )
        self.result_box.pack(side="left", fill="both", expand=True)
        scrollbar.config(command=self.result_box.yview)

        self.result_box.tag_config("error", foreground="red")
        self.result_box.tag_config("warning", foreground="orange")
        self.result_box.tag_config("info", foreground="blue")
        self.result_box.tag_config("match", background="yellow")

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

            counts = results["counts"]
            matches = results["matches"]
            total = results["total_matches"]

            output = []
            output.append("=== ANALYSIS SUMMARY ===")
            output.append("")
            output.append(f"Total Issues Found: {total}")
            output.append("")

            if counts:
                output.append("Issue Breakdown:")
                for k, v in counts.items():
                    output.append(f"- {k.upper()}: {v}")
            else:
                output.append("No issues detected.")

            output.append("")
            output.append("=== MATCHING LOG ENTRIES ===")
            output.extend(matches[:100])

            self.current_output_lines = output
            self.display_output(output)
            self.status_label.config(text="Status: Analysis complete")

        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.status_label.config(text="Status: Error occurred")

    def display_output(self, lines):
        self.result_box.delete("1.0", tk.END)

        for line in lines:
            lower_line = line.lower()

            if any(word in lower_line for word in ["error", "failed", "exception", "denied", "refused", "unauthorized"]):
                self.result_box.insert(tk.END, line + "\n", "error")
            elif any(word in lower_line for word in ["warning", "timeout"]):
                self.result_box.insert(tk.END, line + "\n", "warning")
            else:
                self.result_box.insert(tk.END, line + "\n", "info")

    def apply_filter(self):
        keyword = self.filter_entry.get().strip().lower()

        if not self.current_output_lines:
            self.status_label.config(text="Status: No analysis results to filter")
            return

        if not keyword:
            self.show_all_results()
            self.status_label.config(text="Status: Empty filter, showing all results")
            return

        filtered_lines = [line for line in self.current_output_lines if keyword in line.lower()]

        self.display_output(filtered_lines)
        self.highlight_matches(keyword)
        self.status_label.config(text=f"Status: Filter applied for '{keyword}'")

    def show_all_results(self):
        if not self.current_output_lines:
            self.status_label.config(text="Status: No analysis results available")
            return

        self.display_output(self.current_output_lines)
        self.status_label.config(text="Status: Showing all results")

    def highlight_matches(self, keyword):
        self.result_box.tag_remove("match", "1.0", tk.END)

        start_pos = "1.0"
        while True:
            start_pos = self.result_box.search(keyword, start_pos, stopindex=tk.END, nocase=True)
            if not start_pos:
                break

            end_pos = f"{start_pos}+{len(keyword)}c"
            self.result_box.tag_add("match", start_pos, end_pos)
            start_pos = end_pos

    def clear_results(self):
        self.result_box.delete("1.0", tk.END)
        self.filter_entry.delete(0, tk.END)
        self.current_output_lines = []
        self.status_label.config(text="Status: Cleared")


