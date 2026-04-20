import tkinter as tk
from tkinter import filedialog, messagebox
from analyzer import analyze_log, generate_incident_summary, KEYWORDS


class LogAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Python GUI Log Analyzer")
        self.root.geometry("1080x820")
        self.root.configure(bg="#f4f6f8")

        self.selected_file = None
        self.current_output_lines = []
        self.latest_results = None
        self.latest_summary = ""

        self.monitoring = False
        self.monitor_job = None
        self.last_position = 0

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
            width=14,
            command=self.open_file,
        )
        self.open_button.grid(row=0, column=0, padx=4)

        self.analyze_button = tk.Button(
            controls_frame,
            text="Run Analysis",
            font=("Arial", 10, "bold"),
            width=14,
            command=self.run_analysis,
        )
        self.analyze_button.grid(row=0, column=1, padx=4)

        self.start_monitor_button = tk.Button(
            controls_frame,
            text="Start Monitoring",
            font=("Arial", 10, "bold"),
            width=16,
            command=self.start_monitoring,
        )
        self.start_monitor_button.grid(row=0, column=2, padx=4)

        self.stop_monitor_button = tk.Button(
            controls_frame,
            text="Stop Monitoring",
            font=("Arial", 10, "bold"),
            width=16,
            command=self.stop_monitoring,
        )
        self.stop_monitor_button.grid(row=0, column=3, padx=4)

        self.summary_button = tk.Button(
            controls_frame,
            text="Generate Summary",
            font=("Arial", 10, "bold"),
            width=16,
            command=self.run_summary,
        )
        self.summary_button.grid(row=0, column=4, padx=4)

        self.export_button = tk.Button(
            controls_frame,
            text="Export Summary",
            font=("Arial", 10, "bold"),
            width=14,
            command=self.export_summary,
        )
        self.export_button.grid(row=0, column=5, padx=4)

        self.copy_button = tk.Button(
            controls_frame,
            text="Copy Summary",
            font=("Arial", 10, "bold"),
            width=14,
            command=self.copy_summary,
        )
        self.copy_button.grid(row=0, column=6, padx=4)

        self.clear_button = tk.Button(
            controls_frame,
            text="Clear Results",
            font=("Arial", 10, "bold"),
            width=14,
            command=self.clear_results,
        )
        self.clear_button.grid(row=0, column=7, padx=4)

        filter_frame = tk.Frame(root, bg="#f4f6f8")
        filter_frame.pack(pady=(4, 10))

        filter_label = tk.Label(
            filter_frame,
            text="Filter Raw Results:",
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

        summary_label = tk.Label(
            root,
            text="Incident Summary",
            font=("Arial", 12, "bold"),
            bg="#f4f6f8",
            fg="#1f2937",
            anchor="w",
        )
        summary_label.pack(fill="x", padx=15, pady=(0, 6))

        summary_frame = tk.Frame(root, bg="#f4f6f8")
        summary_frame.pack(fill="x", padx=15, pady=(0, 12))

        summary_scrollbar = tk.Scrollbar(summary_frame)
        summary_scrollbar.pack(side="right", fill="y")

        self.summary_box = tk.Text(
            summary_frame,
            wrap="word",
            height=14,
            font=("Courier", 10),
            bg="#fdfcff",
            fg="#4c1d95",
            relief="solid",
            bd=1,
            yscrollcommand=summary_scrollbar.set,
        )
        self.summary_box.pack(side="left", fill="both", expand=True)
        summary_scrollbar.config(command=self.summary_box.yview)

        raw_label = tk.Label(
            root,
            text="Raw Analysis Results",
            font=("Arial", 12, "bold"),
            bg="#f4f6f8",
            fg="#1f2937",
            anchor="w",
        )
        raw_label.pack(fill="x", padx=15, pady=(0, 6))

        text_frame = tk.Frame(root, bg="#f4f6f8")
        text_frame.pack(fill="both", expand=True, padx=15, pady=(0, 15))

        raw_scrollbar = tk.Scrollbar(text_frame)
        raw_scrollbar.pack(side="right", fill="y")

        self.result_box = tk.Text(
            text_frame,
            wrap="word",
            font=("Courier", 11),
            bg="white",
            fg="#111827",
            relief="solid",
            bd=1,
            yscrollcommand=raw_scrollbar.set,
        )
        self.result_box.pack(side="left", fill="both", expand=True)
        raw_scrollbar.config(command=self.result_box.yview)

        self.result_box.tag_config("error", foreground="red")
        self.result_box.tag_config("warning", foreground="orange")
        self.result_box.tag_config("info", foreground="blue")
        self.result_box.tag_config("match", background="yellow")
        self.result_box.tag_config("live", foreground="green")

    def open_file(self):
        file_path = filedialog.askopenfilename(
            title="Select a log file",
            filetypes=[("Log files", "*.log *.txt *.csv"), ("All files", "*.*")]
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
            self.latest_results = results
            self.latest_summary = ""
            self.summary_box.delete("1.0", tk.END)

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

    def start_monitoring(self):
        if not self.selected_file:
            messagebox.showwarning("No File Selected", "Please choose a log file first.")
            self.status_label.config(text="Status: No file selected")
            return

        if self.monitoring:
            self.status_label.config(text="Status: Monitoring already active")
            return

        try:
            with open(self.selected_file, "r", encoding="utf-8", errors="ignore") as file:
                file.seek(0, 2)
                self.last_position = file.tell()

            if self.latest_results is None:
                self.latest_results = {
                    "counts": {},
                    "matches": [],
                    "total_matches": 0,
                }

            self.monitoring = True
            self.status_label.config(text="Status: Live monitoring started")
            self.poll_log_file()

        except Exception as e:
            messagebox.showerror("Monitoring Error", str(e))
            self.status_label.config(text="Status: Failed to start monitoring")

    def stop_monitoring(self):
        self.monitoring = False

        if self.monitor_job is not None:
            self.root.after_cancel(self.monitor_job)
            self.monitor_job = None

        self.status_label.config(text="Status: Monitoring stopped")

    def poll_log_file(self):
        if not self.monitoring or not self.selected_file:
            return

        try:
            with open(self.selected_file, "r", encoding="utf-8", errors="ignore") as file:
                file.seek(self.last_position)
                new_lines = file.readlines()
                self.last_position = file.tell()

            live_matches = []
            for line in new_lines:
                stripped = line.strip()
                lower_line = stripped.lower()

                for keyword in KEYWORDS:
                    if keyword in lower_line:
                        live_matches.append(f"LIVE: {stripped}")
                        self.update_live_results(keyword, stripped)
                        break

            if live_matches:
                self.status_label.config(text=f"Status: Monitoring active - {len(live_matches)} new issue(s) found")
                self.append_live_output(live_matches)

        except Exception as e:
            self.status_label.config(text=f"Status: Monitoring error - {str(e)}")
            self.monitoring = False
            return

        self.monitor_job = self.root.after(2000, self.poll_log_file)

    def update_live_results(self, keyword, line):
        if self.latest_results is None:
            self.latest_results = {
                "counts": {},
                "matches": [],
                "total_matches": 0,
            }

        counts = self.latest_results["counts"]
        if keyword not in counts:
            counts[keyword] = 0
        counts[keyword] += 1

        self.latest_results["matches"].append(f"LIVE: {line}")
        self.latest_results["total_matches"] += 1

        self.current_output_lines.append(f"LIVE: {line}")

    def append_live_output(self, live_lines):
        if "=== MATCHING LOG ENTRIES ===" not in self.current_output_lines:
            self.current_output_lines.append("")
            self.current_output_lines.append("=== MATCHING LOG ENTRIES ===")

        for line in live_lines:
            lower_line = line.lower()
            if any(word in lower_line for word in ["error", "failed", "exception", "denied", "refused", "unauthorized"]):
                self.result_box.insert(tk.END, line + "\n", "error")
            elif any(word in lower_line for word in ["warning", "timeout"]):
                self.result_box.insert(tk.END, line + "\n", "warning")
            else:
                self.result_box.insert(tk.END, line + "\n", "live")

        self.result_box.see(tk.END)

    def run_summary(self):
        if not self.latest_results:
            messagebox.showwarning("No Analysis Available", "Run analysis before generating a summary.")
            self.status_label.config(text="Status: Run analysis first")
            return

        self.latest_summary = generate_incident_summary(self.latest_results)
        self.summary_box.delete("1.0", tk.END)
        self.summary_box.insert(tk.END, self.latest_summary)
        self.status_label.config(text="Status: Summary generated")

    def export_summary(self):
        if not self.latest_summary:
            messagebox.showwarning("No Summary Available", "Generate a summary before exporting.")
            self.status_label.config(text="Status: No summary to export")
            return

        file_path = filedialog.asksaveasfilename(
            title="Export Summary",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )

        if not file_path:
            self.status_label.config(text="Status: Export canceled")
            return

        try:
            with open(file_path, "w", encoding="utf-8") as file:
                file.write(self.latest_summary)

            self.status_label.config(text="Status: Summary exported successfully")
            messagebox.showinfo("Export Complete", f"Summary saved to:\n{file_path}")

        except Exception as e:
            messagebox.showerror("Export Error", str(e))
            self.status_label.config(text="Status: Export failed")

    def copy_summary(self):
        if not self.latest_summary:
            messagebox.showwarning("No Summary", "Generate a summary first.")
            self.status_label.config(text="Status: No summary to copy")
            return

        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.latest_summary)
            self.root.update()

            self.status_label.config(text="Status: Summary copied to clipboard")
            messagebox.showinfo("Copied", "Summary copied to clipboard!")

        except Exception as e:
            messagebox.showerror("Copy Error", str(e))
            self.status_label.config(text="Status: Copy failed")

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
        self.stop_monitoring()
        self.result_box.delete("1.0", tk.END)
        self.summary_box.delete("1.0", tk.END)
        self.filter_entry.delete(0, tk.END)
        self.current_output_lines = []
        self.latest_results = None
        self.latest_summary = ""
        self.status_label.config(text="Status: Cleared")
