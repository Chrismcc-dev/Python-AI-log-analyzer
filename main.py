import tkinter as tk
from gui import LogAnalyzerApp


def main():
    root = tk.Tk()
    app = LogAnalyzerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()