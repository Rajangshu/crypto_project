# utils/display.py
"""
Colored CLI output helper.
"""
import sys

def c(text, color):
    colors = {"red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m", "blue": "\033[94m", "end": "\033[0m"}
    return f"{colors.get(color, '')}{text}{colors['end']}"

def banner():
    print(c("\n=== SecureTalk: Offline Encrypted Chat Messenger ===", "blue"))
