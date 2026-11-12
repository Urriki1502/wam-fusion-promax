"""Presentation layer: what the Qt wallet windows show and allow the user to click.

Presentation decides only availability and wording. It never holds signing,
broadcast, reservation or custody authority: every action it enables is still
re-checked by the backend and the owned spend session on the wallet-owner
thread. Pure modules here (no PySide6 import) can be tested without a GUI.
May import application, domain and foundation; nothing below may import it.
"""
