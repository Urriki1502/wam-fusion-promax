"""Foundation layer: cross-cutting primitives with no wallet authority.

Lowest layer. Modules here import nothing from wam_regtest, never import
PySide6, and never hold keys, seeds, passwords or signing authority. Every
other layer (presentation, application, domain, infrastructure, custody,
qualification) may depend on it; it depends on none of them.
"""
