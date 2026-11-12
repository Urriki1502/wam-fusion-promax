"""Application layer: wallet command coordination between presentation and domain.

Holds application services that are neither Qt presentation nor wallet-domain
authority. Modules here must not import PySide6 and must not hold keys,
seeds, passwords or signing authority.
"""
