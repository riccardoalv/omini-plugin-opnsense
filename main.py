"""Omini plugin for OPNsense (entrypoint run by the Omini core)."""

from omini_sdk import plugin

from omini_opnsense.collect import apply, backup, collect, test

plugin.collect(collect)
plugin.test(test)
plugin.apply(apply)
if hasattr(plugin, "backup"):  # Omini 1.3 and later
    plugin.backup(backup)

if __name__ == "__main__":
    plugin.run()
