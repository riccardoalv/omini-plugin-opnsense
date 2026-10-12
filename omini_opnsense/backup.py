"""The firewall's configuration (config.xml) for Omini's history of versions."""

from __future__ import annotations

import re

from omini_sdk import PluginError

from omini_opnsense.client import Client, Forbidden, NotFound

DOWNLOAD = "/api/core/backup/download/this"
PRIVILEGE = "Diagnostics: Backup & Restore (System: Configuration: History on newer versions)"

# Parts that change without a configuration change: the revision stamp
# OPNsense writes on every save (time, user, description of the last change).
VOLATILE = re.compile(r"[ \t]*<revision>.*?</revision>[ \t]*\r?\n?", re.DOTALL)


def config_xml(c: Client) -> str:
    try:
        raw = c.get_text(DOWNLOAD)
    except Forbidden as e:
        raise PluginError(f"reading the configuration needs the privilege {PRIVILEGE}") from e
    except NotFound as e:
        raise PluginError("this OPNsense has no configuration backup API") from e
    if "<opnsense" not in raw:
        raise PluginError("OPNsense did not answer with its config.xml")
    return clean(raw)


def clean(raw: str) -> str:
    out = VOLATILE.sub("", raw.replace("\r\n", "\n"))
    return out.rstrip() + "\n"
