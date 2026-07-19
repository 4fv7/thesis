#!/usr/bin/env python3
"""Temporarily enable Wazuh JSON archives for a controlled experiment."""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import stat
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def enable(config: Path, backup: Path) -> None:
    if backup.exists():
        if sha256(backup) != sha256(config):
            raise SystemExit(f"Backup already exists and differs from config: {backup}")
    else:
        shutil.copy2(config, backup)
    config_stat = config.stat()
    original_mode = stat.S_IMODE(config_stat.st_mode)
    source = config.read_text(encoding="utf-8")
    parser = ET.XMLParser(target=ET.TreeBuilder(insert_comments=True))
    root = ET.fromstring(f"<wazuh-fragment>{source}</wazuh-fragment>", parser=parser)
    nodes = root.findall("./ossec_config/global/logall_json")
    if len(nodes) != 1:
        raise SystemExit(f"Expected one global/logall_json node, found {len(nodes)}")
    if (nodes[0].text or "").strip() != "no":
        raise SystemExit("Expected logall_json to be disabled before capture")
    disabled_tag = "<logall_json>no</logall_json>"
    if source.count(disabled_tag) != 1:
        raise SystemExit("Could not identify the unique logall_json text node")
    enabled_source = source.replace(
        disabled_tag, "<logall_json>yes</logall_json>", 1
    )

    with tempfile.NamedTemporaryFile(
        mode="wb", dir=config.parent, prefix="ossec.conf.", delete=False
    ) as handle:
        temporary = Path(handle.name)
        handle.write(enabled_source.encode("utf-8"))
    os.chmod(temporary, original_mode)
    os.chown(temporary, config_stat.st_uid, config_stat.st_gid)
    os.replace(temporary, config)

    print(f"backup_sha256={sha256(backup)}")
    print(f"enabled_sha256={sha256(config)}")
    print("logall_json=yes")


def restore(config: Path, backup: Path) -> None:
    if not backup.is_file():
        raise SystemExit(f"Backup not found: {backup}")
    backup_hash = sha256(backup)
    shutil.copy2(backup, config)
    restored_hash = sha256(config)
    if restored_hash != backup_hash:
        raise SystemExit("Restored Wazuh configuration hash does not match backup")
    backup.unlink()
    print(f"restored_sha256={restored_hash}")
    print("logall_json restored")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("enable", "restore"))
    parser.add_argument(
        "--config", type=Path, default=Path("/var/ossec/etc/ossec.conf")
    )
    parser.add_argument(
        "--backup", type=Path, default=Path("/tmp/ossec.conf.dataset-capture.backup")
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.mode == "enable":
        enable(args.config, args.backup)
    else:
        restore(args.config, args.backup)


if __name__ == "__main__":
    main()
