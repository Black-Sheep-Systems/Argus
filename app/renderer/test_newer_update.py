"""Tests for moving a service to a newer version of its own major version (service-newer)."""
import importlib.machinery
import importlib.util
import json
import os

import pytest

HERE = os.path.dirname(__file__)
loader = importlib.machinery.SourceFileLoader("helper", os.path.join(HERE, "..", "argus-helper"))
spec = importlib.util.spec_from_loader("helper", loader)
h = importlib.util.module_from_spec(spec)
loader.exec_module(h)

DIG_OLD = "sha256:" + "a" * 64
DIG_NEW = "sha256:" + "b" * 64


def _row(image):
    return {"name": "bss-caddy", "image": image, "project": "bss", "workdir": "/opt/bss", "service": "caddy"}


def test_service_newer_refuses_without_a_newer_version_in_the_check(tmp_path, monkeypatch):
    # Arrange: the last check found no newer version for the service
    cache = tmp_path / "svc.json"
    cache.write_text(json.dumps({"services": [{"name": "bss-caddy", "image": "caddy:2.11.7@" + DIG_OLD}]}))
    monkeypatch.setattr(h, "SVC_CACHE", str(cache))
    # Act / Assert
    with pytest.raises(h.Refused, match="no newer version"):
        h.service_newer(["bss-caddy"])


def test_newer_script_refuses_when_the_check_is_out_of_date(monkeypatch):
    # Arrange: the check saw a different image than the one running now
    item = {"image": "caddy:2.11.6@" + DIG_OLD, "newer": {"ref": "caddy:2.11.9"}}
    row = _row("caddy:2.11.7@" + DIG_OLD)
    # Act / Assert
    with pytest.raises(h.Refused, match="out of date"):
        h._newer_script("bss-caddy", item, row, "/opt/bss", "caddy")


def test_newer_script_refuses_when_registry_has_no_digest(monkeypatch):
    # Arrange
    monkeypatch.setattr(h, "remote_digest", lambda ref: None)
    item = {"image": "caddy:2.11.7@" + DIG_OLD, "newer": {"ref": "caddy:2.11.9"}}
    row = _row("caddy:2.11.7@" + DIG_OLD)
    # Act / Assert
    with pytest.raises(h.Refused, match="did not answer"):
        h._newer_script("bss-caddy", item, row, "/opt/bss", "caddy")


def test_repin_newer_refuses_a_pin_for_another_image(monkeypatch):
    # Arrange: the new pin points at a different repository than the one the check named
    item = {"image": "caddy:2.11.7@" + DIG_OLD, "newer_ref": "caddy:2.11.9",
            "new_image": "other:2.11.9@" + DIG_NEW}
    row = _row("caddy:2.11.7@" + DIG_OLD)
    # Act / Assert
    with pytest.raises(h.Refused, match="can't be changed safely"):
        h._repin_script("bss-caddy", item, row, "/opt/bss", "caddy", newer=True)


def test_repin_newer_refuses_when_registry_moved_since_check(monkeypatch):
    # Arrange: the newer tag now resolves to a different digest than the check saw
    monkeypatch.setattr(h, "remote_digest", lambda ref: "sha256:" + "c" * 64)
    item = {"image": "caddy:2.11.7@" + DIG_OLD, "newer_ref": "caddy:2.11.9",
            "new_image": "caddy:2.11.9@" + DIG_NEW}
    row = _row("caddy:2.11.7@" + DIG_OLD)
    # Act / Assert
    with pytest.raises(h.Refused, match="registry changed"):
        h._repin_script("bss-caddy", item, row, "/opt/bss", "caddy", newer=True)


def test_newer_restore_test_runs_in_the_new_version(monkeypatch):
    # Arrange: MySQL 8.4 to a newer 8.4.x; the restore test must use the new image
    seen = {}
    real = h._dump_block

    def spy(target, kind, image):
        seen["image"] = image
        return real(target, kind, image)

    monkeypatch.setattr(h, "_dump_block", spy)
    monkeypatch.setattr(h, "remote_digest", lambda ref: DIG_NEW)
    monkeypatch.setattr(h, "_compose_files_with", lambda wd, image: [("/opt/bss/docker-compose.yml", 1)])
    monkeypatch.setattr(h, "run", lambda cmd, *a, **k: "caddy-data" if any("Mounts" in c for c in cmd) else "/opt/bss/docker-compose.yml")
    monkeypatch.setattr(h, "NOTED", [])
    item = {"image": "mysql:8.4", "newer_ref": "mysql:8.4.7", "new_image": "mysql:8.4.7@" + DIG_NEW}
    row = {"name": "folio-db", "image": "mysql:8.4", "project": "folio", "workdir": "/opt/folio", "service": "folio-db"}
    # Act
    h._repin_script("folio-db", item, row, "/opt/folio", "folio-db", newer=True)
    # Assert
    assert seen["image"] == "mysql:8.4.7@" + DIG_NEW
    assert h.NOTED[-1][2] == "newer"


def test_database_newer_version_stays_in_its_release_line(monkeypatch):
    # A move between release lines changes the data in place: not offered. Within the line: offered.
    assert h._newer_allowed("mysql:8.0", "8.4") is False
    assert h._newer_allowed("mysql:8.4", "8.4.7") is True


def test_non_database_newer_version_is_offered(monkeypatch):
    assert h._newer_allowed("caddy:2.11.7", "2.11.9") is True


def test_image_match_is_whole_name_only():
    pat = h._image_pattern("caddy:2.11.7")
    assert pat.search("image: caddy:2.11.7\n")
    assert not pat.search("image: caddy:2.11.7-alpine\n")
    assert not pat.search("image: mycaddy:2.11.7\n")


def test_undo_restores_the_kept_image_for_an_unpinned_service(monkeypatch):
    # Arrange: an unpinned database image; the undo must re-tag the kept image, not re-pull the floating tag
    monkeypatch.setattr(h, "remote_digest", lambda ref: DIG_NEW)
    monkeypatch.setattr(h, "_compose_files_with", lambda wd, image: [("/opt/folio/docker-compose.yml", 1)])
    monkeypatch.setattr(h, "run", lambda cmd, *a, **k: "folio-data" if any("Mounts" in c for c in cmd) else "/opt/folio/docker-compose.yml")
    monkeypatch.setattr(h, "NOTED", [])
    item = {"image": "mysql:8.4", "newer_ref": "mysql:8.4.7", "new_image": "mysql:8.4.7@" + DIG_NEW}
    row = {"name": "folio-db", "image": "mysql:8.4", "project": "folio", "workdir": "/opt/folio", "service": "folio-db"}
    script = h._repin_script("folio-db", item, row, "/opt/folio", "folio-db", newer=True)
    # Assert: a failed database upgrade keeps the failed data in a new volume, checks the copy,
    # and only then empties the live data and loads the verified dump into the previous version
    assert "Putting the database back on the previous version" in script
    assert script.index("argus-failed-folio-db") < script.index("find /d -mindepth 1 -delete")
    assert script.index("does not match") < script.index("find /d -mindepth 1 -delete")
    assert "gunzip -c \"$DUMP\"" in script
