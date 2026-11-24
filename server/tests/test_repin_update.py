"""Tests for the "repin" update action in argus-helper.

A repin moves a pinned image (for example caddy:2.11.7@sha256:...) to a newer
build by changing its pin in the compose file, keeping a backup copy, and
restarting the service. These tests only exercise _container_update() and
_repin_script() (through _container_update): they build the script, they never
run it. No Docker, no network. container_table(), compose_dir_ok(), the update
cache (SVC_CACHE), remote_digest() and the one docker call made by the repin
(run, which reads the compose project label) are replaced with monkeypatched
fakes, and subprocess.run is replaced with a fake that fails the test if
anything tries to run a command."""
import importlib.machinery
import importlib.util
import json
import os
import re
import shlex
import sys

import pytest

sys.dont_write_bytecode = True          # don't leave a __pycache__ in server/

HERE = os.path.dirname(os.path.abspath(__file__))
loader = importlib.machinery.SourceFileLoader("helper", os.path.join(HERE, "..", "argus-helper"))
spec = importlib.util.spec_from_loader("helper", loader)
h = importlib.util.module_from_spec(spec)
loader.exec_module(h)

SERVICE = "shop"
OLD_BASE = "caddy:2.11.7"
OLD_DIGEST = "sha256:" + "c" * 64
NEW_DIGEST = "sha256:" + "d" * 64
OLD_IMAGE = OLD_BASE + "@" + OLD_DIGEST
NEW_IMAGE = OLD_BASE + "@" + NEW_DIGEST


def _no_docker(*args, **kwargs):
    raise AssertionError("the repin script builder must not run a command")


def _item(image, new_image):
    """A cached update item as service-updates writes it: the image the check saw, and the new pin."""
    return {"name": SERVICE, "can_update": True, "action": "repin", "image": image, "new_image": new_image}


def _row(wd, image):
    """A running container as container_table() reports it."""
    return {"name": SERVICE, "image": image, "project": SERVICE, "workdir": str(wd),
            "service": SERVICE, "image_id": "sha256:cur"}


def _write_cache(items):
    with open(h.SVC_CACHE, "w") as f:
        json.dump({"services": items}, f)


def _stub_run(monkeypatch, config_files):
    """Stub the one docker call the repin makes: the compose project label of the container."""
    def fake_run(cmd, timeout=20, stderr_too=False):
        if cmd[:2] == ["docker", "inspect"] and cmd[-1] == SERVICE and any("config_files" in c for c in cmd):
            return config_files
        if cmd[:2] == ["docker", "inspect"] and any("Mounts" in c for c in cmd):
            return "shop-data"   # the named volume that holds the database data
        raise AssertionError("unexpected command in the repin check: " + repr(cmd))
    monkeypatch.setattr(h, "run", fake_run)


@pytest.fixture
def compose_dir(tmp_path, monkeypatch):
    """A fake compose folder with one compose file that pins the old image once.
    The service was started from that file, and the registry still has the new digest.
    Returns the folder; tests rewrite docker-compose.yml when they need other text."""
    wd = tmp_path / "shop"
    wd.mkdir()
    cf = wd / "docker-compose.yml"
    cf.write_text("services:\n  " + SERVICE + ":\n    image: " + OLD_IMAGE + "\n")
    cache = tmp_path / "service-updates.json"
    cache.write_text(json.dumps({"services": [_item(OLD_IMAGE, NEW_IMAGE)]}))
    monkeypatch.setattr(h, "SVC_CACHE", str(cache))
    monkeypatch.setattr(h, "container_table", lambda: [_row(wd, OLD_IMAGE)])
    monkeypatch.setattr(h, "compose_dir_ok", lambda p: p)
    monkeypatch.setattr(h, "remote_digest", lambda ref: NEW_DIGEST)
    monkeypatch.setattr(h.subprocess, "run", _no_docker)
    _stub_run(monkeypatch, str(cf) + "\n")
    return wd


def _set_row_image(monkeypatch, wd, image):
    monkeypatch.setattr(h, "container_table", lambda: [_row(wd, image)])


def test_repin_single_match_returns_script_with_new_ref_backup_and_recreate(compose_dir):
    # Arrange: the fixture's compose file pins the old image exactly once
    cf = shlex.quote(str(compose_dir / "docker-compose.yml"))
    # Act
    script = h._container_update(SERVICE)
    # Assert: the script pulls the new ref, keeps a backup, and force-recreates the service from the same file
    assert "docker pull " + NEW_IMAGE in script
    assert "docker-compose.yml.before-update" in script
    assert "--force-recreate" in script
    assert "docker compose -f " + cf + " up -d --no-deps --force-recreate" in script


def test_repin_single_match_script_checks_restart_and_new_image_id(compose_dir):
    # Arrange: the fixture's compose file pins the old image exactly once
    # Act
    script = h._container_update(SERVICE)
    # Assert: the restart step is named, and the running image id is compared with the new image
    assert "4/4 Restarting " + SERVICE in script
    assert "docker image inspect --format '{{.Id}}' " + NEW_IMAGE in script


def test_repin_single_match_does_not_change_compose_file_while_building_script(compose_dir):
    # Arrange: the compose file as written by the fixture
    before = (compose_dir / "docker-compose.yml").read_text()
    # Act
    h._container_update(SERVICE)
    # Assert: only the script is built; the pin is changed when the script runs, not here
    assert (compose_dir / "docker-compose.yml").read_text() == before


def test_repin_old_image_without_digest_is_refused(compose_dir, monkeypatch):
    # Arrange: the running container's image has no digest pin (the check saw the same image)
    _set_row_image(monkeypatch, compose_dir, OLD_BASE)
    _write_cache([_item(OLD_BASE, OLD_BASE + "@" + NEW_DIGEST)])
    # Act / Assert
    with pytest.raises(h.Refused):
        h._container_update(SERVICE)


def test_repin_compose_file_with_zero_matches_is_refused(compose_dir):
    # Arrange: the compose file no longer mentions the old image
    (compose_dir / "docker-compose.yml").write_text(
        "services:\n  " + SERVICE + ":\n    image: caddy:2.11.6\n")
    # Act / Assert
    with pytest.raises(h.Refused):
        h._container_update(SERVICE)


def test_repin_compose_file_with_two_matches_is_refused(compose_dir):
    # Arrange: the old image appears twice in the one compose file
    (compose_dir / "docker-compose.yml").write_text(
        "services:\n  " + SERVICE + ":\n    image: " + OLD_IMAGE + "\n"
        "  other:\n    image: " + OLD_IMAGE + "\n")
    # Act / Assert
    with pytest.raises(h.Refused):
        h._container_update(SERVICE)


@pytest.mark.parametrize("bad_digest", [
    "sha256:" + "d" * 63,            # one character short
    "sha256:" + "D" * 64,            # upper-case hex
    "sha256:" + "g" * 64,            # not hex
    "md5:" + "d" * 32,               # wrong algorithm
    "sha256:" + "d" * 64 + "\n",     # trailing newline
])
def test_repin_malformed_new_digest_is_refused(compose_dir, bad_digest):
    # Arrange: the cached item (matching the running image) carries a new digest that is not a valid sha256 digest
    _write_cache([_item(OLD_IMAGE, OLD_BASE + "@" + bad_digest)])
    # Act / Assert
    with pytest.raises(h.Refused):
        h._container_update(SERVICE)


def _setup_pinned(tmp_path, monkeypatch, old, new):
    """A compose folder whose one service runs `old`, with the cache holding `new` for it.
    Returns (wd, compose file path). Same fakes as the compose_dir fixture."""
    wd = tmp_path / "db"
    wd.mkdir()
    cf = wd / "docker-compose.yml"
    cf.write_text("services:\n  " + SERVICE + ":\n    image: " + old + "\n")
    cache = tmp_path / "service-updates.json"
    cache.write_text(json.dumps({"services": [_item(old, new)]}))
    monkeypatch.setattr(h, "SVC_CACHE", str(cache))
    monkeypatch.setattr(h, "container_table", lambda: [_row(wd, old)])
    monkeypatch.setattr(h, "compose_dir_ok", lambda p: p)
    monkeypatch.setattr(h, "remote_digest", lambda ref: NEW_DIGEST)
    monkeypatch.setattr(h.subprocess, "run", _no_docker)
    _stub_run(monkeypatch, str(cf))
    return wd, cf


DB_CASES = {
    "postgres": ("pg_dumpall -U", "dump complete", "mysqldump", "mariadb-dump"),
    "mysql": ("mysqldump -uroot", "Dump completed", "mariadb-dump", "pg_dumpall"),
    "mariadb": ("mariadb-dump -uroot", "Dump completed", "mysqldump", "pg_dumpall"),
}


@pytest.mark.parametrize("db_repo", ["postgres", "mysql", "mariadb"])
def test_database_dumps_before_update(tmp_path, monkeypatch, db_repo):
    # Arrange: a database image is pinned in its compose file and the cache has a newer digest for it
    old = db_repo + ":16.4@" + OLD_DIGEST
    new = db_repo + ":16.4@" + NEW_DIGEST
    wd, cf = _setup_pinned(tmp_path, monkeypatch, old, new)
    before = cf.read_text()
    dump_cmd, done, other_tool, wrong_tool = DB_CASES[db_repo]
    # Act
    script = h._container_update(SERVICE)
    # Assert: the dump runs first, to a file named for the target, with the matching tool and completion check
    assert "0/4 Backing up the database first" in script
    assert "/var/backups/argus-db/" + SERVICE + "-" in script
    assert dump_cmd in script
    assert other_tool not in script and wrong_tool not in script
    assert done in script
    assert script.index("0/4 Backing up") < script.index("1/4 Getting the new build")
    # Assert: the compose file is unchanged while the script is built
    assert cf.read_text() == before


def test_repin_changed_registry_digest_is_refused(compose_dir, monkeypatch):
    # Arrange: the registry now says the tag points at a third digest, not the one the check saw
    monkeypatch.setattr(h, "remote_digest", lambda ref: "sha256:" + "e" * 64)
    before = (compose_dir / "docker-compose.yml").read_text()
    # Act / Assert: refused before any change, and the compose file is untouched
    with pytest.raises(h.Refused, match="registry changed"):
        h._container_update(SERVICE)
    assert (compose_dir / "docker-compose.yml").read_text() == before


def test_repin_config_label_naming_other_file_is_refused(compose_dir, monkeypatch):
    # Arrange: the service was started from a different compose file than the one holding the pin
    other = compose_dir / "override.yml"
    _stub_run(monkeypatch, str(other) + "\n")
    # Act / Assert
    with pytest.raises(h.Refused, match="more than one compose file"):
        h._container_update(SERVICE)


def test_repin_config_label_naming_two_files_is_refused(compose_dir, monkeypatch):
    # Arrange: the service was started from two compose files, one of them the file holding the pin
    cf = compose_dir / "docker-compose.yml"
    other = compose_dir / "override.yml"
    _stub_run(monkeypatch, str(cf) + "," + str(other) + "\n")
    # Act / Assert
    with pytest.raises(h.Refused, match="more than one compose file"):
        h._container_update(SERVICE)


def test_repin_script_has_rollback_tag_and_compose_file_flag(compose_dir):
    # Arrange: the fixture's compose file pins the old image exactly once
    cf = shlex.quote(str(compose_dir / "docker-compose.yml"))
    # Act
    script = h._container_update(SERVICE)
    # Assert: the current image is tagged for rollback, and the restart names the compose file with -f
    assert re.search(r"docker tag .*argus-rollback/" + SERVICE + r":before-update", script)
    assert "docker compose -f " + cf + " up" in script


def test_compose_files_with_ignores_non_yaml_files(tmp_path):
    # Arrange: the image text is in a yaml file, a yml file, and several non-yaml files
    (tmp_path / "docker-compose.yml").write_text("image: " + OLD_IMAGE + "\n")
    (tmp_path / "override.yaml").write_text("image: " + OLD_IMAGE + "\n")
    (tmp_path / "notes.txt").write_text("image: " + OLD_IMAGE + "\n")
    (tmp_path / "compose.json").write_text('{"image": "' + OLD_IMAGE + '"}\n')
    (tmp_path / "Dockerfile").write_text("FROM " + OLD_IMAGE + "\n")
    # Act
    hits = h._compose_files_with(str(tmp_path), OLD_IMAGE)
    # Assert: only the two yaml files are returned, each with one mention
    names = sorted(os.path.basename(p) for p, _ in hits)
    assert names == ["docker-compose.yml", "override.yaml"]
    assert all(count == 1 for _, count in hits)


@pytest.mark.parametrize("nosql_repo", ["mongo", "redis"])
def test_nosql_database_image_is_refused(tmp_path, monkeypatch, nosql_repo):
    # Arrange: a database type with no dump step here is pinned and has a newer digest
    old = nosql_repo + ":7.2@" + OLD_DIGEST
    new = nosql_repo + ":7.2@" + NEW_DIGEST
    wd, cf = _setup_pinned(tmp_path, monkeypatch, old, new)
    before = cf.read_text()
    # Act / Assert: refused, and the compose file is untouched
    with pytest.raises(h.Refused, match="database type"):
        h._container_update(SERVICE)
    assert cf.read_text() == before


def test_latest_tag_is_refused(tmp_path, monkeypatch):
    # Arrange: the pin is on the tag 'latest', which the registry can move to a new major version
    old = OLD_BASE.split(":")[0] + ":latest@" + OLD_DIGEST
    new = OLD_BASE.split(":")[0] + ":latest@" + NEW_DIGEST
    wd, cf = _setup_pinned(tmp_path, monkeypatch, old, new)
    before = cf.read_text()
    # Act / Assert: refused before any change
    with pytest.raises(h.Refused, match="latest"):
        h._container_update(SERVICE)
    assert cf.read_text() == before


def test_digitless_tag_is_accepted(tmp_path, monkeypatch):
    # Arrange: the pin is on a tag with no digit in it (v2), pinned by digest, with a newer digest cached
    old = "myapp:v2@" + OLD_DIGEST
    new = "myapp:v2@" + NEW_DIGEST
    wd, cf = _setup_pinned(tmp_path, monkeypatch, old, new)
    # Act
    script = h._container_update(SERVICE)
    # Assert: a script is built that pulls the new ref and restarts the service on it
    assert "docker pull " + new in script
    assert "4/4 Restarting " + SERVICE in script
    assert "0/4 Backing up" not in script


def test_non_database_script_has_no_backup_step(compose_dir):
    # Arrange: the fixture's compose file pins a non-database image (caddy)
    # Act
    script = h._container_update(SERVICE)
    # Assert: no dump step is added to a non-database update
    assert "0/4 Backing up" not in script
    assert "pg_dumpall" not in script and "mysqldump" not in script and "mariadb-dump" not in script


DB_WORD_IMAGES = [
    "valkey/valkey:7@" + OLD_DIGEST,                          # DB_WORDS: valkey
    "mcr.microsoft.com/mssql/server:2022-latest@" + OLD_DIGEST,  # name contains "sql"
    "percona/percona-server:8.0@" + OLD_DIGEST,               # DB_WORDS: percona
    "nds-db:8.0@" + OLD_DIGEST,                               # DB_WORDS: "-db"
]


@pytest.mark.parametrize("old", DB_WORD_IMAGES, ids=["valkey", "mssql-sql-in-name", "percona", "nds-db"])
def test_db_word_image_is_refused_as_database(tmp_path, monkeypatch, old):
    # Arrange: an image whose name holds a database word (or "sql") is pinned and has a newer digest cached
    new = old.split("@", 1)[0] + "@" + NEW_DIGEST
    wd, cf = _setup_pinned(tmp_path, monkeypatch, old, new)
    before = cf.read_text()
    # Act / Assert: refused as a database type, and the compose file is untouched
    with pytest.raises(h.Refused, match="looks like a database"):
        h._container_update(SERVICE)
    assert cf.read_text() == before


@pytest.mark.parametrize("db_repo, pw_var", [("mysql", "MYSQL_ROOT_PASSWORD"), ("mariadb", "MARIADB_ROOT_PASSWORD")])
def test_mysql_family_dump_password_comes_from_env_var_not_argv(tmp_path, monkeypatch, db_repo, pw_var):
    # Arrange: a MySQL-family database image is pinned and has a newer digest cached
    old = db_repo + ":10.11@" + OLD_DIGEST
    new = db_repo + ":10.11@" + NEW_DIGEST
    _setup_pinned(tmp_path, monkeypatch, old, new)
    # Act
    script = h._container_update(SERVICE)
    # Assert: the password is read from the container's environment, and never passed as a -p argument
    assert 'MYSQL_PWD="$' + pw_var + '"' in script
    assert '-p"' not in script
    assert '-p"$' not in script


@pytest.mark.parametrize("db_repo", ["postgres", "mysql", "mariadb"])
def test_failed_dump_removes_partial_file(tmp_path, monkeypatch, db_repo):
    # Arrange: a database image is pinned and has a newer digest cached
    old = db_repo + ":16.4@" + OLD_DIGEST
    new = db_repo + ":16.4@" + NEW_DIGEST
    _setup_pinned(tmp_path, monkeypatch, old, new)
    # Act
    script = h._container_update(SERVICE)
    # Assert: the failure branch of the dump deletes the partial $DUMP file before stopping
    failure = script.index("The backup did not finish")
    assert 'rm -f "$PART"' in script
    assert script.index('rm -f "$PART"') < failure


@pytest.mark.parametrize("db_repo", ["postgres", "mysql", "mariadb"])
def test_backup_folder_is_created_root_only_mode_700(tmp_path, monkeypatch, db_repo):
    # Arrange: a database image is pinned and has a newer digest cached
    old = db_repo + ":16.4@" + OLD_DIGEST
    new = db_repo + ":16.4@" + NEW_DIGEST
    _setup_pinned(tmp_path, monkeypatch, old, new)
    # Act
    script = h._container_update(SERVICE)
    # Assert: the backup folder is made with mode 700, owned by root
    assert "install -d -m 700 -o root -g root /var/backups/argus-db" in script
