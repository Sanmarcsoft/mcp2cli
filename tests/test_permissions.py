"""Tests for credential file/directory permission hardening.

Covers the security patch on branch ``security/credential-permission-hardening``:

- OAuth ``tokens.json`` / ``tokens_meta.json`` / ``client.json`` land at 0o600.
- ``CACHE_DIR`` / ``OAUTH_DIR`` (and per-server subdir) / ``CONFIG_DIR`` /
  ``SESSIONS_DIR`` land at 0o700.
- ``baked.json`` lands at 0o600.
- The permission fix survives a permissive umask (the whole point of the
  explicit ``chmod`` -- ``mkdir(mode=...)`` alone is masked by umask).
- A world-readable file left by an older release is tightened on next write.
- The session daemon never exposes secrets in its ``ps``-visible argv.
- ``resolve_secret`` warns (but does not change behaviour) on literal values.
"""

import json
import os
import stat

import anyio
import pytest

import mcp2cli


def _mode(path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


@pytest.fixture
def permissive_umask():
    """Force a fully-permissive umask so an unguarded mkdir/open would land
    world-readable; restores the previous umask afterwards."""
    old = os.umask(0o000)
    try:
        yield
    finally:
        os.umask(old)


class TestDirectoryPermissions:
    def test_save_cache_makes_cache_dir_private(self, tmp_path, monkeypatch):
        cache = tmp_path / "cache"
        monkeypatch.setattr(mcp2cli, "CACHE_DIR", cache)
        mcp2cli.save_cache("k", {"a": 1})
        assert _mode(cache) == 0o700

    def test_save_usage_makes_cache_dir_private(self, tmp_path, monkeypatch):
        cache = tmp_path / "cache"
        monkeypatch.setattr(mcp2cli, "CACHE_DIR", cache)
        monkeypatch.setattr(mcp2cli, "USAGE_FILE", cache / "usage.json")
        mcp2cli._save_usage({"src": {}})
        assert _mode(cache) == 0o700

    def test_oauth_dir_and_subdir_are_private(self, tmp_path, monkeypatch):
        oauth = tmp_path / "oauth"
        monkeypatch.setattr(mcp2cli, "OAUTH_DIR", oauth)
        storage = mcp2cli.FileTokenStorage("https://example.com/mcp")
        assert _mode(oauth) == 0o700
        assert _mode(storage._dir) == 0o700

    def test_baked_config_dir_is_private(self, tmp_path, monkeypatch):
        config_dir = tmp_path / "config"
        monkeypatch.setattr(mcp2cli, "CONFIG_DIR", config_dir)
        monkeypatch.setattr(mcp2cli, "BAKED_FILE", config_dir / "baked.json")
        mcp2cli._save_baked_all({"myapi": {"source": "https://example.com"}})
        assert _mode(config_dir) == 0o700


class TestFilePermissions:
    def test_tokens_and_meta_are_0600(self, tmp_path, monkeypatch):
        monkeypatch.setattr(mcp2cli, "OAUTH_DIR", tmp_path / "oauth")
        storage = mcp2cli.FileTokenStorage("https://example.com/mcp")

        async def _run():
            from mcp.shared.auth import OAuthToken

            token = OAuthToken(
                access_token="test-access",
                token_type="Bearer",
                refresh_token="test-refresh",
                expires_in=3600,
            )
            await storage.set_tokens(token)

        anyio.run(_run)
        assert _mode(storage._tokens_path) == 0o600
        assert _mode(storage._tokens_meta_path) == 0o600

    def test_client_info_is_0600(self, tmp_path, monkeypatch):
        monkeypatch.setattr(mcp2cli, "OAUTH_DIR", tmp_path / "oauth")
        storage = mcp2cli.FileTokenStorage("https://example.com/mcp")

        async def _run():
            from mcp.shared.auth import OAuthClientInformationFull

            info = OAuthClientInformationFull(
                client_id="my-client",
                client_secret="my-secret",
                redirect_uris=["http://127.0.0.1:9999/callback"],
            )
            await storage.set_client_info(info)

        anyio.run(_run)
        assert _mode(storage._client_path) == 0o600

    def test_baked_file_is_0600(self, tmp_path, monkeypatch):
        config_dir = tmp_path / "config"
        monkeypatch.setattr(mcp2cli, "CONFIG_DIR", config_dir)
        monkeypatch.setattr(mcp2cli, "BAKED_FILE", config_dir / "baked.json")
        mcp2cli._save_baked_all(
            {"myapi": {"source": "https://example.com", "auth_headers": []}}
        )
        assert _mode(mcp2cli.BAKED_FILE) == 0o600

    def test_write_private_tightens_existing_world_readable_file(self, tmp_path):
        p = tmp_path / "tokens.json"
        p.write_text("old")
        os.chmod(p, 0o644)
        mcp2cli._write_private(p, "new-secret")
        assert p.read_text() == "new-secret"
        assert _mode(p) == 0o600


class TestUmaskIndependence:
    """The explicit chmod is what makes the fix hold regardless of umask;
    mkdir(mode=)/os.open(mode=) alone would be masked."""

    def test_mkdir_private_ignores_permissive_umask(self, tmp_path, permissive_umask):
        d = tmp_path / "secret-dir"
        mcp2cli._mkdir_private(d)
        assert _mode(d) == 0o700

    def test_write_private_ignores_permissive_umask(self, tmp_path, permissive_umask):
        f = tmp_path / "secret-file"
        mcp2cli._write_private(f, "payload")
        assert _mode(f) == 0o600

    def test_oauth_files_private_under_permissive_umask(
        self, tmp_path, monkeypatch, permissive_umask
    ):
        monkeypatch.setattr(mcp2cli, "OAUTH_DIR", tmp_path / "oauth")
        storage = mcp2cli.FileTokenStorage("https://example.com/mcp")

        async def _run():
            from mcp.shared.auth import OAuthToken

            await storage.set_tokens(
                OAuthToken(access_token="a", token_type="Bearer", refresh_token="r")
            )

        anyio.run(_run)
        assert _mode(storage._dir) == 0o700
        assert _mode(storage._tokens_path) == 0o600


class TestSessionDaemonSecretExposure:
    def test_daemon_argv_has_no_secret_and_config_is_private(
        self, tmp_path, monkeypatch
    ):
        sessions = tmp_path / "sessions"
        monkeypatch.setattr(mcp2cli, "SESSIONS_DIR", sessions)

        sentinel = "s3ntinel-secret-token-DO-NOT-LEAK"
        captured = {}

        class FakeProc:
            pid = 4321
            returncode = 0

            def poll(self):
                return None

            def kill(self):
                pass

        def fake_popen(argv, **kwargs):
            captured["argv"] = list(argv)
            # Release the stderr log handle the parent opened for the child.
            err = kwargs.get("stderr")
            if hasattr(err, "close"):
                err.close()
            # Pretend the daemon came up by creating its socket file so
            # session_start's readiness loop returns instead of timing out.
            sock = mcp2cli._session_sock_path("mysess")
            sock.parent.mkdir(parents=True, exist_ok=True)
            sock.write_bytes(b"")
            return FakeProc()

        monkeypatch.setattr(mcp2cli.subprocess, "Popen", fake_popen)

        mcp2cli.session_start(
            "mysess",
            "https://example.com/mcp",
            False,
            [("Authorization", f"Bearer {sentinel}")],
            {"API_KEY": sentinel},
        )

        # Session dir is locked down.
        assert _mode(sessions) == 0o700

        # The ps-visible argv must not carry the secret anywhere.
        joined = " ".join(captured["argv"])
        assert sentinel not in joined

        # The secret lives only in a private 0o600 file referenced by path.
        config_path = sessions / "mysess.config.json"
        assert config_path.exists()
        assert _mode(config_path) == 0o600
        assert sentinel in config_path.read_text()
        assert str(config_path) in joined

    def test_run_session_daemon_reads_and_unlinks_config(
        self, tmp_path, monkeypatch
    ):
        sessions = tmp_path / "sessions"
        sessions.mkdir()
        monkeypatch.setattr(mcp2cli, "SESSIONS_DIR", sessions)

        config_path = sessions / "d.config.json"
        payload = {
            "name": "d",
            "source": "https://example.com/mcp",
            "is_stdio": False,
            "auth_headers": [["Authorization", "Bearer x"]],
            "env_vars": {},
            "transport": "auto",
        }
        mcp2cli._write_private(config_path, json.dumps(payload))

        ran = {}

        # Patch the anyio module attribute (the daemon re-imports anyio
        # locally, so patching the module object is what intercepts it) to a
        # no-op so no real MCP connection is attempted.
        def fake_run(fn, *args, **kwargs):
            ran["called"] = True

        monkeypatch.setattr(anyio, "run", fake_run)

        mcp2cli._run_session_daemon(str(config_path))

        assert ran.get("called") is True
        # Config file is unlinked immediately after being read.
        assert not config_path.exists()


class TestResolveSecretWarning:
    def test_literal_warns_but_returns_value(self, capsys):
        assert mcp2cli.resolve_secret("plain-literal") == "plain-literal"
        assert "visible in process listings" in capsys.readouterr().err

    def test_env_reference_does_not_warn(self, monkeypatch, capsys):
        monkeypatch.setenv("X_SECRET_VAR", "value")
        assert mcp2cli.resolve_secret("env:X_SECRET_VAR") == "value"
        assert "visible in process listings" not in capsys.readouterr().err

    def test_file_reference_does_not_warn(self, tmp_path, capsys):
        f = tmp_path / "secret.txt"
        f.write_text("value")
        assert mcp2cli.resolve_secret(f"file:{f}") == "value"
        assert "visible in process listings" not in capsys.readouterr().err


def _isolate_paths(tmp_path, monkeypatch):
    cache = tmp_path / "cache"
    oauth = tmp_path / "oauth"
    config = tmp_path / "config"
    sessions = tmp_path / "sessions"
    monkeypatch.setattr(mcp2cli, "CACHE_DIR", cache)
    monkeypatch.setattr(mcp2cli, "OAUTH_DIR", oauth)
    monkeypatch.setattr(mcp2cli, "CONFIG_DIR", config)
    monkeypatch.setattr(mcp2cli, "BAKED_FILE", config / "baked.json")
    monkeypatch.setattr(mcp2cli, "SESSIONS_DIR", sessions)
    monkeypatch.setattr(mcp2cli, "USAGE_FILE", cache / "usage.json")


class TestSecurityGateHardening:
    def test_oauth_preseed_client_json_is_0600(
        self, tmp_path, monkeypatch, permissive_umask
    ):
        _isolate_paths(tmp_path, monkeypatch)
        mcp2cli.build_oauth_provider(
            "https://example.com/mcp",
            client_id="cid",
            client_secret="S3CRET",
            flow="authorization_code",
        )
        storage = mcp2cli.FileTokenStorage("https://example.com/mcp")
        assert storage._client_path.exists()
        assert _mode(storage._client_path) == 0o600
        content = storage._client_path.read_text()
        assert "S3CRET" in content

    def test_no_credential_file_or_dir_is_group_or_world_accessible(
        self, tmp_path, monkeypatch, permissive_umask
    ):
        _isolate_paths(tmp_path, monkeypatch)

        # 1. save_cache
        mcp2cli.save_cache("cache_entry", {"schemas": ["secret-schema"]})

        # 2. _save_usage
        mcp2cli._save_usage({"src_hash": {"my_tool": {"count": 1}}})

        # 3. FileTokenStorage set_tokens and set_client_info
        storage = mcp2cli.FileTokenStorage("https://example.com/mcp-storage")
        from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

        async def _exercise_storage():
            token = OAuthToken(
                access_token="secret-access-token",
                token_type="Bearer",
                refresh_token="secret-refresh-token",
                expires_in=3600,
            )
            await storage.set_tokens(token)
            info = OAuthClientInformationFull(
                client_id="storage-client-id",
                client_secret="storage-client-secret",
                redirect_uris=["http://127.0.0.1:9999/callback"],
            )
            await storage.set_client_info(info)

        anyio.run(_exercise_storage)

        # 4. OAuth pre-seed
        mcp2cli.build_oauth_provider(
            "https://example.com/mcp-preseed",
            client_id="preseed-id",
            client_secret="preseed-secret",
            flow="authorization_code",
        )

        # 5. _save_baked_all
        mcp2cli._save_baked_all(
            {
                "baked_srv": {
                    "source": "https://example.com",
                    "auth_headers": [("Authorization", "Bearer tok")],
                }
            }
        )

        # 6. session_start (using the same fakes as test c)
        class FakeProc:
            pid = 5678
            returncode = 0

            def poll(self):
                return None

            def kill(self):
                pass

        def fake_popen(argv, **kwargs):
            err = kwargs.get("stderr")
            if hasattr(err, "close"):
                err.close()
            sock = mcp2cli._session_sock_path("sess_walk")
            mcp2cli._write_private(sock, "")
            return FakeProc()

        monkeypatch.setattr(mcp2cli.subprocess, "Popen", fake_popen)
        mcp2cli.session_start(
            "sess_walk",
            "https://example.com/mcp",
            False,
            [("Authorization", "Bearer token-123")],
            {"API_KEY": "key-123"},
            roots=["file:///tmp/project-walk"],
        )

        # Directory-walk sweep: assert every file and dir has no group/other bits
        found_paths = list(tmp_path.rglob("*"))
        assert len(found_paths) > 0, "Expected files and directories to be created under tmp_path"
        for p in found_paths:
            mode = _mode(p)
            assert (
                mode & 0o077 == 0
            ), f"Path {p} has unsafe permissions: {oct(mode)} (group/other accessible)"

    def test_session_start_passes_roots_via_private_config_not_argv(
        self, tmp_path, monkeypatch, permissive_umask
    ):
        _isolate_paths(tmp_path, monkeypatch)

        auth_secret = "secret-auth-header-val"
        env_secret = "secret-env-var-val"
        captured = {}

        class FakeProc:
            pid = 9999
            returncode = 0

            def poll(self):
                return None

            def kill(self):
                pass

        def fake_popen(argv, **kwargs):
            captured["argv"] = list(argv)
            err = kwargs.get("stderr")
            if hasattr(err, "close"):
                err.close()
            sock = mcp2cli._session_sock_path("sess_test")
            mcp2cli._write_private(sock, "")
            return FakeProc()

        monkeypatch.setattr(mcp2cli.subprocess, "Popen", fake_popen)

        mcp2cli.session_start(
            "sess_test",
            "https://example.com/mcp",
            False,
            [("Authorization", f"Bearer {auth_secret}")],
            {"API_KEY": env_secret},
            roots=["file:///tmp/project-a"],
        )

        joined_argv = " ".join(captured["argv"])
        assert auth_secret not in joined_argv
        assert env_secret not in joined_argv

        config_path = mcp2cli.SESSIONS_DIR / "sess_test.config.json"
        assert config_path.exists()
        assert _mode(config_path) == 0o600
        config_data = json.loads(config_path.read_text())
        assert config_data["roots"] == ["file:///tmp/project-a"]

        log_path = mcp2cli._session_log_path("sess_test")
        assert log_path.exists()
        assert _mode(log_path) == 0o600
