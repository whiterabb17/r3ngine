"""Minimal Metasploit MSFRPC (msgpack) client for allowlisted aux/post execute.

Uses the classic msgpack RPC on the Docker network. Injectable for tests via
``MsfrpcClient`` constructor hooks / monkeypatch of ``call``.
"""
from __future__ import annotations

import logging
import os
import socket
import time
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class MsfrpcError(Exception):
    def __init__(self, message: str, status: int = 502):
        super().__init__(message)
        self.status = status


def _rpc_config() -> dict[str, Any]:
    url = (os.environ.get('MSF_RPC_URL') or '').strip()
    host = (os.environ.get('MSF_RPC_HOST') or '').strip()
    port = int(os.environ.get('MSF_RPC_PORT') or '55553')
    user = os.environ.get('MSF_RPC_USER') or 'msf'
    password = os.environ.get('MSF_RPC_PASS') or os.environ.get('MSF_RPC_PASSWORD') or ''
    ssl = (os.environ.get('MSF_RPC_SSL') or 'false').lower() in ('1', 'true', 'yes')
    timeout = float(os.environ.get('MSF_RPC_TIMEOUT') or '60')
    if url:
        parsed = urlparse(url if '://' in url else f'tcp://{url}')
        host = parsed.hostname or host
        if parsed.port:
            port = parsed.port
        if parsed.scheme in ('https', 'ssl'):
            ssl = True
    return {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'ssl': ssl,
        'timeout': timeout,
    }


class MsfrpcClient:
    """Thin msgpack RPC client. Requires the ``msgpack`` package at runtime."""

    def __init__(
        self,
        *,
        host: str | None = None,
        port: int | None = None,
        user: str | None = None,
        password: str | None = None,
        ssl: bool | None = None,
        timeout: float | None = None,
    ):
        cfg = _rpc_config()
        self.host = host if host is not None else cfg['host']
        self.port = port if port is not None else cfg['port']
        self.user = user if user is not None else cfg['user']
        self.password = password if password is not None else cfg['password']
        self.ssl = cfg['ssl'] if ssl is None else ssl
        self.timeout = cfg['timeout'] if timeout is None else timeout
        self._token: str | None = None
        self._sock: socket.socket | None = None

    def connect(self) -> None:
        if not self.host:
            raise MsfrpcError(
                'MSF RPC not configured. Set MSF_RPC_HOST or MSF_RPC_URL '
                '(metasploit_integration / MSFRPC on r3ngine_network).',
                status=503,
            )
        if not self.password:
            raise MsfrpcError('MSF_RPC_PASS is required', status=503)
        try:
            import msgpack  # noqa: F401
        except ImportError as exc:
            raise MsfrpcError(
                'msgpack is required for MSFRPC (install in web image)',
                status=503,
            ) from exc
        try:
            raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
            if self.ssl:
                import ssl as ssl_mod
                ctx = ssl_mod.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl_mod.CERT_NONE
                self._sock = ctx.wrap_socket(raw, server_hostname=self.host)
            else:
                self._sock = raw
            self._sock.settimeout(self.timeout)
        except OSError as exc:
            raise MsfrpcError(f'MSFRPC unreachable at {self.host}:{self.port}: {exc}', status=503) from exc
        result = self.call('auth.login', self.user, self.password)
        if not isinstance(result, dict) or result.get('result') != 'success':
            raise MsfrpcError('MSFRPC auth.login failed', status=403)
        self._token = result.get('token')
        if not self._token:
            raise MsfrpcError('MSFRPC auth.login returned no token', status=403)

    def close(self) -> None:
        if self._sock:
            try:
                if self._token:
                    try:
                        self.call('auth.logout', self._token)
                    except MsfrpcError:
                        pass
            finally:
                try:
                    self._sock.close()
                except OSError:
                    pass
                self._sock = None
                self._token = None

    def __enter__(self) -> 'MsfrpcClient':
        self.connect()
        return self

    def __exit__(self, *args) -> None:
        self.close()

    def call(self, method: str, *args: Any) -> Any:
        import msgpack

        if not self._sock:
            raise MsfrpcError('MSFRPC not connected', status=503)
        payload = [method, *args]
        packed = msgpack.packb(payload)
        try:
            self._sock.sendall(packed)
            data = b''
            unpacker = msgpack.Unpacker(raw=False, strict_map_key=False)
            deadline = time.time() + self.timeout
            while True:
                if time.time() > deadline:
                    raise MsfrpcError('MSFRPC read timeout', status=504)
                chunk = self._sock.recv(4096)
                if not chunk:
                    raise MsfrpcError('MSFRPC connection closed', status=502)
                unpacker.feed(chunk)
                for obj in unpacker:
                    return obj
        except OSError as exc:
            raise MsfrpcError(f'MSFRPC I/O error: {exc}', status=502) from exc

    def module_execute(self, module: str, options: dict[str, str]) -> dict[str, Any]:
        if not self._token:
            raise MsfrpcError('not authenticated', status=401)
        # Classic API: module.execute(token, module_type, module_name, options)
        # module path like auxiliary/scanner/http/title → type=auxiliary, name=scanner/http/title
        parts = module.split('/', 1)
        if len(parts) != 2:
            raise MsfrpcError(f'invalid module path: {module}')
        mod_type, mod_name = parts[0], parts[1]
        result = self.call('module.execute', self._token, mod_type, mod_name, options)
        if not isinstance(result, dict):
            return {'raw': result}
        return result

    def job_list(self) -> dict[str, Any]:
        if not self._token:
            raise MsfrpcError('not authenticated', status=401)
        result = self.call('job.list', self._token)
        return result if isinstance(result, dict) else {'raw': result}

    def console_create_and_run(
        self,
        resource_lines: list[str],
        *,
        abort_check=None,
    ) -> str:
        """Create a console, write commands, read output (truncated).

        ``abort_check`` is an optional zero-arg callable; when it returns True
        the console is destroyed and ``MsfrpcError('aborted')`` is raised.
        """
        if not self._token:
            raise MsfrpcError('not authenticated', status=401)
        created = self.call('console.create', self._token)
        if not isinstance(created, dict) or 'id' not in created:
            raise MsfrpcError('console.create failed')
        cid = created['id']
        try:
            script = '\n'.join(resource_lines) + '\n'
            self.call('console.write', self._token, cid, script)
            # Poll briefly for output
            chunks: list[str] = []
            deadline = time.time() + min(self.timeout, 45.0)
            while time.time() < deadline:
                if abort_check and abort_check():
                    raise MsfrpcError('aborted', status=409)
                time.sleep(0.4)
                read = self.call('console.read', self._token, cid)
                if isinstance(read, dict):
                    data = str(read.get('data') or '')
                    if data:
                        chunks.append(data)
                    if read.get('busy') in (False, 0, 'false', None) and data == '':
                        # idle after some output
                        if chunks:
                            break
                else:
                    break
            return ''.join(chunks)[:8000]
        finally:
            try:
                self.call('console.destroy', self._token, cid)
            except MsfrpcError:
                pass
