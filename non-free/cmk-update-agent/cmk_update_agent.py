#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (C) 2019 Checkmk GmbH - License: Checkmk Enterprise License
# This file is part of Checkmk (https://checkmk.com). It is subject to the terms and
# conditions defined in the file COPYING, which is part of this source code package.

# This file must be compatible with Python 3.4
# see cmk/gui/cee/plugins/wato/agent_bakery/rulespecs/cmk_update_agent.py

import os
import sys
import warnings

# disable annoying warning in pyca cryptography openssl bindings: CMK-12532
if sys.platform == "win32" and os.environ.get("PROCESSOR_ARCHITEW6432") is not None:
    warnings.filterwarnings("ignore", category=UserWarning)

import abc
import argparse
import ast
import base64
import contextlib
import errno
import getpass
import json
import logging
import logging.handlers
import shlex
import shutil
import ssl
import subprocess
import tempfile
import time
import urllib.parse as urlparse
from collections.abc import Iterator, Sequence
from datetime import datetime, timezone

import requests
import urllib3
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

try:
    import typing
except ImportError:
    # The typing stuff is only used in annotations therefore the missed imports
    # are unimportend
    pass

if os.name == "posix":
    import fcntl
elif os.name == "nt":
    import msvcrt  # pylint: disable=import-error

    import yaml


class TargetState:
    def __init__(
        self,
        agent_available: bool,
        signatures: "list[tuple[str, bytes]]",
        target_hash: "str | None",
    ) -> None:
        self.agent_available = agent_available
        self.signatures = signatures
        self.target_hash = target_hash

        if agent_available and not target_hash:
            raise ValueError(
                "The response is contradictory, agent_available but without a target_hash"
            )

    def log(self, logger: "logging.Logger") -> None:
        logger.info("  %-20s %s", "Agent available:", self.agent_available)
        logger.info("  %-20s %s", "Signatures:", len(self.signatures))
        logger.info("  %-20s %s", "Target hash:", self.target_hash)


class AgentData:
    """Agentdata meant to be serialized to disk

    this currently is only used on Linux systems, Windows has its own Installer routine.
    Idea is to keep the signature at the data as long as possible"""

    def __init__(self, agent_data: bytes, target_state: TargetState) -> None:
        self.agent_data = agent_data
        self.target_state = target_state

    def serialize(self, target_file_handle: "typing.IO[str]") -> None:
        serialized_dict = {
            "agent_data": base64.b64encode(self.agent_data).decode("utf-8"),
            "target_state": {
                "signatures": [
                    {"certificate": c, "signature": base64.b64encode(s).decode("utf-8")}
                    for c, s in self.target_state.signatures
                ],
                "target_hash": self.target_state.target_hash,
            },
        }
        json.dump(serialized_dict, target_file_handle)

    @classmethod
    def load(cls, file_handle: "typing.IO[str]") -> "AgentData":
        serialized_dict = json.load(file_handle)
        target_state = TargetState(
            agent_available=True,  # We have it on disk...
            signatures=[
                (s["certificate"], base64.b64decode(s["signature"]))
                for s in serialized_dict["target_state"]["signatures"]
            ],
            target_hash=serialized_dict["target_state"]["target_hash"],
        )
        return cls(
            agent_data=base64.b64decode(serialized_dict["agent_data"]),
            target_state=target_state,
        )

    def check_signatures(self, logger: "logging.Logger", signature_keys: "list[str]") -> None:
        for count, (certificate_str, signature) in enumerate(self.target_state.signatures):
            try:
                cert = x509.load_pem_x509_certificate(
                    certificate_str.encode("utf-8"), default_backend()
                )
            except BaseException:
                logger.exception("Error loading certificate #%d", (count + 1))
                continue
            if cert.not_valid_after < datetime.utcnow():
                logger.error("Certificate #%d has expired", (count + 1))
                continue

            if certificate_str not in signature_keys:
                logger.info(
                    "Ignoring signature #%d for certificate: certificate is unknown.", (count + 1)
                )
                continue
            if self._check_signature(cert, signature, self.agent_data):
                logger.info("Signature check OK.")
                return
            logger.info("Signature #%d is invalid.", count + 1)

        raise Exception("No valid signature found.")

    @staticmethod
    def _check_signature(cert: x509.Certificate, signature: bytes, content: bytes) -> bool:
        try:
            pub_key = cert.public_key()
            if not isinstance(pub_key, rsa.RSAPublicKey):
                # Unsupported for now
                return False
            pub_key.verify(signature, content, padding.PKCS1v15(), hashes.SHA256())
            return True
        except InvalidSignature:
            return False


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# .
#   .--Constants-----------------------------------------------------------.
#   |       ___                _              _                            |
#   |      / __\___  _ __  ___| |_ __ _ _ __ | |_ ___                      |
#   |     / /  / _ \| '_ \/ __| __/ _` | '_ \| __/ __|                     |
#   |    / /__| (_) | | | \__ \ || (_| | | | | |_\__ \                     |
#   |    \____/\___/|_| |_|___/\__\__,_|_| |_|\__|___/                     |
#   |                                                                      |
#   +----------------------------------------------------------------------+
#   |  Module Constants                                                    |
#   '----------------------------------------------------------------------'

# Note: Version gets patched by build process
__version__ = "2.3.0b1"

API_VERSION = "2"

LOG_ONLY = logging.DEBUG - 4
USER_VERBOSE = logging.INFO + 2  # To be used with optional verbose flag, output to user only
USER_AND_LOG = logging.INFO + 3
USER_ONLY = logging.INFO + 4  # Output to user independent of verbose flag
IMPORTANT = logging.INFO + 5  # To be used for bold console and normal log output

has_unix_tty = sys.stdout.isatty() and not os.name == "nt"

TTY_BOLD = "\033[1m" if has_unix_tty else ""
TTY_NORMAL = "\033[0m" if has_unix_tty else ""
TTY_RED = "%s\033[31m" % TTY_BOLD if has_unix_tty else ""

STATE_DIR_LINUX = "/etc"
STATE_FILE = "cmk-update-agent.state"
CONFIG_DIR_LINUX = "/etc/check_mk"
CONFIG_FILE = "cmk-update-agent.cfg"
CERTS_FILE = "all_certs.pem"
VAR_DIR_LINUX = "/var/lib/check_mk_agent"
INSTALLATION_CANDIDATE_PREFIX = "new_agent"
CACHE_FOLDER_LINUX = "cache"
CACHE_FILE = "plugins_cmk-update-agent.cache"

# We need an arbitrary chosen value here in order to prevent the
# agent updater from blocking in case of connection problems.
# see http://docs.python-requests.org/en/master/user/advanced/#timeouts
REQUESTS_TIMEOUT = 120  # Requests timeout in seconds


def fix_bytes(value: "typing.Any") -> "typing.Any":
    """decode some byte values

    >>> fix_bytes(b"foo")
    'foo'
    >>> fix_bytes(["a", b"b"])
    ['a', 'b']
    >>> fix_bytes({"a": "b", "c": b"d", b"e": "f", b"g": b"h"})
    {'a': 'b', 'c': 'd', b'e': 'f', b'g': 'h'}
    """

    if isinstance(value, bytes):
        return value.decode("utf-8")

    if isinstance(value, list):
        return [fix_bytes(entry) for entry in value]

    if isinstance(value, dict):
        return {k: fix_bytes(v) for k, v in value.items()}

    # Leave everything else untouched
    return value


# .
#   .--HTTP/HTTPS----------------------------------------------------------.
#   |      _   _ _____ _____ ____   ___   _ _____ _____ ____  ____         |
#   |     | | | |_   _|_   _|  _ \ / / | | |_   _|_   _|  _ \/ ___|        |
#   |     | |_| | | |   | | | |_) / /| |_| | | |   | | | |_) \___ \        |
#   |     |  _  | | |   | | |  __/ / |  _  | | |   | | |  __/ ___) |       |
#   |     |_| |_| |_|   |_| |_| /_/  |_| |_| |_|   |_| |_|   |____/        |
#   |                                                                      |
#   +----------------------------------------------------------------------+
#   |  Fetching of URLs                                                    |
#   '----------------------------------------------------------------------'


class HttpHandler:
    _logger = logging.getLogger(__name__)

    def __init__(
        self, config_handler: "ConfigHandler", environment_handler: "EnvironmentHandler"
    ) -> None:
        self._logger = logging.getLogger(__name__)
        self._config = config_handler
        self._env = environment_handler
        self._proxy_config = self._get_proxy_config()
        if self._config.insecure:
            self._logger.warning(
                "All HTTPS connections are done insecurely, as you requested."
                " As a consequence, no TLS verification will be done, i.e. the"
                " authenticity of the Checkmk server cannot be guaranteed. However, HTTPS"
                ' connections are still TLS-encrypted while using the "--insecure" option.'
            )
        self.update_ca_store()

    def _get_proxy_config(self) -> "dict[str, str] | None":
        if not self._config.proxy:
            return None

        if "user" in self._config.proxy and "password" in self._config.proxy:
            user_quoted = urlparse.quote(self._config.proxy["user"])
            password_quoted = urlparse.quote(self._config.proxy["password"])
            auth = "%s:%s@" % (user_quoted, password_quoted)
        else:
            auth = ""
        proxy_string = "%s://%s%s:%s" % (
            self._config.proxy["proxy_protocol"],
            auth,
            urlparse.quote(self._config.proxy["server"]),
            self._config.proxy["port"],
        )
        return {"http": proxy_string, "https": proxy_string}

    def _certificate_dir(self) -> str:
        if self._env.opsys == "windows_msi":
            return os.path.join(self._config.config_file_dir, "cas")  # windows

        return os.path.join(os.getenv("MK_VARDIR", VAR_DIR_LINUX), "cas")

    def _certificate_filepath(self) -> str:
        return os.path.join(self._certificate_dir(), CERTS_FILE)

    def update_ca_store(self) -> None:
        if self._config.insecure:
            return
        if not (self._config.certificates or self._config.local_certificates):
            return

        if not os.path.exists(self._certificate_dir()):
            os.makedirs(self._certificate_dir())

        self._logger.debug('Updating the certificate store "%s"...', self._certificate_filepath())
        saved_certs = (self._config.certificates or []) + (
            self._config.local_certificates or []
        )  # type: list[str]
        all_certs = "\n".join(fix_bytes(cert) for cert in saved_certs)
        self._env.write_to_file(self._certificate_filepath(), all_certs)
        self._logger.info(
            'Updated the certificate store "%s" with %s certificate(s)',
            self._certificate_filepath(),
            len(saved_certs),
        )

    def _verify_arg(self) -> "bool | str":
        """Determine requests argument for CA validation.
        Update internal CA-Store if Certificates are present.
        """
        if self._config.insecure:
            return False

        if self._config.certificates or self._config.local_certificates:
            return self._certificate_filepath()

        return True

    def _establish_trust_with_server(self, base_url: str) -> None:
        """try to establish trust with the server

        we have a `--trust-cert` option. When you call with that option we
        connect to the server, ignore TLS trust-errors and store the received
        cert for the future"""
        if not self._config.trust_cert:
            return

        if urlparse.urlparse(base_url).scheme != "https":
            self._logger.debug(
                "Not adding server to trusted locations, as we are not connecting via HTTPS."
            )
            return

        try:
            self._trust_server(base_url)
        except Exception as exc:
            self._logger.log(LOG_ONLY, "Caught Exception:", exc_info=True)
            self._logger.warning("Unknown Error while adding server to trusted locations: %s", exc)

    def _trust_server(self, url: str) -> None:
        try:
            vvv = self._verify_arg()
            requests.head(
                url,
                verify=vvv,
                timeout=REQUESTS_TIMEOUT,
            )
            self._logger.debug("Already trusting server, skipping certificate import.")
            return
        except requests.exceptions.SSLError:
            pass

        new_cert = self._get_cert_from_server(url)
        if not new_cert:
            return

        self._logger.debug(
            'Adding server "%s" to trusted locations...', urlparse.urlparse(url).netloc
        )
        local_certificates = self._config.local_certificates or []
        local_certificates.append(new_cert)
        self._config.local_certificates = local_certificates
        self._config.update_deployment_state(["local_certificates"])
        self.update_ca_store()

    def _get_cert_from_server(self, url: str) -> "str | None":
        """get the certificate of the server

        this does not access the provided chain and does not try to retrieve the CA"""

        server = urlparse.urlparse(url).netloc
        port = 443
        if ":" in server:
            server, port_str = server.split(":")
            port = int(port_str)

        try:
            return ssl.get_server_certificate((server, port))
        except Exception as exc:
            self._logger.log(LOG_ONLY, "Caught Exception:", exc_info=True)
            self._logger.warning(
                "Error retreiving certificate from server: %s. Aborting import.", exc
            )
            return None

    @contextlib.contextmanager
    def _proxy_env(self) -> "Iterator[None]":
        """Unset proxy environment variables if not configured otherwise.
        Note: Setting request's proxy-argument to anything other than None
        would override handling of env vars
        """

        if self._config.use_proxy_env:
            yield
            return

        deleted_env_vars = {}
        orig_proxy_ignores = os.environ.get("NO_PROXY")

        try:
            for env_var in list(os.environ):
                if env_var.lower() in ["http_proxy", "https_proxy", "all_proxy"]:
                    deleted_env_vars[env_var] = os.environ.pop(env_var)
            if orig_proxy_ignores:
                os.environ["NO_PROXY"] = "%s,%s" % (orig_proxy_ignores, self._config.server)
            else:
                assert isinstance(self._config.server, str)
                os.environ["NO_PROXY"] = self._config.server

            yield

        finally:
            for env_var in deleted_env_vars:
                os.environ[env_var] = deleted_env_vars[env_var]
            if orig_proxy_ignores:
                os.environ["NO_PROXY"] = orig_proxy_ignores
            else:
                os.environ.pop("NO_PROXY", None)

    @contextlib.contextmanager
    def _catch_timeout(self) -> "Iterator[None]":
        try:
            yield
        except requests.exceptions.Timeout:
            raise Exception("Connection timed out after %s seconds" % REQUESTS_TIMEOUT)

    def _with_effective_protocol(self, url: str) -> str:
        """check for a 'unexpected' redirect to https"""
        parsed_url = urlparse.urlparse(url)

        if parsed_url.scheme == "https":
            return url

        with self._proxy_env():
            with self._catch_timeout():
                resulting_url = requests.head(  # nosec B501 # BNS:016141
                    url,
                    verify=False,
                    proxies=self._proxy_config,
                    allow_redirects=True,
                    timeout=REQUESTS_TIMEOUT,
                ).url
        resulting_url_parsed = urlparse.urlparse(resulting_url)

        if resulting_url_parsed.scheme == "http":
            return url

        self._logger.warning(
            "Detected forced redirect from HTTP to HTTPS. Connecting via HTTPS for"
            " now. Consider configuring HTTPS."
        )

        return parsed_url._replace(scheme="https").geturl()

    def fetch_data_from_server(
        self, site_rel_url: str, post_args: "dict[str, str | None]", auth: bool = False
    ) -> "typing.Any":
        """Access and fetch content of url relative to Checkmk site using requests.post method
        Perform a login to Checkmk site within a requests session if necessary.
        """

        pending_exc = None  # type: BaseException | None
        for base_url in self._config.candidates_for_update_url():
            if pending_exc:
                self._logger.warning("Failed to connect to agent bakery: %s", pending_exc)
                self._logger.warning("Retrying with fallback URL: %s", base_url)
            base_url = self._with_effective_protocol(base_url)

            self._establish_trust_with_server(base_url)

            try:
                return self._do_request(base_url, site_rel_url, post_args, auth)
            except BaseException as exc:
                if "agent bakery" in str(exc).lower():
                    raise
                pending_exc = exc

        assert pending_exc is not None
        raise pending_exc

    def _do_request(
        self, base_url: str, site_rel_url: str, post_args: "dict[str, str | None]", auth: bool
    ) -> "typing.Any":
        with self._proxy_env():
            with requests.Session() as session:
                # determine whether to authenticate via login or automation user
                if auth:
                    if self._config.password:
                        self._login_site(session, base_url)
                    else:
                        post_args["_username"] = self._config.user
                        post_args["_secret"] = self._config.secret
                post_args["au_api"] = API_VERSION
                # send and receive actual data
                url = "%s/%s" % (base_url, site_rel_url)
                self._logger.debug("Fetching content (using requests): %s", url)
                with self._catch_timeout():
                    response = session.post(
                        url,
                        data=post_args,
                        verify=self._verify_arg(),
                        proxies=self._proxy_config,
                        timeout=REQUESTS_TIMEOUT,
                    )
        try:
            self._log_response(response)
        except Exception:
            self._logger.log(LOG_ONLY, "Failed to log raw response", exc_info=True)
        self._check_for_response_error(response)
        return response.json()["result"]

    def _log_response(self, response: requests.Response) -> None:
        if "json" not in response.headers.get("Content-Type", ""):
            self._logger.error("Response without json Content-Type")
            return

        json_response = response.json()
        if isinstance(json_response["result"], dict):
            # If it's not, it probably just contains an error message (i.e., str)
            if "host_secret" in json_response.get("result", {}):
                json_response["result"]["host_secret"] = "***"
            if "agent" in json_response.get("result", {}):
                json_response["result"]["agent"] = "%s...%s" % (
                    json_response["result"]["agent"][:10],
                    json_response["result"]["agent"][-10:],
                )

        self._logger.debug("Response from agent bakery:\n%s", json_response)

    def _login_site(self, session: requests.Session, base_url: str) -> None:
        """login to GUI in order to set Cookies used later on in this session"""

        auth_url = "%s/login.py" % base_url
        self._logger.debug("Authenticating at Checkmk Server (using requests): %s", auth_url)
        credential_args = {
            "_login": "1",
            "_username": self._config.user,
            "_password": self._config.password,
        }
        with self._catch_timeout():
            auth_response = session.post(
                auth_url,
                data=credential_args,
                verify=self._verify_arg(),
                proxies=self._proxy_config,
                timeout=REQUESTS_TIMEOUT,
            )
        auth_response.raise_for_status()
        self._check_for_login_error(auth_response)

    def _check_for_response_error(self, response: requests.Response) -> None:
        response.raise_for_status()

        if "json" in response.headers.get("Content-Type", "") and "result_code" in response.json():
            if response.json()["result_code"] == 1:
                raise Exception("Agent Bakery: %s" % response.json()["result"])
        else:
            self._check_for_login_error(response)
            raise Exception("Unexpected answer from Checkmk server, missing json data.")

    def _check_for_login_error(self, response: requests.Response) -> None:
        for hint in [
            '<div id="login_error">',
            "Permission denied",
            "Nicht angemeldet",
            "Invalid automation secret for user",
            "Ungültiges Automatisierungspasswort für Benutzer",
        ]:
            if hint in response.text:
                raise Exception("Cannot authenticate, invalid user/passwort/secret.")


# .
#   .--Helpers-------------------------------------------------------------.
#   |                  _   _      _                                        |
#   |                 | | | | ___| |_ __   ___ _ __ ___                    |
#   |                 | |_| |/ _ \ | '_ \ / _ \ '__/ __|                   |
#   |                 |  _  |  __/ | |_) |  __/ |  \__ \                   |
#   |                 |_| |_|\___|_| .__/ \___|_|  |___/                   |
#   |                              |_|                                     |
#   +----------------------------------------------------------------------+
#   |  Generic helper functions                                            |
#   '----------------------------------------------------------------------'


class EnvironmentHandler:
    _logger = logging.getLogger(__name__)

    def __init__(self) -> None:
        self.sub_env = self._get_subprocess_env()
        self.opsys = self._our_os_type()
        self.run_sync_parts = os.getenv("MK_RUN_SYNC_PARTS", "true") != "false"

    @staticmethod
    def _our_os_type() -> str:
        if os.name == "nt":
            return "windows_msi"
        if os.path.exists("/var/lib/dpkg/status"):
            return "linux_deb"
        if (
            os.path.exists("/var/lib/rpm")
            and os.path.exists("/bin/rpm")
            or os.path.exists("/usr/bin/rpm")
        ):
            return "linux_rpm"
        if (
            os.path.exists("/var/sadm/pkg")
            and os.path.exists("/usr/bin/pkg")
            or os.path.exists("/usr/sbin/pkgadd")
        ):
            return "solaris_pkg"

        return "linux_tgz"

    @staticmethod
    def _get_subprocess_env() -> "dict[str, str] | None":
        """When executing as a frozen binary, the LD_LIBRARY_PATH env variable has to be
        removed for subprocess calls because they remain system-dependent and need
        their own system-related libraries.
        """
        if not (hasattr(sys, "frozen") and "LD_LIBRARY_PATH" in os.environ):
            return None
        sub_env = dict(os.environ)
        sub_env.pop("LD_LIBRARY_PATH")
        return sub_env

    @staticmethod
    def read_line(prompt: str, echo: bool = True) -> str:
        EnvironmentHandler._logger.log(USER_ONLY, "%s %s", prompt, TTY_BOLD)
        try:
            if echo:
                answer = sys.stdin.readline().rstrip()
            else:
                answer = getpass.getpass(prompt="")
        except Exception:
            EnvironmentHandler._logger.log(USER_ONLY, "")
            answer = None
        EnvironmentHandler._logger.log(USER_ONLY, TTY_NORMAL)
        if not answer:
            raise Exception("Aborted.")
        return answer

    @staticmethod
    def write_to_file(target_path: str, data: object) -> None:
        """write something somewhere to disk, using the write then copy approach"""

        # TODO(We write only str to file and later read with ast.literal_eval,
        # use json or something more robust)
        tmp_file = tempfile.NamedTemporaryFile(  # pylint: disable=consider-using-with
            "w",
            dir=os.path.dirname(target_path),
            prefix=".%s.new" % os.path.basename(target_path),
            delete=False,
        )
        tmp_path = tmp_file.name

        try:
            os.chmod(tmp_path, 0o600)
            tmp_file.write("%s\n" % data)
            tmp_file.flush()
            os.fsync(tmp_file.fileno())
            tmp_file.close()
            shutil.move(tmp_path, target_path)
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)


# .
#   .--Config-&-Status-----------------------------------------------------.
#   |   ____             __ _        ___   ____  _        _                |
#   |  / ___|___  _ __  / _(_) __ _ ( _ ) / ___|| |_ __ _| |_ _   _ ___    |
#   | | |   / _ \| '_ \| |_| |/ _` |/ _ \/\___ \| __/ _` | __| | | / __|   |
#   | | |__| (_) | | | |  _| | (_| | (_>  <___) | || (_| | |_| |_| \__ \   |
#   |  \____\___/|_| |_|_| |_|\__, |\___/\/____/ \__\__,_|\__|\__,_|___/   |
#   |                         |___/                                        |
#   +----------------------------------------------------------------------+
#   | Reading and saving of config file and deployment status              |
#   '----------------------------------------------------------------------'


class OptionParser:
    """Determine mode and parse cmdline arguments.
    Mode-specific cmdline arg are taken from applicable mode class.
    The arguments are specified so that non-configurable attributes (e.g. "password")
    receive a default value
    """

    def __init__(self, args: "list[str]") -> None:
        main_parser = self._make_main_parser()
        (self.mode_class, mode_args) = self._determine_mode_info(args)
        self.arg_namespace = self._parse_cmd_line(main_parser, mode_args)

    @staticmethod
    def _make_main_parser() -> argparse.ArgumentParser:
        main_parser = argparse.ArgumentParser(
            usage="%(prog)s [register|install|show-config] [OPTIONS]",
            description="Manually update the Checkmk agent, register"
            " at update server for automatic updates, install previously"
            " downloaded agent package or show current config."
            " Keywords 'register' or 'show-config' must be passed as first"
            " argument to call corresponding mode. Type"
            " '%(prog)s register --help' for registration usage",
            conflict_handler="resolve",
        )
        OptionParser._add_generic_group(main_parser)
        return main_parser

    @staticmethod
    def _add_generic_group(main_parser: argparse.ArgumentParser) -> None:
        generic_group = main_parser.add_argument_group("General options")
        generic_group.set_defaults(verbose_level=0, logfile=None)
        generic_group.add_argument(
            "-t",
            "--trust-cert",
            action="store_true",
            help="Trust the server's TLS certificate on this connection and save"
            " it to trusted certificates for further connections.",
        )
        generic_group.add_argument(
            "-x",
            "--insecure",
            action="store_true",
            help="Disable TLS server certificate verification.",
        )
        generic_group.add_argument(
            "-v",
            "--verbose",
            dest="verbose_level",
            action="count",
            help="Enable verbose output, twice for more details",
        )
        generic_group.add_argument(
            "-l",
            "--logfile",
            action="store",
            help="Log to specified file. Logging data will be appended and logfile"
            " will be rotated if file already exists.",
        )
        generic_group.add_argument(
            "-V", "--version", action="version", version="Checkmk Agent Updater v%s" % __version__
        )

    @staticmethod
    def _determine_mode_info(args: "list[str]") -> "tuple[typing.Type['GenericMode'], list[str]]":
        if len(args) > 1 and args[1] == "show-config":
            return (ShowConfigMode, args[2:])
        if len(args) > 1 and args[1] == "register":
            return (RegisterMode, args[2:])
        if len(args) > 1 and args[1] == "install":
            if os.name == "nt":
                raise Exception("No seperate install mode available on Windows.")
            return (UnixInstallMode, args[2:])
        if os.name == "nt":
            return (WindowsUpdateMode, args[1:])
        return (UnixUpdateMode, args[1:])

    def _parse_cmd_line(
        self, parser: argparse.ArgumentParser, args: "list[str]"
    ) -> argparse.Namespace:
        self.mode_class.add_parser_group(parser)  # mode not yet instantiated
        return parser.parse_args(args)


class ConfigHandler:
    _logger = logging.getLogger(__name__)

    def __init__(self, environment_handler: EnvironmentHandler, cmdline_opts: OptionParser) -> None:
        self._cmdline_opts = cmdline_opts

        # setup env and file config handler before config is applied
        self._env = environment_handler
        self._file_config = FileConfigHandler(self._env)

        self._apply_config()

        # setup http handler after config is applied
        self._http = HttpHandler(self, self._env)

        self._mode = self._cmdline_opts.mode_class(self, self._env, self._http)

    def _apply_config(self) -> None:
        # config_origin is collected for ShowConfigMode
        self.config_origin = {}  # type: dict

        # init all configurable attributes with None
        self._init_attributes()

        # read config files, config_file wins over state_file
        # only set attributes that are initialized (with None)
        self._apply_file_config(self._file_config.read_state_file(), "state_file")
        self._apply_file_config(self._file_config.read_config_file(), "config_file")

        # cmdline wins over config, attributes need no initialization
        # OptionParser class handles that non-configurable (i.e. pure cmdline opts
        # like password) get a default value if not set by user.
        self._apply_cmdline_config()

        # evaluate "force" option for convenience
        if getattr(self, "force", False):
            self.reinstall = True
            self.skip_signatures = True

    def _init_attributes(self) -> None:
        self.server = None  # type: str | None
        self.site = None  # type: str | None
        self.protocol = None  # type: str | None
        self.host_name = None  # type: str | None
        self.user = None  # type: str | None
        self.certificates = None  # type: list[str] | None
        self.local_certificates = None  # type: list[str] | None
        self.interval = None  # type: int | None
        self.proxy = None  # type: dict[str, str] | None
        self.use_proxy_env = False
        self.update_url = None  # type: str | None
        self.ignore_update_url = False
        self.host_secret = None  # type: str | None
        self.last_error = None  # type: str | None
        self.last_check = None  # type: float | None
        self.last_update = None  # type: float | None
        self.installed_aghash = None  # type: str | None
        self.signature_keys = None  # type: list[str] | None
        self.pending_hash = None  # type: str | None
        self.secret = None  # type: str | None
        self.insecure = False
        self.trust_cert = False
        self.password = None  # type: str | None
        self.verbose_level = 0
        self.run_as_plugin = False

    def _apply_file_config(self, config_dict: dict, origin: str) -> None:
        # TODO(we should set the attributes explicitly)
        for key in [entry for entry in config_dict if hasattr(self, entry)]:
            setattr(self, key, config_dict[key])
            self.config_origin[key] = origin

    def _apply_cmdline_config(self) -> None:
        # TODO(we should set the attributes explicitly)
        for attribute, value in self._cmdline_opts.arg_namespace.__dict__.items():
            setattr(self, attribute, value)

    def _cache_file_location(self) -> "str | None":
        if not hasattr(self, "interval"):
            return None

        cache_location_candidate = os.path.join(
            os.getenv("MK_VARDIR", VAR_DIR_LINUX),
            CACHE_FOLDER_LINUX,
            CACHE_FILE,
        )
        if os.path.exists(cache_location_candidate):
            return cache_location_candidate

        return None

    def _actual_update_url(self) -> str:
        return next(self.candidates_for_update_url())

    def _list_trusted_certs_and_expiry(self) -> "dict[int, dict[str, None | bool | str]]":
        """list trusted signing certs and their expiry time so we can warn if there will no signing cert be left

        The "inner" dict is basically this:

            class CertDetails(TypedDict):
                corrupt: bool
                # if the cert is corrupt these will be None
                not_after: str | None # ASN.1 GENERALIZEDTIME
                signature_algorithm: str | None
                common_name: str | None
        """

        certs = {}  # type: dict[int, dict[str, None | bool | str]]

        if self.signature_keys is None:
            return certs

        for number, certificate_str in enumerate(self.signature_keys):
            try:
                cert = x509.load_pem_x509_certificate(
                    certificate_str.encode("utf-8"), default_backend()
                )
            except BaseException:
                certs[number] = {
                    "corrupt": True,
                    "not_after": None,
                    "signature_algorithm": None,
                    "common_name": None,
                }
                continue

            # This is a list...
            common_names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            cn = common_names[0].value if len(common_names) == 1 else None
            if isinstance(cn, bytes):
                cn = cn.decode("utf-8")
            assert cert.signature_hash_algorithm is not None

            certs[number] = {
                "corrupt": False,
                "not_after": cert.not_valid_after.replace(tzinfo=timezone.utc).isoformat(),
                "signature_algorithm": cert.signature_hash_algorithm.name,
                "common_name": cn,
            }

        return certs

    def update_deployment_state(self, update_keys: "typing.Iterable[str]") -> None:
        deployment_state = self._file_config.read_state_file()
        for key in update_keys:
            deployment_state[key] = getattr(self, key)
        self._file_config.write_state_file(fix_bytes(deployment_state))

    def candidates_for_update_url(self) -> "Iterator[str]":
        if not self.ignore_update_url and self.update_url:
            yield self.update_url.rstrip("/")

        yield "%s://%s/%s/check_mk" % (self.protocol, self.server, self.site)

    def agent_section(self) -> str:
        return "<<<cmk_update_agent_status:sep(0)>>>\n%s\n" % (
            json.dumps(
                {
                    "last_check": self.last_check,
                    "last_update": self.last_update,
                    "aghash": self.installed_aghash,
                    "pending_hash": self.pending_hash,
                    "update_url": self._actual_update_url(),
                    "trusted_certs": self._list_trusted_certs_and_expiry(),
                    "error": self.last_error,
                }
            )
        )

    def update_cache_file(self) -> None:
        cache_file_location = self._cache_file_location()
        if not cache_file_location:
            self._logger.debug("Could not find and update cachefile.")
            return

        try:
            self._env.write_to_file(cache_file_location, self.agent_section())
            self._logger.debug("Successfully updated cachefile.")
        except IOError:
            self._logger.log(LOG_ONLY, "Caught Exception:", exc_info=True)
            self._logger.debug(
                "Could not access and update cachefile at %s.", self._cache_file_location()
            )

    @property
    def mode(self) -> "GenericMode":
        return self._mode

    @property
    def state_file_path(self) -> str:
        return self._file_config.state_file_path

    @property
    def config_file_dir(self) -> str:
        return self._file_config.config_dir

    @property
    def config_file_path(self) -> str:
        return self._file_config.config_file_path

    @property
    def cache_file_location(self) -> "str | None":
        return self._cache_file_location()

    @property
    def installation_candidate(self) -> "str | None":
        return self.pending_hash and os.path.join(
            os.getenv("MK_VARDIR", VAR_DIR_LINUX),
            "%s_%s" % (INSTALLATION_CANDIDATE_PREFIX, self.pending_hash),
        )


class FileConfigHandler:
    _logger = logging.getLogger(__name__)

    def __init__(self, environment_handler: EnvironmentHandler) -> None:
        self._env = environment_handler
        # set needed paths
        self.config_dir = self._get_config_dir()
        self.config_file_path = os.path.join(self.config_dir, CONFIG_FILE)
        self.state_file_path = os.path.join(self._get_state_dir(), STATE_FILE)

    def _get_config_dir_candidate(self) -> str:
        if self._env.opsys == "windows_msi":
            # for windows, look for a config directory parallel to the plugin directory
            # we're running from.
            return os.path.abspath(
                os.path.join(
                    os.path.dirname(os.path.realpath(os.path.realpath(__file__))), "..", "config"
                )
            )

        return CONFIG_DIR_LINUX

    def _get_config_dir(self) -> str:
        for dir_candidate in [os.getenv("MK_CONFDIR"), self._get_config_dir_candidate()]:
            if dir_candidate and os.path.exists(dir_candidate):
                return dir_candidate
        return "."  # Fallback

    def _get_state_dir(self) -> str:
        if os.name == "posix" and os.path.exists(STATE_DIR_LINUX):  # Don't use e.g. C:\etc
            # Beware: On linux we must not use /etc/check_mk. This will be removed
            # by the agent on update.
            # TODO(au): Fix this
            return STATE_DIR_LINUX

        return self.config_dir

    def _read_repr_file(self, path: str) -> "dict | None":
        if not os.path.exists(path):
            return None

        try:
            with open(path) as repr_file:
                value = ast.literal_eval(repr_file.read())
                if not isinstance(value, dict):
                    raise ValueError
                self._logger.debug("Successfully read %s.", path)
                return value

        except IOError:
            self._logger.log(LOG_ONLY, "Caught Exception:", exc_info=True)
            raise Exception("Cannot read file %s" % path)

        except (ValueError, SyntaxError) as exc:
            self._logger.log(LOG_ONLY, "Caught Exception:", exc_info=True)
            raise Exception("%s is ill-formatted: %s" % (path, exc))

        except Exception as exc:
            self._logger.log(LOG_ONLY, "Caught Exception:", exc_info=True)
            if "compile" in str(exc):
                raise Exception("Could not parse %s: File may be corrupt." % path)
            raise Exception("Unknown error while reading %s: %s" % (path, exc))

    def read_config_file(self) -> dict:
        config_file = self._read_repr_file(self.config_file_path)
        if config_file is None:
            self._logger.warning(
                "Missing config file at %s. Configuration may be incomplete.",
                self.config_file_path,
            )
        return config_file or {}

    def _read_backup_file(self) -> dict:
        try:
            state_file = self._read_repr_file(self.state_file_path + ".bak")
            if state_file is None:
                self._logger.debug(
                    "No backup state file found yet. New state data will be saved to %s",
                    self.state_file_path,
                )
            return state_file or {}
        except Exception:
            self._logger.error(
                "Content of the backup state file is corrupted or inaccessible. "
                "New state data will be saved to %s",
                self.state_file_path,
            )

        return {}

    def read_state_file(self) -> dict:
        try:
            state_file = self._read_repr_file(self.state_file_path)
            if state_file is None:
                self._logger.debug(
                    "No state file found yet. New state data will be saved to %s",
                    self.state_file_path,
                )
        except Exception:
            self._logger.error(
                "Content of the state file is corrupted or inaccessible. "
                "Falling back to backup state file %s. Some data may be lost, though."
                "New state data will be saved to %s",
                self.state_file_path + ".bak",
                self.state_file_path,
            )
            state_file = self._read_backup_file()

        return state_file or {}

    def _backup_state_file(self) -> None:
        try:
            if self._read_repr_file(self.state_file_path):
                shutil.copy(self.state_file_path, self.state_file_path + ".bak")
        except Exception:
            self._logger.log(LOG_ONLY, "Caught Exception:", exc_info=True)

    def write_state_file(self, status: object) -> None:
        self._backup_state_file()
        try:
            self._env.write_to_file(self.state_file_path, status)
        except IOError:
            self._logger.log(LOG_ONLY, "Caught Exception:", exc_info=True)
            raise Exception("Failed to write state to '%s'" % self.state_file_path)

        self._logger.debug("Saved deployment status to %s.", self.state_file_path)


# .
#   .--Generic-------------------------------------------------------------.
#   |                   ____                      _                        |
#   |                  / ___| ___ _ __   ___ _ __(_) ___                   |
#   |                 | |  _ / _ \ '_ \ / _ \ '__| |/ __|                  |
#   |                 | |_| |  __/ | | |  __/ |  | | (__                   |
#   |                  \____|\___|_| |_|\___|_|  |_|\___|                  |
#   |                                                                      |
#   +----------------------------------------------------------------------+
#   | Base class for program execution                                     |
#   | Set up and lock session, tidy up leftover files                      |
#   '----------------------------------------------------------------------'


class GenericMode(abc.ABC):
    _logger = logging.getLogger(__name__)

    def __init__(
        self,
        config_handler: ConfigHandler,
        environment_handler: EnvironmentHandler,
        http_handler: HttpHandler,
    ) -> None:
        self._config = config_handler
        self._env = environment_handler
        self._http = http_handler

    def run(self) -> None:
        """Acquire a file lock for exclusive instance of cmk-update-agent and run selected mode"""
        lockfile, lockfile_path = self._acquire_updater_lock()

        try:
            self._run_mode()
        finally:
            lockfile.close()
            os.remove(lockfile_path)

    @staticmethod
    def add_parser_group(arg_parser: argparse.ArgumentParser) -> None:
        return

    @abc.abstractmethod
    def _run_mode(self) -> None:
        raise NotImplementedError()

    def _apply_update_server_info_response(self, result: dict) -> None:
        state_keys = []

        update_url = result.get("update_url", None)
        if update_url != self._config.update_url:
            self._logger.info("Applying new update URL %s from deployment server", update_url)
            self._config.update_url = update_url
            state_keys.append("update_url")

        new_certs = result.get("certificates", [])
        if new_certs:
            temp_certs = (self._config.local_certificates or []) + new_certs
            self._config.local_certificates = list(set(temp_certs))
            state_keys.append("local_certificates")
            self._http.update_ca_store()

        self._config.update_deployment_state(state_keys)

    def _acquire_updater_lock(
        self, num_attempts: int = 10, delay: float = 1.0
    ) -> "tuple[typing.IO, str]":
        lockfile_path = self._get_lockfile_path()

        lockfile_handle = self._try_lock(lockfile_path, num_attempts, delay)
        lockfile_handle.write(str(os.getpid()))
        lockfile_handle.flush()

        return lockfile_handle, lockfile_path

    def _try_lock(
        self,
        lockfile_path: str,
        num_attempts: int,
        delay: float,
    ) -> "typing.IO":
        for try_no in range(1, num_attempts + 1):
            try:
                lockfile_handle = self._open_lockfile(lockfile_path)
                self._lock_os_specific(lockfile_handle)
                return lockfile_handle
            except IOError as exc:
                if exc.errno not in [errno.EACCES, errno.EAGAIN]:
                    raise
                lockfile_handle.close()
            self._logger.log(
                LOG_ONLY,
                "Couldn't lock %s (attempt %d), trying again in %g second(s).",
                lockfile_path,
                try_no,
                delay,
            )
            time.sleep(delay)

        raise Exception(
            "Couldn't lock %s after %d attempts. Seems that an instance of %s is already running"
            " on this system. Aborting..." % (lockfile_path, num_attempts, sys.argv[0])
        )

    def _open_lockfile(self, lockfile_path: str) -> "typing.IO":
        try:
            return open(lockfile_path, "w")  # pylint: disable=consider-using-with
        except IOError as exc:
            self._logger.log(LOG_ONLY, "Caught Exception:", exc_info=True)
            raise Exception(
                "Could not access lockfile at %s: %s. Maybe running with unsufficient rights?"
                % (lockfile_path, exc)
            )

    @staticmethod
    def _lock_os_specific(lockfile_handle: "typing.IO") -> None:
        if os.name == "posix":
            fcntl.lockf(lockfile_handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        elif os.name == "nt":
            msvcrt.locking(  # type: ignore[attr-defined]
                lockfile_handle.fileno(),
                msvcrt.LK_NBLCK,  # type: ignore[attr-defined]
                1024,
            )

    def _get_lockfile_path(self) -> str:
        if self._env.opsys == "windows_msi":
            for dir_candidate in ["tmp", "temp"]:
                local_temp_dir = os.path.realpath(
                    os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", dir_candidate)
                )
                if os.path.exists(local_temp_dir):
                    return os.path.join(local_temp_dir, "cmk-update-agent.pid")

            self._logger.warning(
                "Could not find tempdir at %s for lockfile creation."
                " Falling back to user's tempdir at %s",
                local_temp_dir,
                tempfile.gettempdir(),
            )

        return os.path.join(tempfile.gettempdir(), "cmk-update-agent.pid")

    def _handle_inconsistent_update(self) -> None:
        self._config.pending_hash = None
        self._config.last_error = "inconsistent pending update"
        self._config.update_deployment_state(["pending_hash", "last_error"])


# .
#   .--Registration--------------------------------------------------------.
#   |        ____            _     _             _   _                     |
#   |       |  _ \ ___  __ _(_)___| |_ _ __ __ _| |_(_) ___  _ __          |
#   |       | |_) / _ \/ _` | / __| __| '__/ _` | __| |/ _ \| '_ \         |
#   |       |  _ <  __/ (_| | \__ \ |_| | | (_| | |_| | (_) | | | |        |
#   |       |_| \_\___|\__, |_|___/\__|_|  \__,_|\__|_|\___/|_| |_|        |
#   |                  |___/                                               |
#   +----------------------------------------------------------------------+
#   |  Before we can do updates the agent needs to exchange a secret with  |
#   |  the deployment server. This is called registration.                 |
#   '----------------------------------------------------------------------'


class RegisterMode(GenericMode):
    def _run_mode(self) -> None:
        self._logger.log(LOG_ONLY, "Starting Registration Mode.")
        show_command_line_hint = False
        if self._need_interaction_for_registration():
            horizontal_bar = "+%s+" % ("-" * 67)
            space = "|%s|" % (" " * 67)
            text_lines = [
                "Checkmk Agent Updater v%s - Registration" % __version__,
                "Activation of automatic agent updates. Your first step is to",
                "register this host at your deployment server for agent updates.",
                "For this step you need a user with the permission",
                '"Register all hosts" on that Checkmk site.',
            ]
            flines = ["|  %s%s|" % (line, " " * (65 - len(line))) for line in text_lines]
            self._logger.log(
                USER_VERBOSE,
                "\n%s" * 10,
                horizontal_bar,
                space,
                flines[0],
                space,
                flines[1],
                flines[2],
                flines[3],
                flines[4],
                space,
                horizontal_bar,
            )
            self._logger.log(LOG_ONLY, "Starting interactive Registration.")

            if os.path.exists(self._config.state_file_path):
                self._logger.log(
                    USER_AND_LOG, "Using previous settings from %s.", self._config.state_file_path
                )

        if self._interactively_complete_config():
            show_command_line_hint = True

        self._config.host_secret = self._register_agent()
        self._config.update_deployment_state(
            ["host_secret", "server", "site", "host_name", "protocol", "user"]
        )
        cmd_line = "check_mk_agent.exe updater -v" if os.name == "nt" else "cmk-update-agent -v"
        self._logger.log(USER_VERBOSE, "You can now update your agent by running '%s'", cmd_line)
        self._logger.info("Saved your registration settings to %s.", self._config.state_file_path)

        if show_command_line_hint and self._config.verbose_level:
            self._show_command_line()

        if os.name == "posix":
            self._invalidate_cache_file_age()

    @staticmethod
    def add_parser_group(arg_parser: argparse.ArgumentParser) -> None:
        reg_group = arg_parser.add_argument_group(
            "Registration options", argument_default=argparse.SUPPRESS
        )
        reg_group.add_argument("-s", "--server", help="DNS name or IP address of update server")
        reg_group.add_argument("-i", "--site", help="Name of Checkmk site on that server")
        reg_group.add_argument("-p", "--protocol", help="Either http or https (default is https)")
        reg_group.add_argument(
            "-H",
            "--hostname",
            dest="host_name",  # attr differs from cmdline
            help="Host name to fetch agent for",
        )
        reg_group.add_argument(
            "-U", "--user", help="User-ID of a user who is allowed to download the agent."
        )
        reg_group.add_argument(
            "-P", "--password", help="Password of the user (in case of normal user)", default=None
        )
        reg_group.add_argument(
            "-S",
            "--secret",
            help="Automation secret of that user (in case of automation user)",
            default=None,
        )

    def _need_interaction_for_registration(self) -> bool:
        return (
            self._config.server is None
            or self._config.protocol is None
            or self._config.site is None
            or self._config.host_name is None
            or self._config.user is None
            or (self._config.password is None and self._config.secret is None)
        )

    def _interactively_complete_config(self) -> bool:
        some_missing = False
        if self._config.server is None:
            self._config.server = self._env.read_line("Deployment server to connect to:")
            some_missing = True

        while self._config.protocol is None or self._config.protocol not in ["http", "https"]:
            self._config.protocol = self._env.read_line(
                "Protocol to use for connection [http/https]:"
            )
            some_missing = True

        if self._config.site is None:
            self._config.site = self._env.read_line("Checkmk site on deployment server:")
            some_missing = True

        if self._config.host_name is None:
            self._config.host_name = self._env.read_line("Our host name in the monitoring:")
            some_missing = True

        user_just_entered = False
        if self._config.user is None:
            self._config.user = self._env.read_line("User with registration permissions:")
            user_just_entered = True

        if self._config.password is None and self._config.secret is None:
            if user_just_entered:
                label = "Password:"
            else:
                label = "Password for user '%s':" % self._config.user
            self._config.password = self._env.read_line(label, echo=False)

        return some_missing

    def _show_command_line(self) -> None:
        config = self._config  # shortcut
        command = self._get_agent_updater_command()
        assert config.user is not None
        command_line = command + " register -s %s -i %s -H %s -p %s -U %s " % (
            config.server,
            config.site,
            config.host_name,
            config.protocol,
            shlex.quote(config.user),
        )

        if config.secret is not None:
            command_line += "-S %s " % ("*" * len(config.secret))
        else:
            assert config.password is not None
            command_line += "-P %s " % ("*" * len(config.password))

        command_line += "-%s" % (
            self._config.verbose_level * "v"
        )  # No need to handle verbose_level==0

        self._logger.log(
            USER_VERBOSE,
            "\nHint: you can do this in scripts with the command:\n\n%s\n",
            command_line,
        )

    @staticmethod
    def _get_agent_updater_command() -> str:
        if os.name == "nt":
            return "check_mk_agent.exe updater"

        return "cmk-update-agent"

    def _register_agent(self) -> str:
        self._logger.info("Going to register agent at deployment server")
        host_ident = {"host": self._config.host_name}
        self._config.ignore_update_url = True  # Don't rely on automatic update url for registration
        result = self._http.fetch_data_from_server(
            site_rel_url="register_agent.py", post_args=host_ident, auth=True
        )
        self._apply_update_server_info_response(result)
        host_secret = result["host_secret"]
        if len(host_secret) != 64:
            raise Exception("Invalid host secret (length is not 64)")
        self._logger.log(
            IMPORTANT,
            'Successfully registered agent of host "%s" for deployment.',
            self._config.host_name,
        )
        if result.get("monitored") is False:
            self._logger.log(
                IMPORTANT,
                'Note: The host "%s" is currently not known in the active'
                " monitoring configuration.\n"
                "You can however add this host to the monitoring later on without"
                " having to register again.\n"
                "Please check the exact spelling if you intended to register an existing host.",
                self._config.host_name,
            )
        return host_secret

    def _invalidate_cache_file_age(self) -> None:
        if not self._config.cache_file_location:
            self._logger.debug("Could not modify cache age: Cachefile not found.")
            return

        try:
            last_mod_time = int(os.path.getmtime(self._config.cache_file_location))
            assert self._config.interval is not None
            critical_timestamp = int(time.time()) - self._config.interval
            if last_mod_time > critical_timestamp:
                os.utime(self._config.cache_file_location, (critical_timestamp, critical_timestamp))
                self._logger.debug(
                    "Successfully scheduled an automatic update "
                    "with next Checkmk Agent execution."
                )
        except OSError:
            self._logger.log(LOG_ONLY, "Caught Exception:", exc_info=True)
            self._logger.debug(
                "Could not modify cache age: No access to cachefile %s)",
                self._config.cache_file_location,
            )


# .
#   .--Update--------------------------------------------------------------.
#   |                   _   _           _       _                          |
#   |                  | | | |_ __   __| | __ _| |_ ___                    |
#   |                  | | | | '_ \ / _` |/ _` | __/ _ \                   |
#   |                  | |_| | |_) | (_| | (_| | ||  __/                   |
#   |                   \___/| .__/ \__,_|\__,_|\__\___|                   |
#   |                        |_|                                           |
#   +----------------------------------------------------------------------+
#   |  Main entry for agent update                                         |
#   '----------------------------------------------------------------------'


class UpdateMode(GenericMode):
    @staticmethod
    def add_parser_group(arg_parser: argparse.ArgumentParser) -> None:
        update_group = arg_parser.add_argument_group("Update options")
        update_group.add_argument(
            "-G",
            "--skip-signatures",
            action="store_true",
            help="Skip validation of package signature",
        )
        update_group.add_argument(
            "-r", "--reinstall", action="store_true", help="Also update if package seems up-to-date"
        )
        update_group.add_argument(
            "-f", "--force", action="store_true", help="Do --skip-signatures and --reinstall"
        )
        update_group.add_argument(
            "-u",
            "--run-as-plugin",
            action="store_true",
            help="Behave like if called as agent plugin",
        )

    def _is_interactive_execution(self) -> bool:
        if self._config.run_as_plugin:  # manual debug option
            return False
        if os.getenv("MK_AGENT_UPDATER_MANUAL"):  # set by /usr/bin/cmk-update-agent script
            return True
        if os.getenv("MK_CONFDIR"):  # set by Checkmk Agent or /usr/bin/cmk-update-agent
            return False

        return True

    def _do_update_as_command(self) -> None:
        horizontal_bar = "+%s+" % ("-" * 67)
        space = "|%s|" % (" " * 67)
        text = "|  Checkmk Agent Updater v%s - Update%s|" % (
            __version__,
            " " * (32 - len(__version__)),
        )
        self._logger.log(
            USER_VERBOSE, "\n%s" * 5, horizontal_bar, space, text, space, horizontal_bar
        )
        self._logger.log(LOG_ONLY, "Starting manual update mode.")

        self._not_registered_info = (
            "Not yet registered at deployment server."
            " Please run 'cmk-update-agent register' first."
        )
        self._do_update_agent()

    def _do_update_as_plugin(self) -> None:
        self._logger.info("Starting Update mode as plugin.")  # goes to syslog

        send_feedback = False  # type: bool | None
        try:
            self._not_registered_info = (
                "The agent updater is not registered at the deployment server"
            )

            send_feedback = self._do_update_agent()

            self._config.last_error = None
            self._config.update_deployment_state(["last_error"])

        except Exception as exc:
            send_feedback = True
            self._config.last_error = str(exc)
            self._config.update_deployment_state(["last_error"])
            self._logger.log(LOG_ONLY, "Caught Exception:", exc_info=True)

        finally:
            self._write_agent_section()

            if send_feedback:
                self._push_status()

    def _write_agent_section(self) -> None:
        section = self._config.agent_section()
        self._logger.log(LOG_ONLY, "Writing agent section to stdout:\n%s", section)
        sys.stdout.write(section)

    def _push_status(self) -> None:
        if self._config.server is None:
            # This only makes sense if we have a server we can contact
            # That's not the case if the agent updater is running without registration.
            return
        self._logger.debug("Sending new state data to agent bakery")
        try:
            # Contact Checkmk server just in order to give immediate
            # feedback about the new situation - Suppress errors
            # arising from server feedback.
            self._fetch_agent_info(mode="status")
        except Exception:
            self._logger.log(LOG_ONLY, "Caught Exception:", exc_info=True)

    def _do_update_agent(self) -> "bool | None":
        """Check for new agents, download it

        - get target_state
        - download agent if current one differs from target_state
        - verify signature
        - call _trigger_installation(agent, target_state) with downloaded agent
        """

        if not self._is_registered():
            raise Exception(self._not_registered_info)

        # Get target configuration
        target_state = self._get_target_state()
        self._config.last_check = time.time()
        self._config.update_deployment_state(["last_check"])

        if not target_state.agent_available:
            self._logger.info("No agent available for us.")
            return None

        # If target_state.agent_available is falsy we already returned. So a
        # ValueError should be thrown by the init
        assert target_state.target_hash is not None

        self._logger.info("Target state (from deployment server):")
        target_state.log(self._logger)

        target_hash = target_state.target_hash
        # Should we update?
        if target_hash == self._config.installed_aghash:
            self._logger.info("Agent %s already installed.", target_hash)
            if self._config.reinstall:
                self._logger.info("Forcing reinstallation.")
            else:
                return None
        # If there is no signature or we do not accept any signature keys
        # then there is no point in going on.
        self._download_makes_sense(target_state)

        # Download agent and update
        agent = self._download_agent(target_hash)
        agent_data = AgentData(agent_data=agent, target_state=target_state)
        self._logger.info("Downloaded agent has size %d bytes.", len(agent))

        if self._config.skip_signatures:
            self._logger.info("Skipping signature check (as you requested).")
        else:
            # We have checked that in _download_makes_sense
            assert self._config.signature_keys is not None
            agent_data.check_signatures(self._logger, self._config.signature_keys)

        self._trigger_installation(agent_data)

        return True

    @abc.abstractmethod
    def _trigger_installation(self, agent_data: AgentData) -> None:
        raise NotImplementedError()

    def _get_target_state(self) -> TargetState:
        self._logger.info(
            "Getting target agent configuration for host %r from deployment server",
            self._config.host_name,
        )
        response = self._fetch_agent_info(mode="status")
        self._apply_update_server_info_response(response)
        return self._parse_agent_target_state(response)

    def _parse_agent_target_state(self, response: dict) -> TargetState:
        try:
            return TargetState(
                agent_available=response.get("AgentAvailable", False),
                signatures=[
                    (entry["certificate"], base64.b64decode(entry["signature"]))
                    for entry in response.get("Signatures", [])
                ],
                target_hash=response.get("TargetHash"),
            )
        except Exception:
            self._logger.log(LOG_ONLY, "Caught Exception:", exc_info=True)
            raise Exception("Garbled response from deployment server: %s" % response)

    def _download_makes_sense(self, target_state: TargetState) -> bool:
        """Check if a download of the agent makes sense, raise an Exception if
        it does not make sense...

        - If we have no signatures configured, and do not skip the signature
          checks we do not need to download the agent, since we cannot verify
          it anyways.
        - If the target_state has no signatures it also does not make sense to
          download the agent.
        """

        if self._config.skip_signatures:
            return True

        if not target_state.signatures:
            raise Exception("The deployment server provides an agent but that is not signed.")
        if not self._config.signature_keys:
            raise Exception("No signature keys are configured.")

        # check that at least one cert in target_state is trusted!
        for count, (certificate, _signature) in enumerate(target_state.signatures):
            if certificate not in self._config.signature_keys:
                self._logger.info(
                    "Ignoring signature #%d for certificate: certificate is unknown.", (count + 1)
                )
                continue
            return True
        raise Exception("No valid signature found.")

    def _download_agent(self, aghash: str) -> bytes:
        base64_agent = self._fetch_agent_info(mode="agent", target_aghash=aghash)["agent"]
        return base64.b64decode(base64_agent)

    def _fetch_agent_info(self, mode: str, target_aghash: str = "") -> "typing.Any":
        # mode seems to be Literal["agent", "status"], but we do not have Literal yet in 3.7
        post_vars = {
            "mode": mode,
            "host": self._config.host_name,
            "host_secret": self._config.host_secret,
            "installed_aghash": self._config.installed_aghash or "",
            "aghash": target_aghash,
            "os": self._env.opsys,
            "last_error": (self._config.last_error or "")[:512],  # cutoff recursive error
        }
        return self._http.fetch_data_from_server("deploy_agent.py", post_args=post_vars)

    def _is_registered(self) -> bool:
        if self._config.host_name is None or self._config.host_secret is None:
            return False

        return True


class WindowsUpdateMode(UpdateMode):
    def __init__(
        self,
        config_handler: ConfigHandler,
        environment_handler: EnvironmentHandler,
        http_handler: HttpHandler,
    ) -> None:
        UpdateMode.__init__(self, config_handler, environment_handler, http_handler)
        # Windows specific constants
        self._msi_path = self._get_msi_path()
        self._win_aghash_path = self._get_win_aghash_path()
        self._logger.debug("MSI deposit path is %s", self._msi_path)
        self._logger.debug("aghash info path is %s", self._win_aghash_path)

    def _get_msi_path(self) -> "str | None":
        msi_file = "check_mk_agent.msi"
        msi_dir = os.environ.get("MK_MSI_PATH", None)
        if msi_dir:
            return os.path.join(msi_dir, msi_file)

        update_dir = os.path.abspath(
            os.path.join(
                os.path.dirname(os.path.realpath(os.path.realpath(__file__))), "..", "update"
            )
        )
        if os.path.exists(update_dir):
            return os.path.join(update_dir, msi_file)
        return None

    def _get_win_aghash_path(self) -> "str | None":
        aghash_file = "checkmk.dat"
        win_aghash_dir = os.environ.get("MK_INSTALLDIR", None)
        if win_aghash_dir:
            return os.path.join(win_aghash_dir, aghash_file)

        install_dir = os.path.abspath(
            os.path.join(
                os.path.dirname(os.path.realpath(os.path.realpath(__file__))), "..", "install"
            )
        )
        if os.path.exists(install_dir):
            return os.path.join(install_dir, aghash_file)
        return None

    def _run_mode(self) -> None:
        if self._config.pending_hash:
            self._handle_pending_installation()
            if not self._is_interactive_execution():
                self._write_agent_section()
                self._push_status()
            return

        if self._is_interactive_execution():
            self._do_update_as_command()
            return

        self._do_update_as_plugin()

    def _handle_pending_installation(self) -> None:
        self._logger.info("Detected pending agent update. Checking state...")
        if self._win_aghash_path and os.path.exists(self._win_aghash_path):
            with open(self._win_aghash_path) as hash_file:
                hash_dict = yaml.safe_load(hash_file.read().strip())
                current_aghash = str(hash_dict["hash"])

            if self._config.pending_hash == current_aghash:
                self._handle_successful_installation(current_aghash)
                return

            if self._msi_path is None or not os.path.exists(self._msi_path):
                self._logger.warning(
                    "Agent not installed yet, but found no MSI file. Discarding pending agent hash."
                )
                self._handle_inconsistent_update()
                return

            self._logger.info("Update not performed yet.")
            return

        self._logger.warning("Agent installation not found. Discarding pending hash.")
        self._handle_inconsistent_update()

    def _handle_successful_installation(self, aghash: str) -> None:
        assert self._win_aghash_path is not None
        self._logger.info("Update successful!")
        self._config.installed_aghash = aghash
        self._config.pending_hash = None
        self._config.last_update = os.path.getmtime(self._win_aghash_path)
        self._config.last_error = None
        self._config.update_deployment_state(
            ["installed_aghash", "pending_hash", "last_update", "last_error"]
        )

    @staticmethod
    def _os_is_acceptable(agent: bytes) -> bool:
        """Checks that OS is appropriate for the downloaded agent.
        Now functionality is based on presence in MSI special marker requesting modern OS"""
        major, minor, *_ = sys.getwindowsversion()  # type: ignore[attr-defined]
        if major == 6 and minor < 2:
            modern_os_required_blob = "( VersionNT >= 602 )".encode("ascii")
            return agent.find(modern_os_required_blob) == -1

        return True

    def _trigger_installation(self, agent_data: AgentData) -> None:
        if not WindowsUpdateMode._os_is_acceptable(agent_data.agent_data):
            self._logger.error(
                "Agent installation can't be performed on this Windows OS."
                "You may need to adjust the rule Install Python runtime environment"
            )
            # TODO(au): write the error into the status and probably leave the function

        self._config.pending_hash = agent_data.target_state.target_hash
        self._config.update_deployment_state(["pending_hash"])
        if self._msi_path:
            self._deposit_msi(agent_data.agent_data)
            return
        self._install_msi(agent_data.agent_data)

    def _deposit_msi(self, agent: bytes) -> None:
        assert self._msi_path is not None  # This is checked right before calling the method
        with open(self._msi_path, "wb") as msi_file:
            msi_file.write(agent)
        self._logger.info(
            "Transferred MSI package to the agent's installation dir."
            "Awaiting upcoming automatic update performed by agent."
        )

    def _install_msi(self, agent: bytes) -> None:
        temp_msi_path = os.path.join(tempfile.gettempdir(), "check_mk_agent.msi")
        with open(temp_msi_path, "wb") as msi_file:
            msi_file.write(agent)

        command = ["msiexec", "/i", temp_msi_path, "/qn", "/quiet", "/norestart"]

        # Optional debugging, if available
        logdir = LoggingConfiguration.local_logdir()
        if logdir:
            command.extend(["/L*V", os.path.join(logdir, "msi_installer.log")])

        self._logger.info(
            "Installing Agent from %s and exiting."
            " Successful installation will be checked after the update.",
            temp_msi_path,
        )
        subprocess.Popen(  # pylint: disable=consider-using-with
            command,
            close_fds=True,
            # CREATE_NEW_PROCESS_GROUP is only available on windows
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,  # type: ignore[attr-defined]
        )


class UnixUpdateMode(UpdateMode):
    def _run_mode(self) -> None:
        if self._is_interactive_execution():
            self._do_update_as_command()
            self._config.update_cache_file()
            return

        self._do_update_as_plugin()

    def _trigger_installation(self, agent_data: AgentData) -> None:
        assert agent_data.target_state.target_hash is not None
        if self._env.run_sync_parts:
            UnixAgentInstaller(self._config, self._env).install_agent(
                agent_data.agent_data, agent_data.target_state.target_hash
            )
            return

        self._prepare_installation(agent_data)

    def _prepare_installation(self, agent_data: AgentData) -> None:
        self._config.pending_hash = agent_data.target_state.target_hash
        self._config.update_deployment_state(["pending_hash"])

        assert self._config.installation_candidate is not None
        with open(self._config.installation_candidate, "w") as agent_file:
            agent_data.serialize(agent_file)
        self._logger.info(
            "Transferred agent package to the agent's var dir."
            "Awaiting upcoming installation performed by agent."
        )


class UnixInstallMode(GenericMode):
    def _run_mode(self) -> None:
        intro = "Running agent updater in InstallMode... "

        if not self._config.installation_candidate:
            self._logger.debug(
                "%s Found no pending agent hash for installation. Nothing to do for us.", intro
            )
            return

        self._logger.debug(
            "%s Found pending agent hash %s. Updating agent...", intro, self._config.pending_hash
        )

        if not os.path.exists(self._config.installation_candidate):
            self._logger.warning(
                "Agent not updated yet, but found no agent package file. Discarding pending agent hash."
            )
            self._handle_inconsistent_update()
            return

        if not self._config.signature_keys:
            self._logger.debug("%s Found no configured signature keys. Abort...", intro)
            self._handle_inconsistent_update()
            os.unlink(self._config.installation_candidate)
            return

        with open(self._config.installation_candidate, "r") as agent_file:
            agent_data = AgentData.load(agent_file)

        agent_data.check_signatures(self._logger, self._config.signature_keys)

        assert self._config.pending_hash is not None
        if UnixAgentInstaller(self._config, self._env).install_agent(
            agent_data.agent_data, self._config.pending_hash
        ):
            try:
                os.remove(self._config.installation_candidate)
            except OSError:
                logging.log(LOG_ONLY, "Caught Exception:", exc_info=True)
                logging.warning(
                    "Could not remove temporary agent file at %s",
                    self._config.installation_candidate,
                )

            self._config.pending_hash = None
            self._config.update_deployment_state(["pending_hash"])
            self._config.update_cache_file()


class UnixAgentInstaller:
    _logger = logging.getLogger(__name__)

    def __init__(
        self, config_handler: ConfigHandler, environment_handler: EnvironmentHandler
    ) -> None:
        self._config = config_handler
        self._env = environment_handler

    def install_agent(self, agent: bytes, target_hash: str) -> bool:
        if not self._perform_installation(agent, target_hash):
            return False

        self._config.installed_aghash = target_hash
        self._config.last_update = time.time()
        self._config.update_deployment_state(["installed_aghash", "last_update"])
        self._logger.info("Successfully installed agent %s.", self._config.installed_aghash)
        return True

    def _perform_installation(self, agent: bytes, target_hash: str) -> bool:
        agent_installed = False
        with tempfile.NamedTemporaryFile(prefix="check-mk-agent-", delete=False) as agent_file:
            agent_file.write(agent)
            filename = agent_file.name

        try:
            self._invoke_installer(filename)
            agent_installed = True
        except Exception as exc:
            self._logger.log(LOG_ONLY, "Caught Exception:", exc_info=True)
            self._logger.error("Failed installing Checkmk agent: %s.", exc)
            self._logger.info(
                "Hint: You can try to install or analyze the agent package "
                "manually by downloading it from the checkmk server. You can find it by looking "
                "for your OS's package for host %s with agent hash %s at the agent bakery.",
                self._config.host_name,
                target_hash,
            )
            raise

        finally:
            try:
                os.remove(filename)
            except OSError:
                logging.log(LOG_ONLY, "Caught Exception:", exc_info=True)
                logging.warning("Could not remove temporary agent file at %s", filename)

        return agent_installed

    def _invoke_installer(self, filename: str) -> None:
        if self._env.opsys == "linux_rpm":
            self._install_agent_linux_rpm(filename)
            return
        if self._env.opsys == "linux_deb":
            self._install_agent_linux_deb(filename)
            return
        if self._env.opsys == "solaris_pkg":
            self._install_agent_solaris_pkg(filename)
            return
        # elif config["opsys"] == "linux_tgz":
        #    install_agent_linux_tgz(filename)
        raise Exception("opsys %s not implemented" % self._env.opsys)

    def _install_agent_linux_deb(self, filename: str) -> None:
        self._invoke_unix_pkg_manager(["dpkg", "-i", filename])

    def _install_agent_linux_rpm(self, filename: str) -> None:
        self._invoke_unix_pkg_manager(["rpm", "-vU", "--oldpackage", "--replacepkgs", filename])

    def _install_agent_solaris_pkg(self, filename: str) -> None:
        # Our current working directory may get deleted by the subsequent pkgrm call.
        # pkgadd can't handle this. We avoid this situation by changing to /
        os.chdir("/")
        # First create a temporary answer file for pkgrm/pkgadd to be able to execute
        # the command in non interactive mode
        with tempfile.NamedTemporaryFile(
            prefix="check-mk-agent-pkadd-response", delete=False, mode="w"
        ) as response_file:
            response_file.write(
                "mail=\n"
                "instance=overwrite\n"
                "partial=nocheck\n"
                "runlevel=nocheck\n"
                "idepend=nocheck\n"
                "rdepend=nocheck\n"
                "space=nocheck\n"
                "setuid=nocheck\n"
                "conflict=nocheck\n"
                "action=nocheck\n"
                "networktimeout=60\n"
                "networkretries=3\n"
                "authentication=quit\n"
                "keystore=/var/sadm/security\n"
                "proxy=\n"
                "basedir=default\n"
            )
            response_filename = response_file.name

        try:
            self._remove_agent_solaris_pkg(response_filename)

            self._logger.info("Installing new check-mk-agent\n")
            self._invoke_unix_pkg_manager(
                ["pkgadd", "-n", "-a", response_filename, "-d", filename, "check-mk-agent"]
            )

        finally:
            os.remove(response_filename)

    def _remove_agent_solaris_pkg(self, response_filename: str) -> None:
        if (
            subprocess.call(
                ["pkginfo", "check-mk-agent"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT,
            )
            != 0
        ):
            self._logger.info("Found no previous check-mk-agent package to remove.")
            return

        self._logger.info("Removing previous check-mk-agent package.")

        proc = subprocess.Popen(  # pylint: disable=consider-using-with
            ["pkgrm", "-n", "-a", response_filename, "check-mk-agent"],
            encoding="utf-8",
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            close_fds=True,
            env=self._env.sub_env,
        )
        stdout, _stderr = proc.communicate()
        if proc.returncode != 0:
            raise Exception(
                "Error (%d) during installation of package:\n%s" % (proc.returncode, stdout)
            )

    def _invoke_unix_pkg_manager(self, command: "Sequence[str]") -> None:
        pkg_manager_command = command[0]
        self._logger.info("Invoking package manager: %s", subprocess.list2cmdline(command))
        proc = subprocess.run(
            command,
            encoding="utf-8",
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            close_fds=True,
            env=self._env.sub_env,
            check=False,
        )
        # We merge stdout and stderr, because there is no clear differentiation between
        # the meaning of the two streams in this context.
        if proc.stdout:
            self._logger.info(
                "Output from %s:\n  %s",
                pkg_manager_command,
                proc.stdout.replace("\n", "\n  "),
            )
        if proc.returncode != 0:
            raise Exception("Error during installation of package")


class ShowConfigMode(GenericMode):
    def _run_mode(self) -> None:
        self._logger.log(LOG_ONLY, "Starting show-config mode.")
        self._logger.log(USER_ONLY, "Showing current configuration...")

        if os.path.exists(self._config.config_file_path):
            self._logger.log(
                USER_ONLY, "\nConfiguration from config file (%s):", self._config.config_file_path
            )
            for entry in [
                attr
                for attr in self._config.config_origin
                if self._config.config_origin[attr] == "config_file"
            ]:
                self._logger.log(USER_ONLY, "%s: %s", entry, getattr(self._config, entry))
        else:
            self._logger.log(
                USER_ONLY, "Configuration file (%s) not found.", self._config.config_file_path
            )

        if os.path.exists(self._config.state_file_path):
            self._logger.log(
                USER_ONLY, "\nConfiguration from state file (%s):", self._config.state_file_path
            )
            for entry in [
                attr
                for attr in self._config.config_origin
                if self._config.config_origin[attr] == "state_file"
            ]:
                self._logger.log(USER_ONLY, "%s: %s", entry, getattr(self._config, entry))
        else:
            self._logger.log(
                USER_ONLY, "\nState file (%s) not found.", self._config.state_file_path
            )


# .
#   .--Main----------------------------------------------------------------.
#   |                        __  __       _                                |
#   |                       |  \/  | __ _(_)_ __                           |
#   |                       | |\/| |/ _` | | '_ \                          |
#   |                       | |  | | (_| | | | | |                         |
#   |                       |_|  |_|\__,_|_|_| |_|                         |
#   |                                                                      |
#   +----------------------------------------------------------------------+
#   |  Main entry point                                                    |
#   |  Init error handling, trigger generic execution, catch errors        |
#   '----------------------------------------------------------------------'


class LoggingConfiguration:
    _logger = logging.getLogger(__name__)
    _pid = "[" + str(os.getpid()) + "]"

    class VerbosityFormatter(logging.Formatter):
        def format(self, record: logging.LogRecord) -> str:
            self._fmt = LoggingConfiguration._pid + " " + self.get_fmt(record.levelno)
            return logging.Formatter.format(self, record)

        @staticmethod
        def get_fmt(levelno: int) -> str:
            if levelno == logging.WARN:
                return "%s%s %s%s" % (TTY_BOLD, "%(levelname)s", "%(message)s", TTY_NORMAL)
            if levelno == logging.ERROR:
                return "%s%s %s%s" % (TTY_RED, "%(levelname)s", "%(message)s", TTY_NORMAL)
            if levelno == IMPORTANT:
                return "%s%s%s" % (TTY_BOLD, "%(message)s", TTY_NORMAL)

            return "%(message)s"

    @staticmethod
    def _log_filter(record: logging.LogRecord) -> bool:
        return record.levelno not in (USER_ONLY, USER_VERBOSE)

    def __init__(self, logger: logging.Logger, verbosity: int, logfile: str) -> None:
        self._logfile = logfile
        self._logger = logger
        self._map_custom_levels()
        self._logger.setLevel(LOG_ONLY)  # enable root logger to pass everything
        self._logger.addHandler(self._get_verbosity_handler(verbosity))
        file_target = self._add_file_log_handler()
        self._logging_target = self._add_syslog_handler(file_target)

    @staticmethod
    def _map_custom_levels() -> None:
        logging.addLevelName(LOG_ONLY, "DEBUG")
        logging.addLevelName(USER_AND_LOG, "INFO")
        logging.addLevelName(IMPORTANT, "INFO")

    def _add_file_log_handler(self) -> "str | None":
        if self._logfile:
            file_log_handler = self._get_file_log_handler(self._logfile)
            self._logger.addHandler(file_log_handler)
            return "Logfile at %s" % self._logfile

        logdir = self.local_logdir()
        if logdir:
            logfile = os.path.join(logdir, "cmk-update-agent.log")
            file_log_handler = self._get_file_log_handler(logfile)
            self._logger.addHandler(file_log_handler)
            return "Logfile at %s" % logfile

        return None

    def _add_syslog_handler(self, file_target: "str | None") -> "str | None":
        if os.name == "posix":
            try:
                syslog_handler = self._get_syslog_handler()
                self._logger.addHandler(syslog_handler)
                return "syslog%s" % (" or %s" % file_target if file_target else "")
            except Exception as exc:
                self._logger.log(LOG_ONLY, "Caught Exception:", exc_info=True)
                self._logger.warning("Unable to initialize logging to syslog: %s", exc)
                if file_target:
                    self._logger.log(USER_ONLY, "See %s for details." % file_target)
        return None

    @staticmethod
    def local_logdir() -> "str | None":
        if os.name == "nt":
            return LoggingConfiguration.local_logdir_windows()
        if os.name == "posix":
            return LoggingConfiguration.local_logdir_linux()
        return None

    @staticmethod
    def local_logdir_windows() -> "str | None":
        logdir = os.getenv(
            "MK_LOGDIR",
            os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "log")),
        )
        if os.path.exists(logdir):
            return logdir
        return None

    @staticmethod
    def local_logdir_linux() -> "str | None":
        return os.getenv("MK_VARDIR", None)

    @staticmethod
    def _get_verbosity_handler(verbosity: int) -> logging.StreamHandler:
        MAX_VERBOSITY = 2
        verbosity_dict = {0: USER_AND_LOG, 1: logging.INFO, 2: logging.DEBUG}
        verbosity_handler = logging.StreamHandler()
        verbosity_handler.setLevel(verbosity_dict[min(verbosity, MAX_VERBOSITY)])
        verbosity_handler.setFormatter(LoggingConfiguration.VerbosityFormatter())

        return verbosity_handler

    @staticmethod
    def _get_syslog_handler() -> logging.handlers.SysLogHandler:
        syslog_handler = logging.handlers.SysLogHandler(address="/dev/log")
        syslog_formatter = logging.Formatter("[cmk-update-agent] %(levelname)s: %(message)s")
        syslog_handler.setFormatter(syslog_formatter)
        syslog_handler.setLevel(logging.WARNING)
        syslog_handler.addFilter(LoggingConfiguration._log_filter)

        return syslog_handler

    @staticmethod
    def _get_file_log_handler(logfile: str) -> logging.handlers.RotatingFileHandler:
        file_log_handler = logging.handlers.RotatingFileHandler(
            logfile, maxBytes=5 * 1024 * 2014, backupCount=3
        )
        file_log_formatter = logging.Formatter(
            "%(asctime)s " + LoggingConfiguration._pid + " %(levelname)s: %(message)s"
        )
        file_log_handler.setFormatter(file_log_formatter)
        file_log_handler.setLevel(LOG_ONLY)  # use lowest level to log tracebacks
        file_log_handler.addFilter(LoggingConfiguration._log_filter)

        return file_log_handler

    @property
    def logging_target(self) -> "str | None":
        return self._logging_target


def main(argv: "list[str] | None" = None) -> None:
    if argv is None:
        argv = sys.argv

    os.environ.pop("LANG", None)

    env = EnvironmentHandler()  # Error handling is set up here

    cmdline_opts = OptionParser(argv)

    logger = logging.getLogger(__name__)
    logging_config = LoggingConfiguration(
        logger, cmdline_opts.arg_namespace.verbose_level, cmdline_opts.arg_namespace.logfile
    )

    logger.log(LOG_ONLY, "Starting Checkmk Agent Updater v%s", __version__)

    try:
        config = ConfigHandler(env, cmdline_opts)
        requested_mode = config.mode  # get mode evaluated from cmdline by ConfigHandler
        requested_mode.run()
        logger.debug("Done.")
    except Exception as exc:
        logger.log(LOG_ONLY, "Caught Exception:", exc_info=True)
        logger.error(exc)
        if logging_config.logging_target:
            logger.log(USER_ONLY, "See %s for details.", logging_config.logging_target)
        sys.exit(1)


if __name__ == "__main__":
    main()
