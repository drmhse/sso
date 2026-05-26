#!/usr/bin/env python3

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
from urllib.parse import quote, urlsplit
from datetime import datetime, timedelta, timezone
from pathlib import Path


STATE_VERSION = 2
AUTHOS_USER = "authos"
INSTALL_ROOT = Path("/opt/authos")
INSTALL_BINARY = Path("/usr/local/bin/authos")
APPLY_WRAPPER = Path("/usr/local/bin/authos-apply")
CONFIG_DIR = Path("/etc/authos")
ENV_PATH = CONFIG_DIR / "authos.env"
INSTALL_STATE_PATH = CONFIG_DIR / "install-state.json"
SERVICE_PATH = Path("/etc/systemd/system/authos.service")
APPLY_SERVICE_PATH = Path("/etc/systemd/system/authos-apply.service")
APPLY_PATH_UNIT_PATH = Path("/etc/systemd/system/authos-apply.path")
CADDY_ROOT = Path("/etc/caddy")
CADDY_SITE_DIR = CADDY_ROOT / "sites-enabled"
CADDY_SITE_PATH = CADDY_SITE_DIR / "authos.caddy"


def main() -> int:
    parser = argparse.ArgumentParser(description="Install and manage standalone AuthOS")
    subparsers = parser.add_subparsers(dest="command", required=True)

    install_parser = subparsers.add_parser("install", help="Install or upgrade AuthOS")
    install_parser.add_argument("--bundle-dir", required=True)
    install_parser.add_argument("--config", help="Path to a config.json to install")
    install_parser.add_argument("--no-start", action="store_true")

    apply_parser = subparsers.add_parser("apply", help="Render config and restart AuthOS")
    apply_parser.add_argument("--bundle-dir", required=True)
    apply_parser.add_argument("--no-print-link", action="store_true")
    apply_parser.add_argument("--skip-start", action="store_true")

    args = parser.parse_args()

    try:
        if args.command == "install":
            require_root()
            install(
                Path(args.bundle_dir),
                Path(args.config).resolve() if args.config else None,
                args.no_start,
            )
        elif args.command == "apply":
            require_root()
            apply(
                Path(args.bundle_dir),
                print_link=not args.no_print_link,
                start_service=not args.skip_start,
            )
        return 0
    except Exception as exc:
        write_failure_status(str(exc))
        print(f"AuthOS standalone error: {exc}", file=sys.stderr)
        return 1


def install(bundle_dir: Path, config_source: Path | None, no_start: bool) -> None:
    stop_existing_service()
    ensure_system_user()
    copy_bundle(bundle_dir)
    current_paths = managed_paths()
    ensure_dir(current_paths["data_dir"], mode=0o700)
    chown_path(current_paths["data_dir"], AUTHOS_USER, AUTHOS_USER)

    desired_config = None
    if config_source:
        desired_config = load_json(config_source)
    elif not current_paths["config_path"].exists():
        example_config = load_json(bundle_dir / "authos.config.example.json")
        desired_config = seed_initial_config(example_config)
    elif not INSTALL_STATE_PATH.exists():
        desired_config = load_json(current_paths["config_path"])

    if desired_config is not None:
        desired_state = build_install_state(desired_config)
        desired_paths = paths_for_data_dir(Path(desired_state["dataDir"]))
        if current_paths != desired_paths:
            relocate_managed_paths(current_paths, desired_paths)
            current_paths = desired_paths
        write_install_state(desired_state)
        config = normalize_config(desired_config, install_state=desired_state)
        write_json(current_paths["config_path"], config, mode=0o640)
        chown_path(current_paths["config_path"], AUTHOS_USER, AUTHOS_USER)
    else:
        current_state = load_install_state()
        write_install_state(current_state)

    apply(bundle_dir, print_link=True, start_service=not no_start)


def apply(bundle_dir: Path, print_link: bool, start_service: bool) -> None:
    current_paths = managed_paths()
    ensure_dir(current_paths["data_dir"], mode=0o700)
    chown_path(current_paths["data_dir"], AUTHOS_USER, AUTHOS_USER)
    ensure_dir(CONFIG_DIR, mode=0o755)

    install_state = load_install_state()
    config = normalize_config(load_json(current_paths["config_path"]), install_state=install_state)
    paths = current_paths
    ensure_dir(paths["sqlite_dir"], mode=0o700)
    chown_path(paths["sqlite_dir"], AUTHOS_USER, AUTHOS_USER)
    ensure_apply_request_file(paths)

    state = ensure_state(load_json(paths["state_path"], {}))
    write_status(paths["status_path"], {
        "status": "running",
        "message": "Applying AuthOS configuration.",
        "updated_at": now_rfc3339(),
    })

    env_values = build_env(config, state, paths)
    write_json(paths["config_path"], config, mode=0o640)
    write_json(paths["state_path"], state, mode=0o640)
    write_env(ENV_PATH, env_values, mode=0o640)
    chown_path(paths["config_path"], AUTHOS_USER, AUTHOS_USER)
    chown_path(paths["state_path"], AUTHOS_USER, AUTHOS_USER)
    chown_path(paths["status_path"], AUTHOS_USER, AUTHOS_USER)
    chown_path(paths["request_path"], AUTHOS_USER, AUTHOS_USER)
    chown_path(ENV_PATH, "root", AUTHOS_USER)

    install_apply_wrapper()
    write_systemd_unit(config, paths)
    write_apply_service_unit(paths)
    write_apply_path_unit(paths)

    run(["systemctl", "daemon-reload"])
    run(["systemctl", "enable", "authos.service"])
    run(["systemctl", "enable", "authos-apply.path"])
    run(["systemctl", "restart", "authos-apply.path"])
    remove_legacy_sudoers()
    configure_caddy(config, paths)

    if start_service:
        run(["systemctl", "restart", "authos.service"])
        wait_for_systemd("authos.service")

    login_url = bootstrap_login_url(config, state)
    write_status(paths["status_path"], {
        "status": "success",
        "message": "AuthOS configuration applied successfully.",
        "updated_at": now_rfc3339(),
        "public_url": config["deployment"]["platformBaseUrl"],
        "config_path": str(paths["config_path"]),
        "login_url": login_url,
    })

    if print_link:
        print("")
        print("AuthOS standalone apply complete")
        print(f"Config: {paths['config_path']}")
        print(f"State: {paths['state_path']}")
        print(f"Status: {paths['status_path']}")
        print(f"Public URL: {config['deployment']['platformBaseUrl']}")
        if login_url:
            print(f"Bootstrap login link: {login_url}")
        print("")


def managed_paths() -> dict:
    data_dir = managed_data_dir()
    return paths_for_data_dir(data_dir)


def paths_for_data_dir(data_dir: Path) -> dict:
    return {
        "data_dir": data_dir,
        "sqlite_dir": data_dir / "data",
        "config_path": data_dir / "config.json",
        "state_path": data_dir / "state.json",
        "status_path": data_dir / "status.json",
        "request_path": data_dir / "apply-request.json",
    }


def seed_initial_config(example: dict) -> dict:
    config = json.loads(json.dumps(example))
    ip_address = detect_primary_ip()
    api_port = int(config.get("deployment", {}).get("apiPort") or 3001)
    base_url = f"http://{ip_address}:{api_port}"

    deployment = config.setdefault("deployment", {})
    deployment["backend"] = "sqlite"
    deployment["buildLocalImage"] = False
    deployment["image"] = ""
    deployment["apiPort"] = api_port
    deployment["baseUrl"] = base_url
    deployment["platformBaseUrl"] = base_url
    deployment["fullWebClientBaseUrl"] = ""
    deployment["trustProxyHeaders"] = False
    deployment["trustedProxyIps"] = ""
    deployment["disableRateLimiting"] = False
    deployment["geoipDisabled"] = True
    deployment["jobProcessorIntervalSecs"] = 10
    deployment["jobProcessorBatchSize"] = 10

    smtp = config.setdefault("smtp", {})
    smtp["mode"] = "disabled"
    smtp["host"] = ""
    smtp["port"] = 1025
    smtp["username"] = ""
    smtp["password"] = ""
    smtp["fromEmail"] = smtp.get("fromEmail") or "noreply@authos.local"
    smtp["fromName"] = smtp.get("fromName") or "AuthOS"

    services = config.get("services") or []
    if services:
        for service in services:
            redirect_uris = service.get("redirectUris") or []
            if redirect_uris:
                service["redirectUris"] = [f"{base_url}/callback"]

    config.setdefault("standalone", {
        "dataDir": "/var/lib/authos",
    })
    config.setdefault("caddy", {
        "enabled": False,
        "install": False,
        "domain": "",
        "email": "",
        "tls": "auto",
    })
    return config


def normalize_config(config: dict, install_state: dict | None = None) -> dict:
    if not isinstance(config, dict):
        raise RuntimeError("Managed config must be a JSON object")

    deployment = config.setdefault("deployment", {})
    previous_base_url = normalize_url_value(deployment.get("baseUrl"))
    previous_platform_base_url = normalize_url_value(deployment.get("platformBaseUrl"))
    previous_public_urls = {value for value in (previous_base_url, previous_platform_base_url) if value}
    if deployment.get("backend", "sqlite") != "sqlite":
        raise RuntimeError("Standalone AuthOS currently supports deployment.backend=sqlite only")

    standalone = config.setdefault("standalone", {})
    install_state = install_state or load_install_state()
    standalone["dataDir"] = install_state["dataDir"]

    caddy = config.setdefault("caddy", {})
    caddy.setdefault("enabled", False)
    caddy["install"] = bool(install_state.get("allowCaddyInstall", False))
    caddy.setdefault("domain", "")
    caddy.setdefault("email", "")
    caddy.setdefault("tls", "auto")

    deployment["apiPort"] = int(deployment.get("apiPort") or 3001)

    if caddy.get("enabled"):
        domain = caddy.get("domain", "").strip()
        if not domain:
            raise RuntimeError("caddy.domain must be set when caddy.enabled=true")
        tls_mode = caddy.get("tls", "auto")
        if tls_mode not in {"auto", "internal", "disabled"}:
            raise RuntimeError("caddy.tls must be one of auto, internal, or disabled")
        scheme = "http" if tls_mode == "disabled" else "https"
        public_url = f"{scheme}://{domain}"
        deployment["baseUrl"] = public_url
        deployment["platformBaseUrl"] = public_url
        deployment["trustProxyHeaders"] = True
        deployment["trustedProxyIps"] = deployment.get("trustedProxyIps") or "127.0.0.1,::1"
        deployment["serverHost"] = "127.0.0.1"
    else:
        base_url = str(deployment.get("baseUrl") or "").strip()
        if not base_url:
            base_url = f"http://{detect_primary_ip()}:{deployment['apiPort']}"
            deployment["baseUrl"] = base_url
        deployment["platformBaseUrl"] = str(deployment.get("platformBaseUrl") or base_url).rstrip("/")
        deployment["baseUrl"] = str(deployment["baseUrl"]).rstrip("/")
        deployment["trustProxyHeaders"] = bool(deployment.get("trustProxyHeaders"))
        deployment["serverHost"] = deployment.get("serverHost") or "0.0.0.0"

    deployment.setdefault("rustLog", "info")
    deployment.setdefault("fullWebClientBaseUrl", "")
    deployment.setdefault("disableRateLimiting", False)
    deployment.setdefault("geoipDisabled", True)
    deployment.setdefault("jobProcessorIntervalSecs", 10)
    deployment.setdefault("jobProcessorBatchSize", 10)
    deployment.setdefault("maxMindLicenseKey", "")

    platform_owner = config.setdefault("platformOwner", {})
    platform_owner.setdefault("email", "admin@example.com")
    platform_owner.setdefault("password", "")

    billing = config.setdefault("billing", {})
    billing.setdefault("provider", "stripe")
    billing.setdefault("stripeSecretKey", "sk_test_bootstrap_placeholder")
    billing.setdefault("stripeWebhookSecret", "whsec_bootstrap_placeholder")
    billing.setdefault("stripeWebhookTestMode", True)
    billing.setdefault("stripeApiBaseUrl", "")
    billing.setdefault("polarApiKey", "")
    billing.setdefault("polarWebhookSecret", "")
    billing.setdefault("polarApiBaseUrl", "")

    smtp = config.setdefault("smtp", {})
    smtp.setdefault("mode", "disabled")
    smtp.setdefault("fromEmail", "noreply@authos.local")
    smtp.setdefault("fromName", "AuthOS")
    smtp.setdefault("host", "")
    smtp.setdefault("port", 1025)
    smtp.setdefault("username", "")
    smtp.setdefault("password", "")

    oauth = config.setdefault("oauth", {})
    for provider in ("github", "google", "microsoft"):
        oauth.setdefault(provider, {
            "clientId": "",
            "clientSecret": "",
            "authUrl": "",
            "tokenUrl": "",
            "userApiUrl": "",
        })
        oauth[provider].setdefault("clientId", "")
        oauth[provider].setdefault("clientSecret", "")
        oauth[provider].setdefault("authUrl", "")
        oauth[provider].setdefault("tokenUrl", "")
        oauth[provider].setdefault("userApiUrl", "")
        oauth[provider]["redirectUri"] = admin_oauth_redirect_uri(deployment["baseUrl"], provider)

    rewrite_managed_service_redirects(
        config.get("services") or [],
        previous_public_urls,
        deployment["baseUrl"],
    )

    return config


def ensure_state(state: dict) -> dict:
    if state.get("version") != STATE_VERSION:
        state = {}

    jwt = state.get("jwt") or generate_jwt_keys()
    bootstrap_login = state.get("bootstrap_login") or {}
    if not bootstrap_login.get("token"):
        bootstrap_login = {
            "token": secrets.token_urlsafe(32),
            "created_at": now_rfc3339(),
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=7)).isoformat(),
            "used_at": None,
        }

    return {
        "version": STATE_VERSION,
        "updatedAt": now_rfc3339(),
        "jwt": jwt,
        "encryptionKey": state.get("encryptionKey") or secrets.token_hex(32),
        "deviceTrustSecret": state.get("deviceTrustSecret") or secrets.token_hex(32),
        "bootstrap_login": bootstrap_login,
    }


def generate_jwt_keys() -> dict:
    if shutil.which("openssl") is None:
        raise RuntimeError("openssl is required to generate JWT keys")

    with tempfile.TemporaryDirectory() as temp_dir:
        private_key_path = Path(temp_dir) / "jwt-private.pem"
        public_key_path = Path(temp_dir) / "jwt-public.pem"
        run([
            "openssl",
            "genpkey",
            "-algorithm",
            "RSA",
            "-out",
            str(private_key_path),
            "-pkeyopt",
            "rsa_keygen_bits:2048",
        ])
        run([
            "openssl",
            "rsa",
            "-pubout",
            "-in",
            str(private_key_path),
            "-out",
            str(public_key_path),
        ])
        return {
            "privateKeyBase64": base64.b64encode(private_key_path.read_bytes()).decode("utf-8"),
            "publicKeyBase64": base64.b64encode(public_key_path.read_bytes()).decode("utf-8"),
            "kid": f"authos-{secrets.token_hex(8)}",
        }


def build_env(config: dict, state: dict, paths: dict) -> dict:
    deployment = config["deployment"]
    billing = config["billing"]
    smtp = config["smtp"]
    oauth = config["oauth"]

    env = {
        "DATABASE_URL": f"sqlite://{paths['sqlite_dir'] / 'authos.db'}?mode=rwc",
        "RUST_LOG": deployment["rustLog"],
        "JWT_PRIVATE_KEY_BASE64": state["jwt"]["privateKeyBase64"],
        "JWT_PUBLIC_KEY_BASE64": state["jwt"]["publicKeyBase64"],
        "JWT_KID": state["jwt"]["kid"],
        "JWT_EXPIRATION_HOURS": "24",
        "BILLING_PROVIDER": billing["provider"],
        "STRIPE_SECRET_KEY": billing["stripeSecretKey"],
        "STRIPE_WEBHOOK_SECRET": billing["stripeWebhookSecret"],
        "SERVER_HOST": deployment["serverHost"],
        "SERVER_PORT": str(deployment["apiPort"]),
        "BASE_URL": deployment["baseUrl"],
        "PLATFORM_BASE_URL": deployment["platformBaseUrl"],
        "PLATFORM_OWNER_EMAIL": config["platformOwner"]["email"],
        "ENCRYPTION_KEY": state["encryptionKey"],
        "DEVICE_TRUST_SECRET": state["deviceTrustSecret"],
        "DISABLE_RATE_LIMITING": str(bool(deployment["disableRateLimiting"])).lower(),
        "TRUST_PROXY_HEADERS": str(bool(deployment["trustProxyHeaders"])).lower(),
        "TRUSTED_PROXY_IPS": deployment.get("trustedProxyIps", ""),
        "GEOIP_DISABLED": str(bool(deployment["geoipDisabled"])).lower(),
        "MAXMIND_LICENSE_KEY": deployment.get("maxMindLicenseKey", ""),
        "JOB_PROCESSOR_INTERVAL_SECS": str(int(deployment["jobProcessorIntervalSecs"])),
        "JOB_PROCESSOR_BATCH_SIZE": str(int(deployment["jobProcessorBatchSize"])),
        "AUTHOS_MANAGED_CONFIG_PATH": str(paths["config_path"]),
        "AUTHOS_MANAGED_STATE_PATH": str(paths["state_path"]),
        "AUTHOS_MANAGED_STATUS_PATH": str(paths["status_path"]),
        "AUTHOS_MANAGED_REQUEST_PATH": str(paths["request_path"]),
    }

    add_if(env, "PLATFORM_OWNER_PASSWORD", config["platformOwner"].get("password"))

    if deployment.get("fullWebClientBaseUrl"):
        env["FULL_WEB_CLIENT_BASE_URL"] = deployment["fullWebClientBaseUrl"]
    if billing.get("stripeApiBaseUrl"):
        env["STRIPE_API_BASE_URL"] = billing["stripeApiBaseUrl"]
    if billing.get("polarApiKey"):
        env["POLAR_API_KEY"] = billing["polarApiKey"]
    if billing.get("polarWebhookSecret"):
        env["POLAR_WEBHOOK_SECRET"] = billing["polarWebhookSecret"]
    if billing.get("polarApiBaseUrl"):
        env["POLAR_API_BASE_URL"] = billing["polarApiBaseUrl"]

    for provider, prefix in (("github", "PLATFORM_GITHUB"), ("google", "PLATFORM_GOOGLE"), ("microsoft", "PLATFORM_MICROSOFT")):
        cfg = oauth[provider]
        add_if(env, f"{prefix}_CLIENT_ID", cfg.get("clientId"))
        add_if(env, f"{prefix}_CLIENT_SECRET", cfg.get("clientSecret"))
        add_if(env, f"{prefix}_REDIRECT_URI", cfg.get("redirectUri"))
        add_if(env, f"{prefix}_AUTH_URL", cfg.get("authUrl"))
        add_if(env, f"{prefix}_TOKEN_URL", cfg.get("tokenUrl"))
        add_if(env, f"{prefix}_USER_API_URL", cfg.get("userApiUrl"))

    if smtp.get("mode") != "disabled":
        add_if(env, "SMTP_HOST", smtp.get("host"))
        add_if(env, "SMTP_PORT", str(smtp.get("port") or 1025))
        add_if(env, "SMTP_USERNAME", smtp.get("username"))
        add_if(env, "SMTP_PASSWORD", smtp.get("password"))
        add_if(env, "SMTP_FROM_EMAIL", smtp.get("fromEmail"))
        add_if(env, "SMTP_FROM_NAME", smtp.get("fromName"))

    return env


def rewrite_managed_service_redirects(services: list[dict], previous_public_urls: set[str], base_url: str) -> None:
    for service in services:
        redirect_uris = service.get("redirectUris")
        if not isinstance(redirect_uris, list):
            continue

        rewritten = []
        for redirect_uri in redirect_uris:
            normalized = normalize_url_value(redirect_uri)
            if normalized and should_follow_authos_callback(normalized, previous_public_urls):
                rewritten.append(f"{base_url}/callback")
            else:
                rewritten.append(redirect_uri)
        service["redirectUris"] = rewritten


def should_follow_authos_callback(url: str, previous_public_urls: set[str]) -> bool:
    try:
        parsed = urlsplit(url)
    except Exception:
        return False

    if parsed.query or parsed.fragment or parsed.path.rstrip("/") != "/callback":
        return False

    origin = normalize_url_value(f"{parsed.scheme}://{parsed.netloc}")
    return bool(origin and origin in previous_public_urls)


def admin_oauth_redirect_uri(base_url: str, provider: str) -> str:
    return f"{normalize_url_value(base_url)}/auth/admin/{provider}/callback"


def normalize_url_value(value) -> str:
    return str(value or "").strip().rstrip("/")


def configure_caddy(config: dict, paths: dict) -> None:
    caddy = config["caddy"]

    if not caddy.get("enabled"):
        if CADDY_SITE_PATH.exists():
            CADDY_SITE_PATH.unlink()
            if shutil.which("systemctl") and shutil.which("caddy"):
                run(["systemctl", "reload", "caddy.service"], check=False)
        return

    if shutil.which("caddy") is None:
        if not caddy.get("install"):
            raise RuntimeError("Caddy is enabled in config.json but caddy is not installed")
        install_caddy()

    ensure_dir(CADDY_SITE_DIR, mode=0o755)
    ensure_caddy_main_file()
    CADDY_SITE_PATH.write_text(render_caddy_site(config, paths), encoding="utf-8")
    run(["caddy", "validate", "--config", str(CADDY_ROOT / "Caddyfile")])
    run(["systemctl", "enable", "caddy.service"])
    run(["systemctl", "restart", "caddy.service"])
    wait_for_systemd("caddy.service")


def install_caddy() -> None:
    if shutil.which("apt-get") is None:
        raise RuntimeError("Automatic Caddy installation requires apt-get")
    run(["apt-get", "update"])
    run(["apt-get", "install", "-y", "caddy"])


def ensure_caddy_main_file() -> None:
    ensure_dir(CADDY_ROOT, mode=0o755)
    caddyfile = CADDY_ROOT / "Caddyfile"
    if not caddyfile.exists():
        caddyfile.write_text("import /etc/caddy/sites-enabled/*.caddy\n", encoding="utf-8")
        return

    content = caddyfile.read_text(encoding="utf-8")
    include_line = "import /etc/caddy/sites-enabled/*.caddy"
    if include_line not in content:
        content = content.rstrip() + "\n\n" + include_line + "\n"
        caddyfile.write_text(content, encoding="utf-8")


def render_caddy_site(config: dict, paths: dict) -> str:
    caddy = config["caddy"]
    host = caddy["domain"]
    admin_email = caddy.get("email", "").strip()
    tls_mode = caddy.get("tls", "auto")
    admin_block = f"{{\n  email {admin_email}\n}}\n\n" if admin_email else ""
    site_label = f"http://{host}" if tls_mode == "disabled" else host
    tls_directive = "  tls internal\n" if tls_mode == "internal" else ""

    return (
        f"{admin_block}"
        f"{site_label} {{\n"
        f"  encode zstd gzip\n"
        f"{tls_directive}"
        f"  reverse_proxy 127.0.0.1:{config['deployment']['apiPort']}\n"
        f"}}\n"
    )


def write_systemd_unit(config: dict, paths: dict) -> None:
    service_text = f"""[Unit]
Description=AuthOS standalone service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User={AUTHOS_USER}
Group={AUTHOS_USER}
WorkingDirectory={paths['data_dir']}
EnvironmentFile={ENV_PATH}
ExecStart={INSTALL_BINARY}
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ReadWritePaths={paths['data_dir']}
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
"""
    SERVICE_PATH.write_text(service_text, encoding="utf-8")


def install_apply_wrapper() -> None:
    wrapper = f"""#!/usr/bin/env bash
set -euo pipefail
exec python3 {INSTALL_ROOT / 'standalone' / 'authos_standalone.py'} "$@"
"""
    APPLY_WRAPPER.write_text(wrapper, encoding="utf-8")
    os.chmod(APPLY_WRAPPER, 0o755)


def write_apply_service_unit(paths: dict) -> None:
    service_text = f"""[Unit]
Description=AuthOS standalone apply worker

[Service]
Type=oneshot
ExecStart={APPLY_WRAPPER} apply --bundle-dir {INSTALL_ROOT} --no-print-link
"""
    APPLY_SERVICE_PATH.write_text(service_text, encoding="utf-8")


def write_apply_path_unit(paths: dict) -> None:
    path_text = f"""[Unit]
Description=Watch AuthOS apply requests

[Path]
PathModified={paths['request_path']}

[Install]
WantedBy=multi-user.target
"""
    APPLY_PATH_UNIT_PATH.write_text(path_text, encoding="utf-8")


def copy_bundle(bundle_dir: Path) -> None:
    ensure_dir(INSTALL_ROOT, mode=0o755)
    ensure_dir(INSTALL_ROOT / "standalone", mode=0o755)

    shutil.copy2(bundle_dir / "authos", INSTALL_BINARY)
    os.chmod(INSTALL_BINARY, 0o755)
    shutil.copy2(bundle_dir / "authos.config.example.json", INSTALL_ROOT / "authos.config.example.json")
    shutil.copy2(bundle_dir / "standalone" / "authos_standalone.py", INSTALL_ROOT / "standalone" / "authos_standalone.py")
    os.chmod(INSTALL_ROOT / "standalone" / "authos_standalone.py", 0o755)


def managed_data_dir() -> Path:
    raw_value = load_install_state().get("dataDir", "/var/lib/authos")
    data_dir = Path(str(raw_value).strip() or "/var/lib/authos")
    if not data_dir.is_absolute():
        raise RuntimeError("standalone.dataDir must be an absolute path")
    return data_dir


def load_install_state() -> dict:
    if not INSTALL_STATE_PATH.exists():
        return {"dataDir": "/var/lib/authos", "allowCaddyInstall": False}

    try:
        payload = load_json(INSTALL_STATE_PATH, {})
    except Exception:
        return {"dataDir": "/var/lib/authos", "allowCaddyInstall": False}

    if not isinstance(payload, dict):
        return {"dataDir": "/var/lib/authos", "allowCaddyInstall": False}

    return {
        "dataDir": str(payload.get("dataDir") or "/var/lib/authos"),
        "allowCaddyInstall": bool(payload.get("allowCaddyInstall", False)),
    }


def configured_data_dir(config: dict) -> Path:
    raw_value = config.get("standalone", {}).get("dataDir", "/var/lib/authos")
    data_dir = Path(str(raw_value).strip() or "/var/lib/authos")
    if not data_dir.is_absolute():
        raise RuntimeError("standalone.dataDir must be an absolute path")
    return data_dir


def build_install_state(config: dict) -> dict:
    return {
        "dataDir": str(configured_data_dir(config)),
        "allowCaddyInstall": bool(config.get("caddy", {}).get("install", False)),
    }


def write_install_state(payload: dict) -> None:
    ensure_dir(CONFIG_DIR, mode=0o755)
    write_json(INSTALL_STATE_PATH, payload, mode=0o640)
    chown_path(INSTALL_STATE_PATH, "root", AUTHOS_USER)


def ensure_apply_request_file(paths: dict) -> None:
    if not paths["request_path"].exists():
        write_json(paths["request_path"], {"requested_at": None}, mode=0o640)


def relocate_managed_paths(current_paths: dict, desired_paths: dict) -> None:
    ensure_dir(desired_paths["data_dir"], mode=0o700)

    for key in ("config_path", "state_path", "status_path"):
        move_path(current_paths[key], desired_paths[key])

    if current_paths["sqlite_dir"] != desired_paths["sqlite_dir"]:
        move_path(current_paths["sqlite_dir"], desired_paths["sqlite_dir"])

    cleanup_empty_dir(current_paths["data_dir"])


def move_path(source: Path, destination: Path) -> None:
    if source == destination or not source.exists():
        return

    ensure_dir(destination.parent, mode=0o755)

    if source.is_dir():
        if not destination.exists():
            shutil.move(str(source), str(destination))
            return

        ensure_dir(destination, mode=0o700)
        for entry in source.iterdir():
            move_path(entry, destination / entry.name)
        cleanup_empty_dir(source)
        return

    if destination.exists():
        if destination.is_dir():
            raise RuntimeError(f"Cannot replace directory with file: {destination}")
        destination.unlink()
    shutil.move(str(source), str(destination))


def cleanup_empty_dir(path: Path) -> None:
    if not path.exists() or not path.is_dir():
        return

    try:
        next(path.iterdir())
        return
    except StopIteration:
        path.rmdir()
    except OSError:
        return


def bootstrap_login_url(config: dict, state: dict) -> str:
    bootstrap = state.get("bootstrap_login") or {}
    token = bootstrap.get("token")
    if not token or bootstrap.get("used_at"):
        return ""
    return f"{config['deployment']['platformBaseUrl']}/bootstrap-login#token={quote(token)}"


def load_json(path: Path, default=None):
    if not path.exists():
        if default is not None:
            return default
        raise RuntimeError(f"Missing required file: {path}")
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: Path, value, mode: int) -> None:
    ensure_dir(path.parent, mode=0o755)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    os.chmod(path, mode)


def write_env(path: Path, values: dict, mode: int) -> None:
    lines = ["# Generated by AuthOS standalone apply. Edit config.json and rerun authos-apply instead."]
    for key in sorted(values.keys()):
        value = str(values[key])
        lines.append(f"{key}={quote_env(value)}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.chmod(path, mode)


def quote_env(value: str) -> str:
    if value == "":
        return ""
    if re.fullmatch(r"[A-Za-z0-9_./:@%+=,-]+", value):
        return value
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def detect_primary_ip() -> str:
    try:
        output = subprocess.check_output(["hostname", "-I"], text=True).strip().split()
        for candidate in output:
            if candidate and not candidate.startswith("127.") and ":" not in candidate:
                return candidate
    except Exception:
        pass

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip_address = sock.getsockname()[0]
        sock.close()
        if ip_address:
            return ip_address
    except Exception:
        pass

    return "127.0.0.1"


def wait_for_systemd(service_name: str) -> None:
    deadline = datetime.now(timezone.utc) + timedelta(seconds=90)
    while datetime.now(timezone.utc) < deadline:
        result = subprocess.run(["systemctl", "is-active", service_name], capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip() == "active":
            return
        time_sleep(2)
    raise RuntimeError(f"Timed out waiting for {service_name} to become active")


def run(cmd: list[str], check: bool = True) -> None:
    result = subprocess.run(cmd, text=True)
    if check and result.returncode != 0:
        raise RuntimeError(f"Command failed ({result.returncode}): {' '.join(cmd)}")


def ensure_system_user() -> None:
    if subprocess.run(["id", "-u", AUTHOS_USER], capture_output=True).returncode == 0:
        return
    run(["useradd", "--system", "--create-home", "--home-dir", "/var/lib/authos", "--shell", "/usr/sbin/nologin", AUTHOS_USER])


def stop_existing_service() -> None:
    if shutil.which("systemctl") is None:
        return
    result = subprocess.run(
        ["systemctl", "list-unit-files", "authos.service", "--no-legend"],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0 and "authos.service" in result.stdout:
        run(["systemctl", "stop", "authos.service"], check=False)


def require_root() -> None:
    if os.geteuid() != 0:
        raise RuntimeError("This command must run as root")


def ensure_dir(path: Path, mode: int) -> None:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, mode)


def chown_path(path: Path, user: str, group: str) -> None:
    if not path.exists():
        return
    shutil.chown(path, user=user, group=group)


def add_if(target: dict, key: str, value) -> None:
    if value is None:
        return
    text = str(value).strip()
    if text:
        target[key] = text


def write_status(path: Path, payload: dict) -> None:
    ensure_dir(path.parent, mode=0o755)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    try:
        chown_path(path, AUTHOS_USER, AUTHOS_USER)
        os.chmod(path, 0o640)
    except Exception:
        pass


def write_failure_status(message: str) -> None:
    paths = managed_paths()
    try:
        write_status(paths["status_path"], {
            "status": "error",
            "message": message,
            "updated_at": now_rfc3339(),
        })
    except Exception:
        pass


def now_rfc3339() -> str:
    return datetime.now(timezone.utc).isoformat()


def remove_legacy_sudoers() -> None:
    legacy_path = Path("/etc/sudoers.d/authos-apply")
    if legacy_path.exists():
        legacy_path.unlink()


def time_sleep(seconds: int) -> None:
    import time

    time.sleep(seconds)


if __name__ == "__main__":
    raise SystemExit(main())
