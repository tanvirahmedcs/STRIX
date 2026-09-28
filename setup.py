#!/usr/bin/env python3
"""
STRIX auto-installer — one file, everything.

  python3 setup.py            # full interactive install
  python3 setup.py --yes      # non-interactive (uses env vars / skips blanks)
  python3 setup.py --no-go    # skip Go tooling (faster; recon tools added later)
  python3 setup.py --uninstall

Installs: system pkgs -> Go recon/scanner tools -> Python deps -> ~/.strix/.env
-> global `strix` launcher in ~/.local/bin -> verification.
After this you can run `strix -d example.com` from any directory.
"""
from __future__ import annotations

import argparse
import os
import platform
import shutil
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# ------------------------------------------------------------------ styling
if sys.stdout.isatty():
    B, G, C, Y, R, X = "\033[1m", "\033[32m", "\033[36m", "\033[33m", "\033[31m", "\033[0m"
else:
    B = G = C = Y = R = X = ""

def say(m):  print(f"{C}  ▸{X} {m}")
def ok(m):   print(f"{G}  ✔{X} {m}")
def warn(m): print(f"{Y}  ▲{X} {m}")
def die(m):  print(f"{R}  ✘{X} {m}"); sys.exit(1)

LOGO = r"""
   ███████╗████████╗██████╗ ██╗██╗  ██╗
   ██╔════╝╚══██╔══╝██╔══██╗██║╚██╗██╔╝
   ███████╗   ██║   ██████╔╝██║ ╚███╔╝
   ╚════██║   ██║   ██╔══██╗██║ ██╔██╗
   ███████║   ██║   ██║  ██║██║██╔╝ ██╗
   ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝
"""

HOME = Path.home()
STRIX_HOME = HOME / ".strix"
BIN_DIR = HOME / ".local" / "bin"
ENV_FILE = STRIX_HOME / ".env"
APP_DIR = STRIX_HOME / "app"
SRC_DIR = Path(__file__).resolve().parent
STRIX_PY = SRC_DIR / "strix.py"

GO_TOOLS = [
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "github.com/projectdiscovery/katana/cmd/katana@latest",
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest",
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    "github.com/tomnomnom/assetfinder@latest",
    "github.com/tomnomnom/anew@latest",
    "github.com/tomnomnom/gf@latest",
    "github.com/tomnomnom/unfurl@latest",
    "github.com/tomnomnom/waybackurls@latest",
    "github.com/lc/gau/v2/cmd/gau@latest",
    "github.com/ffuf/ffuf/v2@latest",
    "github.com/hakluke/hakrawler@latest",
    "github.com/BishopFox/jsluice/cmd/jsluice@latest",
]
PY_DEPS = ["httpx", "openai", "python-dotenv", "rich", "ollama"]


# ------------------------------------------------------------------ helpers
def run(cmd, check=False, quiet=True, env=None, timeout=None):
    """Run a command; return (rc, stdout+stderr). Never raises unless check."""
    try:
        p = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, env=env, timeout=timeout,
        )
        out = p.stdout or ""
        if p.returncode != 0 and check and not quiet:
            print(out)
        return p.returncode, out
    except FileNotFoundError:
        return 127, f"not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, f"timeout: {cmd[0]}"
    except Exception as e:  # noqa: BLE001
        return 1, str(e)

def have(tool): return shutil.which(tool) is not None
def is_wsl(): return "microsoft" in platform.uname().release.lower()
def is_root(): return os.geteuid() == 0


# ------------------------------------------------------------------ 1. system packages
def install_system():
    say("System packages")
    if shutil.which("apt-get"):
        sudo = [] if is_root() else (["sudo"] if have("sudo") else None)
        if sudo is None:
            warn("no sudo — skipping system packages"); return
        run(sudo + ["apt-get", "update", "-qq"], timeout=600)
        rc, _ = run(sudo + ["apt-get", "install", "-y", "-qq",
                            "curl", "git", "jq", "python3", "python3-pip",
                            "python3-venv", "golang-go", "chromium"], timeout=1800)
        ok("apt packages installed") if rc == 0 else warn("some apt packages failed (non-fatal)")
    elif shutil.which("brew"):
        for p in ("curl", "git", "jq", "go", "chromium"):
            if not have(p):
                run(["brew", "install", p], timeout=1800)
        ok("brew packages installed")
    else:
        warn("no apt/brew — install curl, git, jq, go, chromium manually")


# ------------------------------------------------------------------ 2. PATH / shell
def configure_path():
    say("Shell PATH")
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    STRIX_HOME.mkdir(parents=True, exist_ok=True)
    block = (
        f'\nexport PATH="$HOME/.local/bin:$PATH"\n'
        f'export STRIX_HOME="{STRIX_HOME}"\n'
        f'[ -f "{ENV_FILE}" ] && set -a && . "{ENV_FILE}" && set +a\n'
    )
    for rc in (HOME / ".bashrc", HOME / ".zshrc"):
        if not rc.exists():
            continue
        txt = rc.read_text(errors="ignore")
        if "STRIX_HOME" not in txt:
            with rc.open("a") as f:
                f.write(block)
    ok("PATH + auto-load configured (relaunch shell to activate)")


# ------------------------------------------------------------------ 3. Go tools
def install_go_tools(no_go=False):
    if no_go:
        warn("--no-go: skipping recon/scanner tooling"); return
    if not have("go"):
        warn("Go not installed — skipping. Install Go then re-run: python3 setup.py")
        return
    say("Go recon/scanner tools (this takes a few minutes)")
    env = dict(os.environ, GOBIN=str(BIN_DIR), PATH=f"{BIN_DIR}:{os.environ.get('PATH','')}")
    for t in GO_TOOLS:
        name = t.split("/")[-1].split("@")[0]
        rc, _ = run(["go", "install", t], env=env, timeout=1200)
        ok(name) if rc == 0 else warn(f"failed: {name}")
    if have("nuclei"):
        run(["nuclei", "-update-templates", "-silent"], timeout=600)
        if have("nuclei"):
            ok("nuclei templates updated")


# ------------------------------------------------------------------ 4. Python deps
def install_python_deps():
    say("Python dependencies")
    # try plain, then --break-system-packages, else venv
    for args in (
        [sys.executable, "-m", "pip", "install", "-q", "--upgrade", *PY_DEPS],
        [sys.executable, "-m", "pip", "install", "-q", "--break-system-packages", "--upgrade", *PY_DEPS],
    ):
        rc, _ = run(args, timeout=900)
        if rc == 0:
            ok("python deps installed")
            return None
    warn("global pip blocked — creating isolated venv")
    venv = STRIX_HOME / "venv"
    run([sys.executable, "-m", "venv", str(venv)], timeout=300)
    py = venv / "bin" / "python"
    rc, _ = run([str(py), "-m", "pip", "install", "-q", "--upgrade", *PY_DEPS], timeout=900)
    ok("python deps installed into venv") if rc == 0 else die("python deps failed")
    return venv


# ------------------------------------------------------------------ 5. key capture
def ask(label, default=""):
    suffix = f" [{default}]" if default else " (blank = skip)"
    try:
        val = input(f"  {B}{label}{X}{suffix}: ").strip()
    except EOFError:
        val = ""
    return val or default

def interactive_keys(non_interactive=False, venv=None):
    print(f"\n{B}── Configuration ──{X}")
    cfg = {}
    env = dict(os.environ)

    def get(label, var, default=""):
        if non_interactive:
            return env.get(var, default)
        return ask(label, env.get(var, default))

    if non_interactive:
        say("non-interactive: reading keys from environment")
        cfg["OPENAI_API_KEY"] = env.get("OPENAI_API_KEY", "")
    else:
        print("  Paste each key and press Enter:\n")
        cfg["OPENAI_API_KEY"] = get("OpenAI API key    (required)", "OPENAI_API_KEY")
        if not cfg["OPENAI_API_KEY"]:
            warn("no OpenAI key — AI triage/report disabled (add later to ~/.strix/.env)")

    # local Ollama option
    backend = "openai"
    if not non_interactive and cfg["OPENAI_API_KEY"]:
        ans = ask("Use LOCAL Ollama instead of OpenAI? (y/N)", "n").lower()
        if ans.startswith("y"):
            backend = "ollama"
    elif non_interactive and env.get("STRIX_LLM_BACKEND") == "ollama":
        backend = "ollama"

    cfg["STRIX_LLM_BACKEND"] = backend
    cfg["STRIX_OLLAMA_MODEL"] = env.get("STRIX_OLLAMA_MODEL", "qwen2.5:14b")
    if backend == "ollama" and not non_interactive:
        cfg["STRIX_OLLAMA_MODEL"] = ask("Ollama model (e.g. qwen2.5:14b)", cfg["STRIX_OLLAMA_MODEL"])
        # try to pull it
        if have("ollama"):
            say(f"pulling Ollama model {cfg['STRIX_OLLAMA_MODEL']} (background-capable)")
            run(["ollama", "pull", cfg["STRIX_OLLAMA_MODEL"]], timeout=3600)

    cfg["NVD_API_KEY"] = get("NVD API key       (optional)", "NVD_API_KEY")
    cfg["URLSCAN_API_KEY"] = get("URLScan API key   (optional)", "URLSCAN_API_KEY")
    cfg["STRIX_OOB_SERVER"] = get("OOB server host   (optional)", "STRIX_OOB_SERVER")

    alert = get("Alert backend [none|ntfy|discord|gotify|email]", "STRIX_ALERT", "none")
    alert = alert if alert in ("none", "ntfy", "discord", "gotify", "email") else "none"
    cfg["STRIX_ALERT"] = alert
    cfg["NTFY_URL"] = cfg["DISCORD_WEBHOOK"] = cfg["GOTIFY_URL"] = ""
    cfg["GOTIFY_TOKEN"] = cfg["ALERT_EMAIL"] = ""
    if alert == "ntfy":    cfg["NTFY_URL"]        = get("ntfy topic URL", "NTFY_URL")
    elif alert == "discord": cfg["DISCORD_WEBHOOK"] = get("Discord webhook URL", "DISCORD_WEBHOOK")
    elif alert == "gotify":
        cfg["GOTIFY_URL"]   = get("Gotify URL", "GOTIFY_URL")
        cfg["GOTIFY_TOKEN"] = get("Gotify token", "GOTIFY_TOKEN")
    elif alert == "email":  cfg["ALERT_EMAIL"]     = get("Alert email address", "ALERT_EMAIL")

    return cfg


# ------------------------------------------------------------------ 6. write env
def write_env(cfg):
    if not STRIX_PY.exists():
        die(f"strix.py not found next to setup.py ({STRIX_PY})")
    STRIX_HOME.mkdir(parents=True, exist_ok=True)
    lines = [f"# STRIX config — generated {datetime.now(timezone.utc).isoformat()}"]
    default_keys = ["OPENAI_API_KEY", "NVD_API_KEY", "URLSCAN_API_KEY", "STRIX_OOB_SERVER",
                    "STRIX_LLM_BACKEND", "STRIX_OLLAMA_MODEL", "STRIX_ALERT",
                    "NTFY_URL", "DISCORD_WEBHOOK", "GOTIFY_URL", "GOTIFY_TOKEN", "ALERT_EMAIL"]
    for k in default_keys:
        lines.append(f'{k}="{cfg.get(k, "")}"')
    ENV_FILE.write_text("\n".join(lines) + "\n")
    ENV_FILE.chmod(stat.S_IRUSR | stat.S_IWUSR)   # 600
    ok(f"secrets written to {ENV_FILE} (mode 600)")


# ------------------------------------------------------------------ 7. app + launcher
def install_app(venv=None):
    say("Installing global 'strix' command")
    APP_DIR.mkdir(parents=True, exist_ok=True)
    shutil.copy2(STRIX_PY, APP_DIR / "strix.py")
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    launcher = BIN_DIR / "strix"
    py = f"{STRIX_HOME}/venv/bin/python" if venv else "python3"
    launcher.write_text(
        "#!/usr/bin/env bash\n"
        "# STRIX launcher — loads ~/.strix/.env, runs the app from anywhere.\n"
        "set -euo pipefail\n"
        'export STRIX_HOME="${STRIX_HOME:-$HOME/.strix}"\n'
        '[ -f "$STRIX_HOME/.env" ] && { set -a; . "$STRIX_HOME/.env"; set +a; }\n'
        f'PY="{py}"\n'
        '[ -x "$STRIX_HOME/venv/bin/python" ] && PY="$STRIX_HOME/venv/bin/python"\n'
        'exec "$PY" "$STRIX_HOME/app/strix.py" "$@"\n'
    )
    launcher.chmod(launcher.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    ok(f"installed {launcher}")


# ------------------------------------------------------------------ 8. verify
def verify():
    print()
    say("Verifying")
    for t in ("subfinder", "httpx", "katana", "nuclei", "gau", "ffuf", "jsluice", "jq"):
        (ok if have(t) else warn)(f"tool: {t}" + ("" if have(t) else "  (install later)"))
    # smoke-test the app
    rc, out = run([sys.executable, str(STRIX_PY), "--help"], timeout=60)
    ok("strix.py runs") if rc == 0 else warn("strix.py failed to run — check python deps")


# ------------------------------------------------------------------ 9. uninstall
def uninstall():
    say("Uninstalling STRIX")
    for p in (BIN_DIR / "strix",):
        if p.exists(): p.unlink(); ok(f"removed {p}")
    for p in (STRIX_HOME,):
        if p.exists():
            shutil.rmtree(p, ignore_errors=True); ok(f"removed {p}")
    for rc in (HOME / ".bashrc", HOME / ".zshrc"):
        if rc.exists():
            lines = rc.read_text(errors="ignore").splitlines(keepends=True)
            keep = [l for l in lines if "STRIX_HOME" not in l
                    and "(.local/bin)" not in l and "/.local/bin:$PATH" not in l]
            rc.write_text("".join(keep))
    ok("cleaned shell rc files")
    warn("state.db and reports in your working dirs were left untouched")


# ------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser(prog="setup.py", description="STRIX auto-installer")
    ap.add_argument("--yes", "-y", action="store_true", help="non-interactive (env vars)")
    ap.add_argument("--no-go", action="store_true", help="skip Go tooling")
    ap.add_argument("--uninstall", action="store_true")
    a = ap.parse_args()

    print(f"{C}{LOGO}{X}")
    print(f"  {B}STRIX v3 installer{X}{'  (WSL)' if is_wsl() else ''}\n")

    if a.uninstall:
        uninstall(); return

    if not STRIX_PY.exists():
        die("put setup.py in the same folder as strix.py")

    install_system()
    configure_path()
    install_go_tools(no_go=a.no_go)
    venv = install_python_deps()
    cfg = interactive_keys(non_interactive=a.yes, venv=venv)
    write_env(cfg)
    install_app(venv)
    verify()

    print(f"""
{G}{B}  ✔ STRIX installed{X}

  Command : {B}strix{X}
  Config  : {ENV_FILE}
  App     : {APP_DIR / 'strix.py'}

  {B}If 'strix' is not found, run:{X}
      export PATH="$HOME/.local/bin:$PATH"
      source ~/.bashrc        # or reopen your shell

  {B}Usage:{X}
      strix -d example.com          # full scan (default)
      strix init
      strix recon   -d example.com
      strix cve     -d example.com
      strix owasp   -d example.com
      strix validate -d example.com
      strix coverage -d example.com
      strix report  -d example.com -o ./out
      strix findings -d example.com -s confirmed
      strix alert-test
""")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n  interrupted"); sys.exit(130)
