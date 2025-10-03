import re
from typing import Tuple
from docker.errors import NotFound


def categorize_path(path: str) -> str:
    if path.startswith('/etc/'):
        return 'config'
    if path.startswith('/usr/share/man/') or path.startswith('/usr/share/doc/') or path.startswith('/usr/share/info/') or path.startswith('/usr/share/locale/'):
        return 'docs'
    if path.startswith('/var/cache/') or path.startswith('/var/log/') or path.startswith('/tmp/'):
        return 'cache'
    if path.startswith('/bin/') or path.startswith('/sbin/'):
        return 'system'
    if path.startswith('/usr/bin/') or path.startswith('/usr/sbin/') or path.startswith('/usr/lib/') or path.startswith('/lib/') or path.startswith('/lib64/'):
        return 'system'
    if path.startswith('/app/') or path.startswith('/opt/') or path.startswith('/srv/') or path.startswith('/var/www/') or path.startswith('/home/') or path.startswith('/workdir/'):
        return 'application'
    return 'other'


def removable_reason(path: str, accessed: bool) -> Tuple[bool, str]:
    if accessed:
        return False, ''
    if '/tests/' in path or path.endswith('/tests') or '/test/' in path or path.endswith('/test') or '/examples/' in path:
        return True, 'tests/examples not needed at runtime'
    if any(x in path for x in ['/usr/share/man/', '/usr/share/doc/', '/usr/share/info/', '/usr/share/locale/']):
        return True, 'documentation, not needed at runtime'
    if any(x in path for x in ['/var/cache/', '/var/log/', '/tmp/']):
        return True, 'cache/log/temp data, safe to remove'
    if any(x in path for x in ['/usr/include/', '/usr/src/']):
        return True, 'development headers/sources'
    if any(x in path for x in ['__pycache__', '.pyc', '.pyo', '.cache']):
        return True, 'bytecode/cache not needed at runtime'
    if re.search(r"\.a$|\.la$|\.o$|\.orig$|\.rej$", path):
        return True, 'build artifact not needed at runtime'
    return True, 'not accessed during runtime'


def keep_reason(path: str, accessed: bool) -> str:
    if accessed:
        return 'needed at runtime (accessed)'
    if path.startswith('/lib/') or path.startswith('/lib64/') or '/lib/' in path:
        return 'required for binaries (system library)'
    if path.startswith('/bin/') or path.startswith('/usr/bin/') or path.startswith('/sbin/'):
        return 'part of base system/commands'
    if path.startswith('/etc/'):
        return 'system config, needed by processes'
    if any(path.startswith(p) for p in ['/app/', '/opt/', '/srv/', '/var/www/']):
        return 'application artifact'
    return 'retained by policy'


def humanize_size(value: int) -> str:
    try:
        size = float(value)
    except Exception:
        return 'Unknown'
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    i = 0
    while size >= 1024 and i < len(units) - 1:
        size /= 1024
        i += 1
    return f"{size:.1f}{units[i]}"


def safe_remove_container(container) -> None:
    """Safely stop and remove a container, tolerating already-removed containers.
    - Stops if running
    - Removes with force
    - Ignores NotFound/404 and any benign cleanup errors
    """
    try:
        try:
            container.reload()
            state = container.attrs.get('State', {})
            if state.get('Running'):
                try:
                    container.stop(timeout=2)
                except Exception:
                    pass
        except Exception:
            pass
        try:
            container.remove(force=True)
        except NotFound:
            pass
        except Exception as e:
            # Best-effort cleanup: ignore errors that indicate it's already gone
            if '404' in str(e):
                return
    except Exception:
        pass


