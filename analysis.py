import io
import tarfile
import time
from typing import Any, Dict, List, Tuple

import docker

from utils import categorize_path, removable_reason, keep_reason, humanize_size, safe_remove_container


class ImageAnalyzer:
    def __init__(self):
        self.client = docker.from_env()

    def _ensure_image(self, image: str):
        try:
            self.client.images.pull(image)
        except Exception:
            # image may already exist locally
            self.client.images.get(image)

    def _get_processes(self, container) -> List[Dict[str, Any]]:
        processes = []
        try:
            res = container.exec_run('ps aux')
            if res.exit_code == 0 and res.output:
                for line in res.output.decode('utf-8', errors='ignore').splitlines()[1:]:
                    parts = line.split(None, 10)
                    if len(parts) >= 11:
                        processes.append({
                            'pid': int(parts[1]) if parts[1].isdigit() else parts[1],
                            'cmd': parts[10]
                        })
        except Exception:
            pass
        return processes

    def _get_entrypoint_cmd(self, image: str) -> Tuple[List[str], List[str]]:
        try:
            img = self.client.images.get(image)
            config = img.attrs.get('Config', {})
            entrypoint = config.get('Entrypoint') or []
            cmd = config.get('Cmd') or []
            return entrypoint, cmd
        except Exception:
            return [], []

    def _try_install_strace(self, container) -> bool:
        if container.exec_run('which strace').exit_code == 0:
            return True
        if container.exec_run('which apt').exit_code == 0:
            container.exec_run('sh -lc "apt-get update && apt-get install -y strace"', user='root')
        elif container.exec_run('which apk').exit_code == 0:
            container.exec_run('sh -lc "apk add --no-cache strace"', user='root')
        elif container.exec_run('which yum').exit_code == 0:
            container.exec_run('sh -lc "yum install -y strace || true"', user='root')
        elif container.exec_run('which dnf').exit_code == 0:
            container.exec_run('sh -lc "dnf install -y strace || true"', user='root')
        return container.exec_run('which strace').exit_code == 0

    def _trace_accessed_files(self, container, duration: int) -> List[str]:
        paths: List[str] = []
        try:
            if not self._try_install_strace(container):
                return []
            log_path = f"/tmp/strace_{int(time.time())}.log"
            container.exec_run(f"sh -lc 'strace -f -e trace=file -o {log_path} -p 1 & sleep {duration}; kill %1 2>/dev/null || true'", detach=False)
            bits, _ = container.get_archive(log_path)
            file_like = io.BytesIO(b"".join(chunk for chunk in bits))
            with tarfile.open(fileobj=file_like) as tar:
                member = tar.getmembers()[0]
                extracted = tar.extractfile(member)
                content = extracted.read().decode('utf-8', errors='ignore') if extracted else ''
            for line in content.splitlines():
                if any(tok in line for tok in ['open(', 'openat(', 'stat(']):
                    parts = line.split('"')
                    if len(parts) > 1:
                        p = parts[1]
                        if p.startswith('/') and not any(skip in p for skip in ['/proc/', '/sys/', '/dev/']):
                            paths.append(p)
        except Exception:
            return []
        return list(dict.fromkeys(paths))

    def _discover_all_files(self, container) -> List[str]:
        candidates: List[str] = []
        cmds = [
            "find / -xdev -type f -not -path '/proc/*' -not -path '/sys/*' -not -path '/dev/*' 2>/dev/null | head -30000",
            "find /usr /bin /sbin /lib /lib64 /etc /opt /var -type f 2>/dev/null | head -30000",
            "find / -type f 2>/dev/null | head -30000"
        ]
        for cmd in cmds:
            try:
                res = container.exec_run(cmd)
                if res.exit_code == 0 and res.output:
                    paths = [p.strip() for p in res.output.decode('utf-8', errors='ignore').splitlines() if p.strip()]
                    if paths:
                        candidates = paths
                        break
            except Exception:
                continue
        if not candidates:
            try:
                res = container.exec_run("sh -lc \"find / -xdev -type f -not -path '/proc/*' -not -path '/sys/*' -not -path '/dev/*' 2>/dev/null\"")
                if res.exit_code == 0 and res.output:
                    candidates = [p.strip() for p in res.output.decode('utf-8', errors='ignore').splitlines() if p.strip()]
            except Exception:
                pass
        if not candidates:
            try:
                res = container.exec_run("sh -lc 'ls -lRa / 2>/dev/null | awk \"$1 ~ /^[^-]/ {next} {print \\ $9}\"'")
                if res.exit_code == 0 and res.output:
                    lines = [p.strip() for p in res.output.decode('utf-8', errors='ignore').splitlines() if p.strip()]
                    candidates = [p for p in lines if p.startswith('/')]
            except Exception:
                pass
        return candidates

    def _file_size(self, container, path: str) -> int:
        try:
            res = container.exec_run(f"stat -c %s '{path}' 2>/dev/null")
            if res.exit_code == 0 and res.output:
                return int(res.output.decode().strip())
        except Exception:
            pass
        return 0

    def _start_alive_container(self, image: str):
        """Start container and keep it alive for the analysis window."""
        # Prefer a simple sleep to keep the process tree minimal
        try_cmds = [
            "sh -lc 'sleep 60'",
            "sleep 60",
            "tail -f /dev/null"
        ]
        last_err = None
        for cmd in try_cmds:
            try:
                return self.client.containers.run(
                    image,
                    command=cmd,
                    detach=True,
                    tty=True,
                    remove=False,
                    cap_add=['SYS_PTRACE'],
                    security_opt=['apparmor=unconfined', 'seccomp=unconfined']
                )
            except Exception as e:
                last_err = e
                continue
        # Fallback to /bin/sh if all else fails
        return self.client.containers.run(
            image,
            command='/bin/sh',
            detach=True,
            tty=True,
            remove=False,
            cap_add=['SYS_PTRACE'],
            security_opt=['apparmor=unconfined', 'seccomp=unconfined']
        )

    def _discover_with_sizes(self, container) -> List[Tuple[str, int]]:
        """Discover files and sizes using GNU find -printf when available; fallback otherwise."""
        pairs: List[Tuple[str, int]] = []
        # First attempt: GNU find with -printf for efficiency
        find_cmds = [
            "sh -lc \"find / -xdev -type f -not -path '/proc/*' -not -path '/sys/*' -not -path '/dev/*' -printf '%s %p\\n' 2>/dev/null\"",
            "sh -lc \"find /usr /bin /sbin /lib /lib64 /etc /opt /var -type f -printf '%s %p\\n' 2>/dev/null\""
        ]
        for cmd in find_cmds:
            try:
                res = container.exec_run(cmd)
                if res.exit_code == 0 and res.output:
                    lines = [ln for ln in res.output.decode('utf-8', errors='ignore').splitlines() if ln.strip()]
                    # Validate format "<size> <path>"
                    ok = 0
                    for ln in lines:
                        try:
                            size_str, path = ln.split(' ', 1)
                            size = int(size_str)
                            if path.startswith('/'):
                                pairs.append((path, size))
                                ok += 1
                        except Exception:
                            # not gnufind; bail out and fallback
                            ok = 0
                            pairs = []
                            break
                    if ok > 0:
                        return pairs
            except Exception:
                continue

        # Fallback: discover paths, then stat sizes individually
        paths = self._discover_all_files(container)
        if not paths:
            return []
        for p in paths:
            try:
                res = container.exec_run(f"stat -c %s '{p}' 2>/dev/null")
                if res.exit_code == 0 and res.output:
                    pairs.append((p, int(res.output.decode().strip())))
                else:
                    pairs.append((p, 0))
            except Exception:
                pairs.append((p, 0))
        return pairs

    def analyze(self, image: str, duration: int = 10) -> Dict[str, Any]:
        self._ensure_image(image)
        container = self._start_alive_container(image)
        try:
            processes = self._get_processes(container)
            entrypoint, cmd = self._get_entrypoint_cmd(image)
            accessed = set(self._trace_accessed_files(container, duration))

            pairs = self._discover_with_sizes(container)
            if not pairs:
                # Last resort: at least return accessed with zero sizes
                pairs = [(p, 0) for p in accessed]

            total_files = len(pairs)
            per_category_size = {'system': 0, 'application': 0, 'config': 0, 'docs': 0, 'cache': 0, 'other': 0}
            removable: List[Dict[str, Any]] = []
            kept: List[Dict[str, Any]] = []

            total_size_bytes = 0
            for p, size in pairs:
                total_size_bytes += size
                cat = categorize_path(p)
                per_category_size[cat] = per_category_size.get(cat, 0) + size
                is_removable, reason = removable_reason(p, p in accessed)
                if is_removable and reason:
                    removable.append({'file': p, 'reason': reason, 'size': size, 'category': cat})
                else:
                    kept.append({'file': p, 'reason': keep_reason(p, p in accessed), 'size': size, 'category': cat})

            estimated_reduction = '0%'
            if total_files > 0:
                estimated_reduction = f"{(len(removable) / total_files) * 100:.0f}%"

            optimization_suggestions = [
                'Use multi-stage builds to avoid shipping build tools',
                "Add 'apt-get clean && rm -rf /var/lib/apt/lists/*' after installs",
                'Remove documentation, locales, and man pages in final image',
                'Clear package caches (apk, apt, yum, dnf) during build'
            ]

            return {
                'total_files': total_files,
                'total_size': humanize_size(total_size_bytes),
                'running_processes': processes,
                'entrypoint': entrypoint,
                'cmd': cmd,
                'files': {
                    'removable': [{'file': f['file'], 'reason': f['reason']} for f in removable[:2000]],
                    'kept': [{'file': f['file'], 'reason': f['reason']} for f in kept[:2000]]
                },
                'optimization_suggestions': optimization_suggestions,
                'estimated_reduction': estimated_reduction,
                'breakdown': {
                    'system': per_category_size['system'],
                    'config': per_category_size['config'],
                    'application': per_category_size['application'],
                    'docs': per_category_size['docs'],
                    'cache': per_category_size['cache'],
                    'other': per_category_size['other']
                },
                'accessed_files': sorted(list(accessed))[:2000]
            }
        finally:
            safe_remove_container(container)


