from typing import Any, Dict, List


def generate_slimming_recommendations(result: Dict[str, Any]) -> List[str]:
    suggestions: List[str] = []
    files = result.get('files', {})
    removable = files.get('removable', [])
    breakdown = result.get('breakdown', {})

    if removable:
        suggestions.append('Remove documentation, locales, and man pages in final image')
    if breakdown.get('cache', 0) > 0:
        suggestions.append('Clear package caches during build (apt, yum/dnf, apk)')
    suggestions.append('Use multi-stage builds to avoid shipping build tools')
    suggestions.append("Run 'apt-get clean && rm -rf /var/lib/apt/lists/*' after installs")
    suggestions.append('Pin dependencies and remove dev/test packages in production')

    return suggestions


