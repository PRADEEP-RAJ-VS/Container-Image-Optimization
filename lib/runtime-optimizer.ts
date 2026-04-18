/**
 * Runtime Optimizer - Cleans up unnecessary files while container is running
 * This reduces memory footprint and disk usage during execution
 */

import { execSync } from "child_process"
import * as fs from "fs"
import * as path from "path"

const PROTECTED_PATH_PREFIXES = ["/tmp/docker-optimizer-sessions"]

function isProtectedPath(targetPath: string): boolean {
  return PROTECTED_PATH_PREFIXES.some(
    (prefix) => targetPath === prefix || targetPath.startsWith(`${prefix}/`),
  )
}

interface RuntimeOptimizationOptions {
  interval?: number // ms between cleanup cycles (default: 5 minutes)
  aggressive?: boolean // remove more files at the cost of potential functionality
  dryRun?: boolean // log what would be deleted without deleting
}

/**
 * Start runtime optimization - runs cleanup periodically
 */
export function startRuntimeOptimizer(options: RuntimeOptimizationOptions = {}) {
  const { interval = 5 * 60 * 1000, aggressive = false, dryRun = false } = options

  console.log(`[RUNTIME-OPTIMIZER] Starting with interval: ${interval}ms, aggressive: ${aggressive}`)

  // Initial cleanup
  performCleanup(aggressive, dryRun)

  // Schedule periodic cleanup
  setInterval(() => {
    performCleanup(aggressive, dryRun)
  }, interval)
}

/**
 * Perform actual cleanup operations
 */
function performCleanup(aggressive: boolean, dryRun: boolean = false) {
  const cleanupTasks = [
    // Always safe to remove
    { name: "Package manager caches", fn: () => cleanPackageCaches(dryRun) },
    { name: "Temporary files", fn: () => cleanTempFiles(dryRun) },
    { name: "Log files", fn: () => cleanLogs(dryRun) },

    // Safe for most applications
    { name: "Python caches", fn: () => cleanPythonCache(dryRun) },
    { name: "Node caches", fn: () => cleanNodeCache(dryRun) },
    { name: "Locale files", fn: () => cleanLocales(dryRun) },

    // Aggressive - only if specified
    ...(aggressive ? [{ name: "Documentation", fn: () => cleanDocs(dryRun) }] : []),
  ]

  console.log(`[RUNTIME-OPTIMIZER] Starting cleanup cycle at ${new Date().toISOString()}`)

  let totalRemoved = 0
  for (const task of cleanupTasks) {
    try {
      const removed = task.fn()
      totalRemoved += removed
      console.log(`[RUNTIME-OPTIMIZER] ${task.name}: ${removed} bytes freed`)
    } catch (error) {
      console.error(`[RUNTIME-OPTIMIZER] Error during ${task.name}:`, error instanceof Error ? error.message : error)
    }
  }

  console.log(`[RUNTIME-OPTIMIZER] Total freed: ${(totalRemoved / 1024 / 1024).toFixed(2)} MB`)
}

/**
 * Clean package manager caches
 */
function cleanPackageCaches(dryRun: boolean): number {
  let freed = 0

  const cachePaths = [
    "/var/cache/apt",
    "/var/lib/apt/lists",
    "/var/cache/apk",
    "/var/cache/yum",
    "/var/cache/dnf",
    "/var/cache/pacman",
  ]

  for (const cachePath of cachePaths) {
    freed += cleanDirectory(cachePath, dryRun)
  }

  return freed
}

/**
 * Clean temporary files
 */
function cleanTempFiles(dryRun: boolean): number {
  let freed = 0

  const tempPaths = ["/tmp", "/var/tmp", "/dev/shm"]

  for (const tempPath of tempPaths) {
    freed += cleanDirectory(tempPath, dryRun, 3600000) // Keep files modified in last hour
  }

  return freed
}

/**
 * Clean log files
 */
function cleanLogs(dryRun: boolean): number {
  let freed = 0

  const logPaths = ["/var/log", "/root/.pm2/logs"]

  for (const logPath of logPaths) {
    freed += cleanDirectory(logPath, dryRun, 86400000) // Keep logs from last 24 hours
  }

  return freed
}

/**
 * Clean Python cache files
 */
function cleanPythonCache(dryRun: boolean): number {
  let freed = 0

  try {
    const result = execSync('find / -type d -name __pycache__ 2>/dev/null | head -100', {
      encoding: "utf-8",
    })
    const dirs = result.split("\n").filter((d) => d)

    for (const dir of dirs) {
      freed += removeRecursive(dir, dryRun)
    }
  } catch {
    // find might not be available
  }

  return freed
}

/**
 * Clean Node.js cache
 */
function cleanNodeCache(dryRun: boolean): number {
  let freed = 0

  const nodeCachePaths = ["/root/.npm", "/root/.cache/npm", "/home/*/.npm"]

  for (const cachePath of nodeCachePaths) {
    freed += cleanDirectory(cachePath, dryRun)
  }

  return freed
}

/**
 * Clean locale and i18n files
 */
function cleanLocales(dryRun: boolean): number {
  let freed = 0

  const localePaths = ["/usr/share/locale", "/usr/share/i18n"]

  for (const localePath of localePaths) {
    freed += cleanDirectory(localePath, dryRun)
  }

  return freed
}

/**
 * Clean documentation files
 */
function cleanDocs(dryRun: boolean): number {
  let freed = 0

  const docPaths = ["/usr/share/doc", "/usr/share/man", "/usr/local/share/doc"]

  for (const docPath of docPaths) {
    freed += cleanDirectory(docPath, dryRun)
  }

  return freed
}

/**
 * Clean a directory, optionally preserving recent files
 */
function cleanDirectory(dirPath: string, dryRun: boolean, maxAgeMiliseconds?: number): number {
  if (isProtectedPath(dirPath)) {
    return 0
  }

  if (!fs.existsSync(dirPath)) {
    return 0
  }

  let freed = 0
  const now = Date.now()

  try {
    const files = fs.readdirSync(dirPath)

    for (const file of files) {
      const filePath = path.join(dirPath, file)

      try {
        const stat = fs.statSync(filePath)

        if (isProtectedPath(filePath)) {
          continue
        }

        const age = now - stat.mtimeMs

        // Skip if file is too recent
        if (maxAgeMiliseconds && age < maxAgeMiliseconds) {
          continue
        }

        if (stat.isDirectory()) {
          freed += removeRecursive(filePath, dryRun)
        } else {
          if (!dryRun) {
            fs.unlinkSync(filePath)
          }
          freed += stat.size
        }
      } catch {
        // Skip files we can't access
      }
    }
  } catch {
    // Directory doesn't exist or can't be read
  }

  return freed
}

/**
 * Recursively remove a directory
 */
function removeRecursive(dirPath: string, dryRun: boolean): number {
  if (isProtectedPath(dirPath)) {
    return 0
  }

  if (!fs.existsSync(dirPath)) {
    return 0
  }

  let freed = 0

  try {
    const stat = fs.statSync(dirPath)

    if (stat.isDirectory()) {
      const files = fs.readdirSync(dirPath)

      for (const file of files) {
        freed += removeRecursive(path.join(dirPath, file), dryRun)
      }

      if (!dryRun) {
        fs.rmdirSync(dirPath)
      }
      freed += 4096 // Approximate directory size
    } else {
      if (!dryRun) {
        fs.unlinkSync(dirPath)
      }
      freed += stat.size
    }
  } catch {
    // Skip files we can't delete
  }

  return freed
}

/**
 * Get current memory/disk usage stats
 */
export function getOptimizationStats() {
  try {
    const df = execSync("df -h / 2>/dev/null || true", { encoding: "utf-8" })
    const du = execSync("du -sh / 2>/dev/null || true", { encoding: "utf-8" })
    const free = execSync("free -h 2>/dev/null || true", { encoding: "utf-8" })

    return {
      timestamp: new Date().toISOString(),
      diskUsage: du.trim(),
      diskAvailable: df.trim(),
      memory: free.trim(),
    }
  } catch {
    return { error: "Could not retrieve stats" }
  }
}
