import { execSync } from "child_process"
import { writeFileSync, unlinkSync, existsSync } from "fs"
import path from "path"
import os from "os"

export interface VulnerabilityFinding {
  id: string
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
  package: string
  version: string
  fixedVersion: string | null
  description: string
  cvssScore: number
}

export interface TrivyResult {
  critical: number
  high: number
  medium: number
  low: number
  total: number
  byPackage: Array<{ name: string; value: number }>
  findings: VulnerabilityFinding[]
  scanned_at: string
  isMockData: boolean
  scannerVersion?: string
}

export async function scanWithTrivy(fileBuffer: Buffer, imageName = "analysis-image"): Promise<TrivyResult> {
  const tempDir = path.join(os.tmpdir(), `docker-scan-${Date.now()}`)
  const tarPath = path.join(tempDir, `${imageName}.tar`)
  const resultPath = path.join(tempDir, "trivy-results.json")

  try {
    // Create temp directory if it doesn't exist
    if (!existsSync(tempDir)) {
      require("fs").mkdirSync(tempDir, { recursive: true })
    }

    // Write buffer to temp tar file
    writeFileSync(tarPath, fileBuffer)

    // Run Trivy scan - with fallback for environments without Trivy
    let results: TrivyResult

    try {
      // Check if Trivy is available
      let trivyVersion = ""
      try {
        trivyVersion = execSync("trivy --version", { encoding: "utf-8", stdio: "pipe" }).trim()
        console.log("[TRIVY] Trivy detected:", trivyVersion)
      } catch {
        console.warn("[TRIVY] Trivy not found - using mock vulnerability data")
        return generateMockTrivyResults(fileBuffer, true)
      }

      // Try to run Trivy if available
      const command = `trivy image --input "${tarPath}" --format json --output "${resultPath}"`
      console.log("[TRIVY] Running scan command:", command)
      
      execSync(command, { stdio: "pipe", timeout: 60000 })

      if (existsSync(resultPath)) {
        const fs = require("fs")
        const resultData = fs.readFileSync(resultPath, "utf-8")
        results = parseTrivyResults(resultData, trivyVersion)
        console.log("[TRIVY] Real scan complete - Found", results.total, "vulnerabilities")
      } else {
        console.warn("[TRIVY] No results file generated - using mock data")
        results = generateMockTrivyResults(fileBuffer, true)
      }
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : String(error)
      console.warn("[TRIVY] Scan failed:", errorMsg, "- using mock data")
      // If Trivy is not available, generate mock results
      results = generateMockTrivyResults(fileBuffer, true)
    }

    return results
  } finally {
    // Cleanup temp files
    try {
      if (existsSync(tarPath)) unlinkSync(tarPath)
      if (existsSync(resultPath)) unlinkSync(resultPath)
      if (existsSync(tempDir)) require("fs").rmSync(tempDir, { recursive: true })
    } catch {
      // Ignore cleanup errors
    }
  }
}

function parseTrivyResults(jsonData: string, trivyVersion = ""): TrivyResult {
  try {
    const data = JSON.parse(jsonData)
    const findings: VulnerabilityFinding[] = []
    let critical = 0,
      high = 0,
      medium = 0,
      low = 0

    // Parse Trivy JSON format
    if (data.Results) {
      data.Results.forEach((result: any) => {
        if (result.Vulnerabilities) {
          result.Vulnerabilities.forEach((vuln: any) => {
            const severity = vuln.Severity as "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
            switch (severity) {
              case "CRITICAL":
                critical++
                break
              case "HIGH":
                high++
                break
              case "MEDIUM":
                medium++
                break
              case "LOW":
                low++
                break
            }

            // Try multiple CVSS score sources with fallbacks
            const cvssScore = 
              vuln.CVSS?.nvd?.V3Score || 
              vuln.CVSS?.nvd?.V2Score || 
              vuln.CVSS?.redhat?.V3Score ||
              vuln.CVSS?.redhat?.V2Score ||
              0

            findings.push({
              id: vuln.VulnerabilityID,
              severity,
              package: vuln.PkgName,
              version: vuln.InstalledVersion,
              fixedVersion: vuln.FixedVersion,
              description: vuln.Title,
              cvssScore,
            })
          })
        }
      })
    }

    const total = critical + high + medium + low
    const byPackage = aggregateByPackage(findings)

    // Create a balanced sample of findings across all severity levels
    const criticalFindings = findings.filter(f => f.severity === "CRITICAL")
    const highFindings = findings.filter(f => f.severity === "HIGH")
    const mediumFindings = findings.filter(f => f.severity === "MEDIUM")
    const lowFindings = findings.filter(f => f.severity === "LOW")

    // Take proportional samples: all CRITICAL, 20 HIGH, 15 MEDIUM, 15 LOW
    const balancedFindings = [
      ...criticalFindings,
      ...highFindings.slice(0, 20),
      ...mediumFindings.slice(0, 15),
      ...lowFindings.slice(0, 15),
    ].slice(0, 100) // Cap at 100 total

    return {
      critical,
      high,
      medium,
      low,
      total,
      byPackage,
      findings: balancedFindings,
      scanned_at: new Date().toISOString(),
      isMockData: false,
      scannerVersion: trivyVersion,
    }
  } catch (error) {
    console.error("[TRIVY] Failed to parse results:", error)
    // If parsing fails, return mock results
    return generateMockTrivyResults(Buffer.alloc(0), true)
  }
}

function generateMockTrivyResults(buffer: Buffer, showWarning = false): TrivyResult {
  if (showWarning) {
    console.warn("[TRIVY] ⚠️  USING MOCK VULNERABILITY DATA - Install Trivy for real security scans")
  }
  
  // Generate realistic mock vulnerability data based on buffer size
  const bufferSize = buffer.length || 0
  const riskFactor = Math.min(10, Math.max(1, Math.floor(bufferSize / 10000000)))

  const critical = Math.floor(Math.random() * 3 * riskFactor)
  const high = Math.floor(Math.random() * 8 * riskFactor)
  const medium = Math.floor(Math.random() * 15 * riskFactor)
  const low = Math.floor(Math.random() * 25 * riskFactor)
  const total = critical + high + medium + low

  const commonPackages = [
    "openssl",
    "curl",
    "bash",
    "gcc",
    "zlib",
    "libssl",
    "libc",
    "npm",
    "python",
    "git",
    "openssh",
    "glibc",
  ]

  const findings: VulnerabilityFinding[] = []

  // Generate critical findings
  for (let i = 0; i < critical; i++) {
    findings.push(generateRandomFinding("CRITICAL", commonPackages))
  }

  // Generate high findings
  for (let i = 0; i < Math.min(high, 5); i++) {
    findings.push(generateRandomFinding("HIGH", commonPackages))
  }

  // Generate medium findings
  for (let i = 0; i < Math.min(medium, 10); i++) {
    findings.push(generateRandomFinding("MEDIUM", commonPackages))
  }

  // Generate low findings
  for (let i = 0; i < Math.min(low, 10); i++) {
    findings.push(generateRandomFinding("LOW", commonPackages))
  }

  const byPackage = aggregateByPackage(findings)

  return {
    critical,
    high,
    medium,
    low,
    total,
    byPackage,
    findings,
    scanned_at: new Date().toISOString(),
    isMockData: true,
    scannerVersion: "MOCK (Trivy not installed)",
  }
}

function generateRandomFinding(
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  packages: string[],
): VulnerabilityFinding {
  const pkg = packages[Math.floor(Math.random() * packages.length)]
  const year = 2022 + Math.floor(Math.random() * 3)
  const num = Math.floor(Math.random() * 50000)
  const cveId = `CVE-${year}-${String(num).padStart(5, "0")}`

  const descriptions: Record<string, string[]> = {
    CRITICAL: [
      "Remote code execution vulnerability",
      "Authentication bypass",
      "Privilege escalation",
      "SQL injection vulnerability",
    ],
    HIGH: [
      "Buffer overflow vulnerability",
      "Path traversal vulnerability",
      "Cross-site scripting vulnerability",
      "Denial of service vulnerability",
    ],
    MEDIUM: ["Information disclosure", "Weak cryptography", "Insecure deserialization", "Missing validation"],
    LOW: ["Deprecated functionality", "Weak randomness", "Improper error handling", "Missing security headers"],
  }

  const severityDescriptions = descriptions[severity]
  const description = severityDescriptions[Math.floor(Math.random() * severityDescriptions.length)]

  const scoreMap = {
    CRITICAL: 9.0 + Math.random(),
    HIGH: 7.0 + Math.random() * 2,
    MEDIUM: 4.0 + Math.random() * 3,
    LOW: 0 + Math.random() * 4,
  }

  return {
    id: cveId,
    severity,
    package: pkg,
    version: `${Math.floor(Math.random() * 3)}.${Math.floor(Math.random() * 20)}.${Math.floor(Math.random() * 20)}`,
    fixedVersion:
      Math.random() > 0.3 ? `${Math.floor(Math.random() * 3)}.${Math.floor(Math.random() * 20) + 20}.0` : null,
    description,
    cvssScore: Number.parseFloat(scoreMap[severity].toFixed(1)),
  }
}

function aggregateByPackage(findings: VulnerabilityFinding[]): Array<{ name: string; value: number }> {
  const packageMap = new Map<string, number>()

  findings.forEach((finding) => {
    const count = packageMap.get(finding.package) || 0
    packageMap.set(finding.package, count + 1)
  })

  return Array.from(packageMap.entries())
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value)
    .slice(0, 10)
}
