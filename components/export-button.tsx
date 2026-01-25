"use client"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { Download, FileJson, FileText, Share2, Package } from "lucide-react"

interface ExportButtonProps {
  analysis: any
  fileName?: string
  sessionId?: string
  imageName?: string
  onOptimizationComplete?: (optimizedSessionId: string, stats: any) => void
}

export default function ExportButton({ analysis, fileName = "docker-analysis", sessionId, imageName, onOptimizationComplete }: ExportButtonProps) {
  const [isExporting, setIsExporting] = useState(false)
  const [isOptimizing, setIsOptimizing] = useState(false)

  const downloadFile = (content: string | Blob, type: string, ext: string) => {
    const blob = content instanceof Blob ? content : new Blob([content], { type })
    const url = window.URL.createObjectURL(blob)
    const link = document.createElement("a")
    link.href = url
    link.download = `${fileName}-${new Date().getTime()}.${ext}`
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    window.URL.revokeObjectURL(url)
  }

  const handleExportJSON = async () => {
    setIsExporting(true)
    try {
      const jsonData = JSON.stringify(analysis, null, 2)
      downloadFile(jsonData, "application/json", "json")
    } finally {
      setIsExporting(false)
    }
  }

  const handleExportHTML = async () => {
    setIsExporting(true)
    try {
      const html = generateHTMLReport(analysis)
      downloadFile(html, "text/html", "html")
    } finally {
      setIsExporting(false)
    }
  }

  const handleExportMarkdown = async () => {
    setIsExporting(true)
    try {
      const markdown = generateMarkdownReport(analysis)
      downloadFile(markdown, "text/markdown", "md")
    } finally {
      setIsExporting(false)
    }
  }

  const handleExportCSV = async () => {
    setIsExporting(true)
    try {
      const csv = generateCSVReport(analysis)
      downloadFile(csv, "text/csv", "csv")
    } finally {
      setIsExporting(false)
    }
  }

  const handleDownloadOptimizedImage = async () => {
    if (!sessionId || !imageName) {
      alert("Session expired. Please re-upload your image.")
      return
    }

    setIsOptimizing(true)
    setIsExporting(true)
    try {
      // Step 1: Optimize the image
      const optimizeResponse = await fetch("/api/optimize", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          sessionId,
          imageName,
          optimizations: {
            useMultiStage: true,
            useAlpineBase: true,
            consolidateRuns: true,
            removeCache: true,
          },
        }),
      })

      if (!optimizeResponse.ok) {
        const error = await optimizeResponse.json()
        throw new Error(error.error || "Optimization failed")
      }

      const optimizeData = await optimizeResponse.json()
      console.log("Optimization complete:", optimizeData)
      
      // Notify parent component about optimization
      if (onOptimizationComplete) {
        onOptimizationComplete(optimizeData.optimizedSessionId, {
          originalSize: optimizeData.originalSize,
          optimizedSize: optimizeData.optimizedSize,
          sizeSavings: optimizeData.sizeSavings,
          percentSavings: optimizeData.percentSavings,
        })
      }

      setIsOptimizing(false)

      // Step 2: Download the optimized image
      const downloadResponse = await fetch("/api/download-optimized", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          optimizedSessionId: optimizeData.optimizedSessionId,
          imageName,
        }),
      })

      if (!downloadResponse.ok) {
        const errorData = await downloadResponse.json()
        throw new Error(errorData.error || "Failed to download optimized image")
      }

      const blob = await downloadResponse.blob()
      downloadFile(blob, "application/x-tar", "tar")
    } catch (error) {
      console.error("Error:", error)
      alert(error instanceof Error ? error.message : "Unknown error")
    } finally {
      setIsOptimizing(false)
      setIsExporting(false)
    }
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="outline"
          size="sm"
          disabled={isExporting}
          className="bg-slate-800 border-slate-700 hover:bg-slate-700"
        >
          <Download className="w-4 h-4 mr-2" />
          {isExporting ? "Exporting..." : "Export"}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="bg-slate-800 border-slate-700">
        <DropdownMenuItem
          onClick={handleDownloadOptimizedImage}
          className="text-slate-300 focus:text-white focus:bg-slate-700 cursor-pointer"
          disabled={isOptimizing}
        >
          <Package className="w-4 h-4 mr-2" />
          {isOptimizing ? "Optimizing..." : "Download Optimized Image (TAR)"}
        </DropdownMenuItem>
        <div className="border-t border-slate-700 my-1"></div>
        <DropdownMenuItem
          onClick={handleExportJSON}
          className="text-slate-300 focus:text-white focus:bg-slate-700 cursor-pointer"
        >
          <FileJson className="w-4 h-4 mr-2" />
          Export as JSON
        </DropdownMenuItem>
        <DropdownMenuItem
          onClick={handleExportHTML}
          className="text-slate-300 focus:text-white focus:bg-slate-700 cursor-pointer"
        >
          <FileText className="w-4 h-4 mr-2" />
          Export as HTML Report
        </DropdownMenuItem>
        <DropdownMenuItem
          onClick={handleExportMarkdown}
          className="text-slate-300 focus:text-white focus:bg-slate-700 cursor-pointer"
        >
          <FileText className="w-4 h-4 mr-2" />
          Export as Markdown
        </DropdownMenuItem>
        <DropdownMenuItem
          onClick={handleExportCSV}
          className="text-slate-300 focus:text-white focus:bg-slate-700 cursor-pointer"
        >
          <Share2 className="w-4 h-4 mr-2" />
          Export Findings as CSV
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

function generateHTMLReport(analysis: any): string {
  const { vulnerabilities = {}, optimizationScore = {}, imageInfo = {}, scanMetadata = {} } = analysis

  const criticalCount = vulnerabilities.critical || 0
  const highCount = vulnerabilities.high || 0
  const mediumCount = vulnerabilities.medium || 0
  const lowCount = vulnerabilities.low || 0

  return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Docker Image Analysis Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif; background: #f5f5f5; color: #333; }
        .container { max-width: 1200px; margin: 0 auto; padding: 40px 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; border-radius: 8px; margin-bottom: 30px; }
        .header h1 { font-size: 32px; margin-bottom: 10px; }
        .header p { opacity: 0.9; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 30px 0; }
        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        .card h3 { color: #667eea; margin-bottom: 10px; font-size: 14px; text-transform: uppercase; }
        .card .value { font-size: 36px; font-weight: bold; color: #333; }
        .critical { color: #ef4444; }
        .high { color: #f97316; }
        .medium { color: #eab308; }
        .low { color: #84cc16; }
        .section { background: white; padding: 30px; border-radius: 8px; margin: 20px 0; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        .section h2 { color: #667eea; margin-bottom: 20px; font-size: 22px; border-bottom: 2px solid #f0f0f0; padding-bottom: 10px; }
        table { width: 100%; border-collapse: collapse; }
        th { background: #f5f5f5; padding: 12px; text-align: left; font-weight: 600; border-bottom: 2px solid #ddd; }
        td { padding: 12px; border-bottom: 1px solid #eee; }
        tr:hover { background: #f9f9f9; }
        .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }
        .badge-critical { background: #fee2e2; color: #991b1b; }
        .badge-high { background: #ffedd5; color: #92400e; }
        .badge-medium { background: #fef3c7; color: #92400e; }
        .badge-low { background: #dcfce7; color: #166534; }
        .metric { display: flex; justify-content: space-between; align-items: center; padding: 10px 0; border-bottom: 1px solid #eee; }
        .metric:last-child { border-bottom: none; }
        .metric-label { font-weight: 600; }
        .metric-value { color: #667eea; font-weight: bold; }
        code { background: #f5f5f5; padding: 2px 6px; border-radius: 3px; font-family: monospace; }
        .footer { text-align: center; margin-top: 40px; color: #999; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Docker Image Analysis Report</h1>
            <p>Comprehensive vulnerability and optimization analysis</p>
            <p style="margin-top: 10px; font-size: 14px;">Generated: ${new Date().toLocaleString()}</p>
        </div>

        <div class="grid">
            <div class="card">
                <h3>Total Vulnerabilities</h3>
                <div class="value">${vulnerabilities.total || 0}</div>
            </div>
            <div class="card">
                <h3>Optimization Score</h3>
                <div class="value">${optimizationScore.score || 0}/100</div>
            </div>
            <div class="card">
                <h3>Image Size</h3>
                <div class="value">${imageInfo.size || "N/A"}</div>
            </div>
            <div class="card">
                <h3>Total Layers</h3>
                <div class="value">${imageInfo.layers || 0}</div>
            </div>
        </div>

        <div class="section">
            <h2>Vulnerability Breakdown</h2>
            <div class="grid">
                <div class="card">
                    <h3>Critical</h3>
                    <div class="value critical">${criticalCount}</div>
                </div>
                <div class="card">
                    <h3>High</h3>
                    <div class="value high">${highCount}</div>
                </div>
                <div class="card">
                    <h3>Medium</h3>
                    <div class="value medium">${mediumCount}</div>
                </div>
                <div class="card">
                    <h3>Low</h3>
                    <div class="value low">${lowCount}</div>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>Image Information</h2>
            <div class="metric">
                <span class="metric-label">File Name</span>
                <span class="metric-value">${scanMetadata.imageFile || "N/A"}</span>
            </div>
            <div class="metric">
                <span class="metric-label">File Size</span>
                <span class="metric-value">${scanMetadata.fileSizeMB || "N/A"} MB</span>
            </div>
            <div class="metric">
                <span class="metric-label">Total Layers</span>
                <span class="metric-value">${imageInfo.layers || 0}</span>
            </div>
            <div class="metric">
                <span class="metric-label">Scanned At</span>
                <span class="metric-value">${new Date(scanMetadata.scannedAt).toLocaleString()}</span>
            </div>
        </div>

        <div class="section">
            <h2>Optimization Recommendations</h2>
            <p style="margin-bottom: 20px;">Potential Size Savings: <strong>${optimizationScore.percentSavings || "0"}%</strong></p>
            ${analysis.optimizationRecommendations
              ?.slice(0, 5)
              .map(
                (rec: any) => `
            <div style="margin-bottom: 20px; padding: 15px; background: #f9f9f9; border-left: 4px solid #667eea; border-radius: 4px;">
                <h4 style="margin-bottom: 8px; color: #667eea;">${rec.title}</h4>
                <p style="font-size: 14px; color: #666; margin-bottom: 8px;">${rec.description}</p>
                <span class="badge badge-${rec.impact.toLowerCase()}">${rec.impact} Impact</span>
                ${rec.estimatedSavings ? `<span style="margin-left: 10px; color: #667eea; font-weight: 600;">Est. Savings: ${rec.estimatedSavings}</span>` : ""}
            </div>
            `,
              )
              .join("")}
        </div>

        <div class="footer">
            <p>Docker Image Optimizer | Generated on ${new Date().toLocaleString()}</p>
        </div>
    </div>
</body>
</html>`
}

function generateMarkdownReport(analysis: any): string {
  const { vulnerabilities = {}, optimizationScore = {}, imageInfo = {}, scanMetadata = {} } = analysis

  const markdown = `# Docker Image Analysis Report

**Generated:** ${new Date().toLocaleString()}

## Executive Summary

- **Total Vulnerabilities:** ${vulnerabilities.total || 0}
- **Optimization Score:** ${optimizationScore.score || 0}/100
- **Image Size:** ${imageInfo.size || "N/A"}
- **Total Layers:** ${imageInfo.layers || 0}
- **Potential Savings:** ${optimizationScore.percentSavings || "0"}%

## Vulnerability Breakdown

| Severity | Count |
|----------|-------|
| Critical | ${vulnerabilities.critical || 0} |
| High | ${vulnerabilities.high || 0} |
| Medium | ${vulnerabilities.medium || 0} |
| Low | ${vulnerabilities.low || 0} |

## Image Information

- **File Name:** ${scanMetadata.imageFile || "N/A"}
- **File Size:** ${scanMetadata.fileSizeMB || "N/A"} MB
- **Layers:** ${imageInfo.layers || 0}
- **Scanned:** ${new Date(scanMetadata.scannedAt).toLocaleString()}

## Top Recommendations

${analysis.optimizationRecommendations
  ?.slice(0, 5)
  .map(
    (rec: any, idx: number) => `
### ${idx + 1}. ${rec.title}

**Impact:** ${rec.impact}  
**Description:** ${rec.description}

${rec.estimatedSavings ? `**Estimated Savings:** ${rec.estimatedSavings}` : ""}
${rec.dockerfile ? `\`\`\`dockerfile\n${rec.dockerfile}\n\`\`\`` : ""}
`,
  )
  .join("")}

---
*Report generated by Docker Image Optimizer*
`
  return markdown
}

function generateCSVReport(analysis: any): string {
  const findings = analysis.vulnerabilities?.findings || []
  let csv = "ID,Severity,Package,Version,Fixed Version,CVSS Score,Description\n"

  findings.forEach((finding: any) => {
    csv += `"${finding.id}","${finding.severity}","${finding.package}","${finding.version}","${finding.fixedVersion || "N/A"}","${finding.cvssScore || "N/A"}","${finding.description.replace(/"/g, '""')}"\n`
  })

  return csv
}

