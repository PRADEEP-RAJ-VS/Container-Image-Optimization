"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { ArrowUpRight, Package, AlertTriangle } from "lucide-react"
import { useState } from "react"

interface FindingsTableProps {
  findings: any[]
}

export default function FindingsTable({ findings }: FindingsTableProps) {
  const [expandedId, setExpandedId] = useState<string | null>(null)

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "CRITICAL":
        return "bg-red-950/50 text-red-300 border-red-500/20"
      case "HIGH":
        return "bg-orange-950/50 text-orange-300 border-orange-500/20"
      case "MEDIUM":
        return "bg-yellow-950/50 text-yellow-300 border-yellow-500/20"
      default:
        return "bg-green-950/50 text-green-300 border-green-500/20"
    }
  }

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case "CRITICAL":
        return "🔴"
      case "HIGH":
        return "🟠"
      case "MEDIUM":
        return "🟡"
      default:
        return "🟢"
    }
  }

  return (
    <Card className="bg-slate-800/50 border-slate-700/50">
      <CardHeader>
        <CardTitle className="text-white flex items-center gap-2">
          <AlertTriangle className="w-5 h-5 text-yellow-500" />
          Vulnerability Findings {findings.length > 0 && `(${findings.length})`}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-3 max-h-96 overflow-y-auto">
          {findings.length > 0 ? (
            findings.slice(0, 20).map((finding, idx) => (
              <div
                key={idx}
                className={`border rounded-lg p-4 cursor-pointer transition-all ${getSeverityColor(finding.severity)}`}
                onClick={() => setExpandedId(expandedId === finding.id ? null : finding.id)}
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-lg">{getSeverityIcon(finding.severity)}</span>
                      <code className="text-sm font-mono font-semibold">{finding.id}</code>
                      <Badge variant="outline" className="ml-auto">
                        {finding.package}
                      </Badge>
                    </div>
                    <p className="text-sm font-medium">{finding.description}</p>
                    <div className="flex items-center gap-2 mt-2 text-xs opacity-75">
                      <Package className="w-3 h-3" />
                      <span>{finding.version}</span>
                      {finding.fixedVersion && (
                        <>
                          <ArrowUpRight className="w-3 h-3" />
                          <span>{finding.fixedVersion}</span>
                        </>
                      )}
                    </div>
                  </div>
                  {finding.cvssScore && (
                    <div className="text-right">
                      <div className="text-lg font-bold">{finding.cvssScore.toFixed(1)}</div>
                      <div className="text-xs opacity-75">CVSS</div>
                    </div>
                  )}
                </div>
                {expandedId === finding.id && (
                  <div className="mt-3 pt-3 border-t border-current/20 text-xs">
                    <p className="opacity-75">
                      <strong>Fixed Version:</strong> {finding.fixedVersion || "No fix available"}
                    </p>
                    <p className="opacity-75 mt-1">
                      <strong>Severity:</strong> {finding.severity}
                    </p>
                  </div>
                )}
              </div>
            ))
          ) : (
            <div className="text-center py-8 text-slate-400">
              <p>No vulnerabilities found</p>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  )
}
