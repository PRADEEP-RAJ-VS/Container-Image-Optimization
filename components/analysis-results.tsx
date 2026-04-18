"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import VulnerabilityChart from "@/components/vulnerability-chart"
import LayerBreakdown from "@/components/layer-breakdown"
import OptimizationRecommendations from "@/components/optimization-recommendations"
import FindingsTable from "@/components/findings-table"
import ExportButton from "@/components/export-button"
import { ECRPushDialog } from "@/components/ecr-push-dialog"
import { ECSDeployDialog } from "@/components/ecs-deploy-dialog"
import { AlertTriangle, AlertCircle, AlertOctagon, Clock, Copy, Cloud } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { useState } from "react"

interface AnalysisResultsProps {
  analysis: any
}

export default function AnalysisResults({ analysis }: AnalysisResultsProps) {
  const [copySuccess, setCopySuccess] = useState(false)
  const [ecrImageUri, setEcrImageUri] = useState<string>("")
  const [optimizedSessionId, setOptimizedSessionId] = useState<string | null>(null)
  const [optimizationStats, setOptimizationStats] = useState<any>(null)
  const criticalCount = analysis.vulnerabilities?.critical || 0
  const highCount = analysis.vulnerabilities?.high || 0
  const mediumCount = analysis.vulnerabilities?.medium || 0

  const scanTime = analysis.scanMetadata?.scannedAt ? new Date(analysis.scanMetadata.scannedAt).toLocaleString() : "N/A"
  const sessionId = analysis.scanMetadata?.sessionId || analysis._sessionId
  const imageName = analysis.scanMetadata?.imageFile || "docker-image"
  const isMockData = analysis.vulnerabilities?.isMockData

  const handleOptimizationComplete = (optSessionId: string, stats: any) => {
    setOptimizedSessionId(optSessionId)
    setOptimizationStats(stats)
  }

  const handleCopyJSON = () => {
    navigator.clipboard.writeText(JSON.stringify(analysis, null, 2))
    setCopySuccess(true)
    setTimeout(() => setCopySuccess(false), 2000)
  }

  return (
    <div className="space-y-6">
      {/* AWS Integration Options */}
      {sessionId && (
        <Card className="bg-slate-800/50 border-slate-700/50">
          <CardHeader>
            <CardTitle className="text-white flex items-center gap-2">
              <Cloud className="w-5 h-5" />
              AWS Integration
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <p className="text-sm text-slate-400">
                Push your images to Amazon ECR and deploy to ECS with one click
              </p>
              {optimizationStats && (
                <div className="p-3 bg-green-950/30 border border-green-500/50 rounded">
                  <p className="text-sm text-green-400">
                    ✓ Optimization complete! Saved {optimizationStats.percentSavings}% ({(optimizationStats.sizeSavings / 1024 / 1024).toFixed(2)} MB)
                  </p>
                </div>
              )}
              <div className="flex flex-wrap gap-3">
                <ECRPushDialog 
                  sessionId={sessionId} 
                  imageName={imageName}
                  imageType="original"
                />
                {optimizedSessionId && (
                  <ECRPushDialog 
                    sessionId={optimizedSessionId} 
                    imageName={imageName}
                    imageType="optimized"
                  />
                )}
                {ecrImageUri && (
                  <ECSDeployDialog 
                    imageUri={ecrImageUri}
                    imageName={imageName}
                  />
                )}
              </div>
              {ecrImageUri && (
                <div className="mt-4 p-3 bg-slate-900/50 rounded border border-slate-700">
                  <p className="text-xs text-slate-400 mb-1">ECR Image URI:</p>
                  <code className="text-xs text-green-400 break-all">{ecrImageUri}</code>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Vulnerability Summary with Export */}
      <Card className="bg-slate-800/50 border-slate-700/50">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-white flex items-center gap-2">
                <span>Vulnerability Summary</span>
                <span className="flex items-center gap-1 text-xs text-slate-400 font-normal">
                  <Clock className="w-3 h-3" />
                  {scanTime}
                </span>
              </CardTitle>
            </div>
            <div className="flex gap-2">
              <Button
                size="sm"
                variant="ghost"
                onClick={handleCopyJSON}
                className="text-slate-400 hover:text-white hover:bg-slate-700"
                title="Copy JSON to clipboard"
              >
                <Copy className="w-4 h-4" />
              </Button>
              <ExportButton 
                analysis={analysis} 
                fileName="docker-analysis"
                sessionId={sessionId}
                imageName={imageName}
                onOptimizationComplete={handleOptimizationComplete}
              />
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-3 gap-4">
            <div className="bg-red-950/30 border border-red-500/20 rounded-lg p-4">
              <div className="flex items-center gap-2 mb-2">
                <AlertOctagon className="w-5 h-5 text-red-500" />
                <span className="text-sm font-medium text-slate-300">Critical</span>
              </div>
              <p className="text-3xl font-bold text-red-500">{criticalCount}</p>
            </div>
            <div className="bg-orange-950/30 border border-orange-500/20 rounded-lg p-4">
              <div className="flex items-center gap-2 mb-2">
                <AlertTriangle className="w-5 h-5 text-orange-500" />
                <span className="text-sm font-medium text-slate-300">High</span>
              </div>
              <p className="text-3xl font-bold text-orange-500">{highCount}</p>
            </div>
            <div className="bg-yellow-950/30 border border-yellow-500/20 rounded-lg p-4">
              <div className="flex items-center gap-2 mb-2">
                <AlertCircle className="w-5 h-5 text-yellow-500" />
                <span className="text-sm font-medium text-slate-300">Medium</span>
              </div>
              <p className="text-3xl font-bold text-yellow-500">{mediumCount}</p>
            </div>
          </div>
          {copySuccess && <p className="text-xs text-green-400 mt-4">JSON copied to clipboard!</p>}
        </CardContent>
      </Card>

      {/* Tabs for detailed views */}
      <Tabs defaultValue="vulnerabilities" className="w-full">
        <TabsList className="grid w-full grid-cols-4 bg-slate-900/50 border border-slate-700/50">
          <TabsTrigger value="vulnerabilities" className="text-slate-300 data-[state=active]:text-white">
            Vulnerabilities
          </TabsTrigger>
          <TabsTrigger value="findings" className="text-slate-300 data-[state=active]:text-white">
            Findings
          </TabsTrigger>
          <TabsTrigger value="layers" className="text-slate-300 data-[state=active]:text-white">
            Layers
          </TabsTrigger>
          <TabsTrigger value="optimization" className="text-slate-300 data-[state=active]:text-white">
            Optimization
          </TabsTrigger>
        </TabsList>

        <TabsContent value="vulnerabilities" className="space-y-4">
          <VulnerabilityChart analysis={analysis} />
        </TabsContent>

        <TabsContent value="findings" className="space-y-4">
          <FindingsTable findings={analysis.vulnerabilities?.findings || []} />
        </TabsContent>

        <TabsContent value="layers" className="space-y-4">
          <LayerBreakdown analysis={analysis} />
        </TabsContent>

        <TabsContent value="optimization" className="space-y-4">
          <OptimizationRecommendations analysis={analysis} />
        </TabsContent>
      </Tabs>
    </div>
  )
}
