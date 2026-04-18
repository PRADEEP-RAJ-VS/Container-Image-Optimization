"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { CheckCircle2, AlertCircle, TrendingDown, Code, Download, Cloud } from "lucide-react"
import { useState } from "react"
import { ECRPushDialog } from "@/components/ecr-push-dialog"
import { ECSDeployDialog } from "@/components/ecs-deploy-dialog"

interface OptimizationRecommendationsProps {
  analysis: any
}

export default function OptimizationRecommendations({ analysis }: OptimizationRecommendationsProps) {
  const [expandedTip, setExpandedTip] = useState<string | null>(null)
  const [isDownloading, setIsDownloading] = useState(false)
  const [actualOptimizedSize, setActualOptimizedSize] = useState<number | null>(null)
  const [optimizedSessionId, setOptimizedSessionId] = useState<string | null>(null)
  const [optimizationComplete, setOptimizationComplete] = useState(false)
  const [ecrImageUri, setEcrImageUri] = useState<string | null>(null)
  const recommendations = analysis.optimizationRecommendations || []
  const optimizationScore = analysis.optimizationScore || {}
  const imageInfo = analysis.imageInfo || {}
  const scanMetadata = analysis.scanMetadata || {}

  // Calculate actual savings if we have the optimized size
  const originalSizeBytes = scanMetadata.fileSizeBytes || 0
  const actualPercentSavings = actualOptimizedSize 
    ? (((originalSizeBytes - actualOptimizedSize) / originalSizeBytes) * 100).toFixed(2)
    : optimizationScore.percentSavings

  const handleDownloadOptimizedImage = async () => {
    setIsDownloading(true)
    try {
      const sessionId =
        scanMetadata.sessionId ||
        analysis._sessionId ||
        sessionStorage.getItem("optimizationSessionId")

      if (!sessionId) {
        throw new Error("Session expired. Please re-upload your image.")
      }

      const controller = new AbortController()
      const timeoutId = setTimeout(() => controller.abort(), 600000) // 10 minute timeout

      // Step 1: Optimize the image
      const optimizeResponse = await fetch("/api/optimize", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          sessionId,
          imageName: scanMetadata.imageFile || "docker-image",
          optimizations: {
            useMultiStage: true,
            useAlpineBase: true,
            consolidateRuns: true,
            removeCache: true,
          },
        }),
        signal: controller.signal,
      })

      if (!optimizeResponse.ok) {
        const errorData = await optimizeResponse.json().catch(() => ({ error: "Optimization failed" }))
        throw new Error(errorData.error || "Optimization failed")
      }

      const optimizeData = await optimizeResponse.json()
      
      // Update actual optimized size for display
      if (optimizeData.optimizedSize) {
        setActualOptimizedSize(optimizeData.optimizedSize)
      }
      
      // Save optimized session ID for ECR push
      if (optimizeData.optimizedSessionId) {
        setOptimizedSessionId(optimizeData.optimizedSessionId)
        setOptimizationComplete(true)
      }

      // Step 2: Download the optimized image
      const downloadResponse = await fetch("/api/download-optimized", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          optimizedSessionId: optimizeData.optimizedSessionId,
          imageName: scanMetadata.imageFile || "docker-image",
        }),
        signal: controller.signal,
      })

      clearTimeout(timeoutId)

      if (!downloadResponse.ok) {
        const errorData = await downloadResponse.json().catch(() => ({ error: "Download failed" }))
        throw new Error(errorData.error || "Download failed")
      }

      const blob = await downloadResponse.blob()

      if (blob.size === 0) {
        throw new Error("Downloaded file is empty")
      }

      const url = window.URL.createObjectURL(blob)
      const link = document.createElement("a")
      link.href = url
      link.download = `${scanMetadata.imageFile || "docker-image"}-optimized.tar`
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      window.URL.revokeObjectURL(url)

      alert(
        `✓ Optimized image downloaded successfully!\n\nSize Reduction:\nOriginal: ${(optimizeData.originalSize / 1024 / 1024).toFixed(2)} MB\nOptimized: ${(optimizeData.optimizedSize / 1024 / 1024).toFixed(2)} MB\nSavings: ${optimizeData.percentSavings}%`,
      )
    } catch (error) {
      console.error("Download error:", error)
      if (error instanceof Error && error.name === "AbortError") {
        alert("⏱️ Download timed out. Image optimization is taking longer than expected. Please try again.")
      } else {
        const errorMessage = error instanceof Error ? error.message : "Unknown error"
        
        let userMessage = `❌ Failed to download optimized image:\n\n${errorMessage}`
        
        if (errorMessage.includes("session") || errorMessage.includes("Session")) {
          userMessage += "\n\n💡 Tip: Upload your Docker image again and click 'Analyze' to create a fresh session."
        } else if (errorMessage.includes("Docker")) {
          userMessage += "\n\n💡 Tip: Make sure Docker Desktop is installed and running on your system."
        }
        
        alert(userMessage)
      }
    } finally {
      setIsDownloading(false)
    }
  }

  const getCategoryColor = (category: string) => {
    switch (category) {
      case "size":
        return "bg-blue-500/20 text-blue-300 border-blue-500/20"
      case "security":
        return "bg-red-500/20 text-red-300 border-red-500/20"
      case "performance":
        return "bg-purple-500/20 text-purple-300 border-purple-500/20"
      default:
        return "bg-green-500/20 text-green-300 border-green-500/20"
    }
  }

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case "size":
        return <TrendingDown className="w-4 h-4" />
      case "security":
        return <AlertCircle className="w-4 h-4" />
      case "performance":
        return <CheckCircle2 className="w-4 h-4" />
      default:
        return <Code className="w-4 h-4" />
    }
  }

  return (
    <div className="space-y-4">
      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <Card className="bg-slate-800/50 border-slate-700/50">
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <TrendingDown className="w-8 h-8 text-green-500" />
              <div>
                <p className="text-sm text-slate-400">Potential Savings</p>
                <p className="text-2xl font-bold text-green-500">
                  {actualPercentSavings || "0%"}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-800/50 border-slate-700/50">
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <CheckCircle2 className="w-8 h-8 text-blue-500" />
              <div>
                <p className="text-sm text-slate-400">Optimization Score</p>
                <p className="text-2xl font-bold text-blue-500">
                  {optimizationScore.score || "0"}/100
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-800/50 border-slate-700/50">
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <AlertCircle className="w-8 h-8 text-purple-500" />
              <div>
                <p className="text-sm text-slate-400">Before</p>
                <p className="text-2xl font-bold text-purple-500">
                  {optimizationScore.imageSizeBeforeMB || "0"}MB
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-800/50 border-slate-700/50">
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <Code className="w-8 h-8 text-amber-500" />
              <div>
                <p className="text-sm text-slate-400">After (Actual)</p>
                <p className="text-2xl font-bold text-amber-500">
                  {actualOptimizedSize 
                    ? (actualOptimizedSize / 1024 / 1024).toFixed(2)
                    : optimizationScore.imageSizeAfterMB || "0"}MB
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Action Buttons */}
      <Card className="bg-slate-800/50 border-slate-700/50">
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="text-white">Optimization Analysis</CardTitle>
          <div className="flex gap-3">
            <Button
              onClick={handleDownloadOptimizedImage}
              disabled={isDownloading}
              className="gap-2 bg-green-600 hover:bg-green-700 text-white disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <Download className="w-4 h-4" />
              {isDownloading ? "Optimizing & Downloading..." : "Download Optimized Image"}
            </Button>
            {optimizationComplete && optimizedSessionId && (
              <ECRPushDialog 
                sessionId={optimizedSessionId}
                imageName={scanMetadata.imageFile || "docker-image"}
                imageType="optimized"
                onPushSuccess={(imageUri) => setEcrImageUri(imageUri)}
              />
            )}
            {ecrImageUri && (
              <ECSDeployDialog 
                imageUri={ecrImageUri}
                imageName={scanMetadata.imageFile || "docker-image"}
              />
            )}
          </div>
        </CardHeader>
        <CardContent>
          <div className="p-4 bg-blue-500/10 border border-blue-500/30 rounded-lg">
            <p className="text-sm text-blue-300">
              💡 This will download an actually optimized Docker image with:
            </p>
            <ul className="text-xs text-blue-300 mt-2 ml-4 space-y-1">
              <li>✓ Lightweight Alpine base images</li>
              <li>✓ Consolidated RUN commands</li>
              <li>✓ Optimized package manager cache</li>
              <li>✓ Multi-stage build patterns</li>
            </ul>
            <p className="text-xs text-blue-400 mt-3 font-semibold">
              Estimated savings: <span className="text-green-400">{optimizationScore.percentSavings}</span>
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Optimization Tips */}
      <Card className="bg-slate-800/50 border-slate-700/50">
        <CardHeader>
          <CardTitle className="text-white">Optimization Tips</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {recommendations.length > 0 ? (
              recommendations.map((rec: any) => (
                <div
                  key={rec.id}
                  className="border border-slate-700 rounded-lg p-4 cursor-pointer transition-all hover:border-slate-600 hover:bg-slate-900/30"
                  onClick={() => setExpandedTip(expandedTip === rec.id ? null : rec.id)}
                >
                  <div className="flex items-start gap-3">
                    <div className={`p-2 rounded-lg ${getCategoryColor(rec.category)}`}>
                      {getCategoryIcon(rec.category)}
                    </div>
                    <div className="flex-1">
                      <div className="flex items-start justify-between mb-1">
                        <h4 className="font-semibold text-white">{rec.title}</h4>
                        <div className="flex items-center gap-2 ml-4">
                          {rec.estimatedSavings && (
                            <Badge variant="secondary" className="bg-green-500/20 text-green-300 border-green-500/20">
                              Save {rec.estimatedSavings}
                            </Badge>
                          )}
                          <Badge
                            variant="outline"
                            className={`capitalize ${
                              rec.impact === "High"
                                ? "bg-red-500/20 text-red-300 border-red-500/20"
                                : rec.impact === "Medium"
                                  ? "bg-yellow-500/20 text-yellow-300 border-yellow-500/20"
                                  : "bg-green-500/20 text-green-300 border-green-500/20"
                            }`}
                          >
                            {rec.impact} Impact
                          </Badge>
                        </div>
                      </div>
                      <p className="text-sm text-slate-400">{rec.description}</p>

                      {expandedTip === rec.id && rec.dockerfile && (
                        <div className="mt-4 pt-4 border-t border-slate-700">
                          <p className="text-xs font-semibold text-slate-300 mb-2">Example Dockerfile:</p>
                          <div className="bg-slate-950 rounded-lg p-3 overflow-x-auto">
                            <pre className="text-xs text-slate-300 font-mono whitespace-pre-wrap break-words">
                              {rec.dockerfile}
                            </pre>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              ))
            ) : (
              <p className="text-slate-400 text-center py-8">No optimization tips available</p>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Summary */}
      <Card className="bg-slate-800/50 border-slate-700/50 border-l-4 border-l-blue-500">
        <CardHeader>
          <CardTitle className="text-white text-base">Summary</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-slate-300 text-sm">{optimizationScore.summary || ""}</p>
        </CardContent>
      </Card>
    </div>
  )
}
