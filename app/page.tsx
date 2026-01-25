"use client"

import { useState } from "react"
import { Upload, Loader2, AlertCircle, CheckCircle2, AlertTriangle } from "lucide-react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Alert, AlertDescription } from "@/components/ui/alert"
import UploadForm from "@/components/upload-form"
import AnalysisResults from "@/components/analysis-results"
import { useAnalysis } from "@/hooks/use-analysis"

export default function Home() {
  const { analysis, isLoading, error, setAnalysis, analyzeImage } = useAnalysis()
  const [showResults, setShowResults] = useState(false)

  const handleUpload = async (file: File) => {
    setShowResults(false)
    const success = await analyzeImage(file)
    if (success) {
      setShowResults(true)
    }
  }

  return (
    <main className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
      {/* Header */}
      <header className="border-b border-slate-700/50 bg-slate-900/50 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 py-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-gradient-to-br from-blue-500 to-cyan-500 rounded-lg flex items-center justify-center">
                <svg className="w-6 h-6 text-white" fill="currentColor" viewBox="0 0 24 24">
                  <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8zm3.5-9c.83 0 1.5-.67 1.5-1.5S16.33 8 15.5 8 14 8.67 14 9.5s.67 1.5 1.5 1.5zm-7 0c.83 0 1.5-.67 1.5-1.5S9.33 8 8.5 8 7 8.67 7 9.5 7.67 11 8.5 11z" />
                </svg>
              </div>
              <div>
                <h1 className="text-xl font-bold text-white">Docker Optimizer</h1>
                <p className="text-xs text-slate-400">Image Analysis & Vulnerability Scanner</p>
              </div>
            </div>
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-4 py-8 sm:px-6 lg:px-8">
        {/* Error Alert */}
        {error && (
          <Alert variant="destructive" className="mb-6 bg-red-950/20 border-red-500/20">
            <AlertCircle className="h-4 w-4" />
            <AlertDescription className="text-red-300">{error}</AlertDescription>
          </Alert>
        )}

        {/* Main Content Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Upload Section */}
          <div className="lg:col-span-1">
            <Card className="bg-slate-800/50 border-slate-700/50 sticky top-24">
              <CardHeader>
                <CardTitle className="text-white">Analyze Image</CardTitle>
                <CardDescription className="text-slate-400">Upload a Docker image to scan</CardDescription>
              </CardHeader>
              <CardContent>
                <UploadForm onUpload={handleUpload} isLoading={isLoading} />
              </CardContent>
            </Card>
          </div>

          {/* Results Section */}
          <div className="lg:col-span-2">
            {isLoading ? (
              <Card className="bg-slate-800/50 border-slate-700/50 h-96 flex items-center justify-center">
                <div className="text-center">
                  <Loader2 className="w-8 h-8 animate-spin text-blue-400 mx-auto mb-4" />
                  <p className="text-slate-300 font-medium">Analyzing Docker image...</p>
                  <p className="text-sm text-slate-500 mt-2">This may take a few moments</p>
                </div>
              </Card>
            ) : showResults && analysis ? (
              <AnalysisResults analysis={analysis} />
            ) : (
              <Card className="bg-slate-800/50 border-slate-700/50 h-96 flex items-center justify-center">
                <div className="text-center">
                  <Upload className="w-12 h-12 text-slate-500 mx-auto mb-4" />
                  <p className="text-slate-300 font-medium">Upload a Docker image to get started</p>
                  <p className="text-sm text-slate-500 mt-2">Supports .tar format from docker save</p>
                </div>
              </Card>
            )}
          </div>
        </div>

        {/* Quick Stats - Only show when analysis is available */}
        {analysis && !isLoading && (
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mt-8">
            <Card className="bg-slate-800/50 border-slate-700/50">
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-slate-400">Total Vulnerabilities</p>
                    <p className="text-2xl font-bold text-white">{analysis.vulnerabilities?.total || 0}</p>
                  </div>
                  <AlertTriangle
                    className={`w-8 h-8 ${analysis.vulnerabilities?.critical ? "text-red-500" : "text-slate-500"}`}
                  />
                </div>
              </CardContent>
            </Card>
            <Card className="bg-slate-800/50 border-slate-700/50">
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-slate-400">Image Size</p>
                    <p className="text-2xl font-bold text-white">{analysis.imageInfo?.size || "N/A"}</p>
                  </div>
                  <Upload className="w-8 h-8 text-blue-500" />
                </div>
              </CardContent>
            </Card>
            <Card className="bg-slate-800/50 border-slate-700/50">
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-slate-400">Base Layers</p>
                    <p className="text-2xl font-bold text-white">{analysis.imageInfo?.layers || 0}</p>
                  </div>
                  <CheckCircle2 className="w-8 h-8 text-green-500" />
                </div>
              </CardContent>
            </Card>
            <Card className="bg-slate-800/50 border-slate-700/50">
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-slate-400">Potential Savings</p>
                    <p className="text-2xl font-bold text-white">
                      {analysis.optimizationScore?.percentSavings || "0"}%
                    </p>
                  </div>
                  <AlertTriangle className="w-8 h-8 text-amber-500" />
                </div>
              </CardContent>
            </Card>
          </div>
        )}
      </div>
    </main>
  )
}
