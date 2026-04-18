"use client"

import { useState, useCallback } from "react"

interface VulnerabilityData {
  critical: number
  high: number
  medium: number
  low: number
  total: number
  byPackage?: any[]
}

interface AnalysisData {
  success: boolean
  imageInfo?: {
    size: string
    layers: number
    layerDetails?: any[]
  }
  vulnerabilities?: VulnerabilityData
  optimizationScore?: {
    score: number
    percentSavings: string
    summary?: string
  }
  optimizationRecommendations?: any[]
  scanMetadata?: {
    scannedAt: string
    imageFile: string
    source: string
    fileSizeMB: string
    sessionId?: string
  }
}

export function useAnalysis() {
  const [analysis, setAnalysis] = useState<AnalysisData | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const analyzeImage = useCallback(async (input: File | string): Promise<boolean> => {
    setIsLoading(true)
    setError(null)
    sessionStorage.removeItem("optimizationSessionId")

    try {
      const formData = new FormData()

      if (input instanceof File) {
        formData.append('file', input)
      } else {
        formData.append('imageName', input)
      }

      const response = await fetch('/api/analyze', {
        method: 'POST',
        body: formData,
      })

      if (!response.ok) {
        let errorData
        let textContent = ''
        try {
          textContent = await response.text()
          errorData = JSON.parse(textContent)
        } catch {
          throw new Error(`Server error (${response.status}): ${textContent.substring(0, 150) || 'Unknown error'}`)
        }
        throw new Error(errorData.error || 'Failed to analyze image')
      }

      const data: AnalysisData = await response.json()
      if (!data.success) {
        throw new Error(data.vulnerabilities?.findings ? 'Analysis partial' : 'Analysis failed')
      }
      
      // Store session ID with the analysis data and in sessionStorage
      const analysisWithSession = {
        ...data,
        _sessionId: data.scanMetadata?.sessionId // Store session ID in analysis object
      }
      
      if (data.scanMetadata?.sessionId) {
        sessionStorage.setItem("optimizationSessionId", data.scanMetadata.sessionId)
        console.log("[USE-ANALYSIS] Stored session ID:", data.scanMetadata.sessionId)
      } else {
        console.warn("[USE-ANALYSIS] No session ID received from server")
      }
      
      setAnalysis(analysisWithSession)
      return true
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to analyze image'
      setError(message)
      return false
    } finally {
      setIsLoading(false)
    }
  }, [])

  return {
    analysis,
    isLoading,
    error,
    setAnalysis,
    analyzeImage,
  }
}
