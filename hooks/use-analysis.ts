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
      const directBackendBaseUrl = process.env.NEXT_PUBLIC_BACKEND_API_BASE_URL?.replace(/\/$/, "")
      const isFileUpload = input instanceof File
      const canUseDirectBackend = !!directBackendBaseUrl && (
        (typeof window !== "undefined" && window.location.protocol === "http:") ||
        directBackendBaseUrl.startsWith("https://")
      )

      if (!isFileUpload) {
        formData.append('imageName', input)
      }

      // Large multipart uploads can fail on Vercel before proxying, so send file uploads directly to EC2 when configured.
      const analyzeEndpoint = isFileUpload && canUseDirectBackend
        ? `${directBackendBaseUrl}/api/analyze`
        : '/api/analyze'

      if (isFileUpload) {
        const uploadFile = input as File

        if (canUseDirectBackend) {
          formData.append('file', uploadFile)
        } else {
          // Fallback for HTTPS Vercel -> HTTP backend setups: upload large files in small chunks.
          const chunkSize = 2 * 1024 * 1024
          const totalChunks = Math.ceil(uploadFile.size / chunkSize)
          const uploadId = `upload-${Date.now()}-${Math.random().toString(36).slice(2)}`

          for (let chunkIndex = 0; chunkIndex < totalChunks; chunkIndex += 1) {
            const start = chunkIndex * chunkSize
            const end = Math.min(start + chunkSize, uploadFile.size)
            const chunk = uploadFile.slice(start, end)

            const chunkFormData = new FormData()
            chunkFormData.append('uploadId', uploadId)
            chunkFormData.append('fileName', uploadFile.name)
            chunkFormData.append('chunkIndex', String(chunkIndex))
            chunkFormData.append('totalChunks', String(totalChunks))
            chunkFormData.append('chunk', chunk, `${uploadFile.name}.part.${chunkIndex}`)

            const chunkResponse = await fetch('/api/upload/chunk', {
              method: 'POST',
              body: chunkFormData,
            })

            if (!chunkResponse.ok) {
              let chunkErrorText = ''
              try {
                chunkErrorText = await chunkResponse.text()
              } catch {
                // no-op
              }
              throw new Error(`Chunk upload failed (${chunkResponse.status}): ${chunkErrorText.substring(0, 150) || 'Unknown error'}`)
            }
          }

          formData.append('uploadedChunkId', uploadId)
          formData.append('uploadedFileName', uploadFile.name)
        }
      }

      const response = await fetch(analyzeEndpoint, {
        method: 'POST',
        body: formData,
      })

      if (!response.ok) {
        if (response.status === 413) {
          throw new Error('Uploaded .tar is too large for this route. Retry in Docker Hub mode or use chunk upload fallback.')
        }

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
