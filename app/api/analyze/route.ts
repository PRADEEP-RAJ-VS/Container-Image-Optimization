import { type NextRequest, NextResponse } from "next/server"
import { analyzeDockerImage } from "@/lib/docker-analyzer"
import { scanWithTrivy } from "@/lib/trivy-scanner"
import { pullAndConvertDockerImage, validateImageName } from "@/lib/docker-image-puller"
import { writeFileSync, readFileSync, existsSync, mkdirSync, readdirSync, unlinkSync, statSync } from "fs"
import { join } from "path"
import { tmpdir } from "os"

// Use file-based storage instead of in-memory to survive server restarts
const SESSION_DIR = join(tmpdir(), "docker-optimizer-sessions")

// Ensure session directory exists
if (!existsSync(SESSION_DIR)) {
  mkdirSync(SESSION_DIR, { recursive: true })
}

// Cleanup old session files on startup and periodically
function cleanupOldSessions() {
  try {
    const now = Date.now()
    const maxAge = 4 * 60 * 60 * 1000 // 4 hours
    const files = readdirSync(SESSION_DIR)
    
    for (const file of files) {
      const filePath = join(SESSION_DIR, file)
      const stats = statSync(filePath)
      
      if (now - stats.mtimeMs > maxAge) {
        unlinkSync(filePath)
        console.log("[ANALYZE] Cleaned up expired session file:", file)
      }
    }
  } catch (error) {
    console.error("[ANALYZE] Session cleanup error:", error)
  }
}

// Initial cleanup
cleanupOldSessions()

// Periodic cleanup every 30 minutes
setInterval(cleanupOldSessions, 30 * 60 * 1000)

export async function POST(request: NextRequest) {
  try {
    const formData = await request.formData()
    const file = formData.get('file') as File | null
    const imageName = formData.get('imageName') as string | null

    let fileBuffer: Buffer
    let source: string
    let imageIdentifier: string

    if (file) {
      fileBuffer = Buffer.from(await file.arrayBuffer())
      source = 'local-upload'
      imageIdentifier = file.name
      console.log(`[DEBUG] File upload: ${file.name}, size: ${fileBuffer.length} bytes`)
    } else if (imageName) {
      if (!validateImageName(imageName)) {
        return NextResponse.json(
          { 
            error: "Invalid Docker image name format. Use format like 'python:3.9' or 'nginx:latest'",
            success: false 
          },
          { status: 400 },
        )
      }

      try {
        const { buffer, imageInfo } = await pullAndConvertDockerImage(imageName)
        fileBuffer = buffer
        source = imageInfo.source
        imageIdentifier = imageName
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error'
        return NextResponse.json(
          {
            error: `Failed to pull Docker image: ${errorMessage}`,
            success: false,
          },
          { status: 500 },
        )
      }
    } else {
      return NextResponse.json(
        { error: 'No file or image name provided', success: false }, 
        { status: 400 }
      )
    }

    if (!fileBuffer || fileBuffer.length === 0) {
      return NextResponse.json(
        { error: 'Failed to process image: empty buffer', success: false }, 
        { status: 500 }
      )
    }

    let imageAnalysis
    try {
      imageAnalysis = await analyzeDockerImage(fileBuffer)
    } catch (analyzeError) {
      const errorMsg = analyzeError instanceof Error ? analyzeError.message : 'Analysis failed'
      return NextResponse.json(
        {
          error: `Image analysis failed: ${errorMsg}`,
          success: false,
        },
        { status: 500 },
      )
    }

    const trivyResults = await scanWithTrivy(fileBuffer, imageIdentifier)

    // Store buffer in file system for later optimization (using session ID)
    const sessionId = `session-${Date.now()}-${Math.random().toString(36).substring(7)}`
    const sessionFilePath = join(SESSION_DIR, `${sessionId}.tar`)
    
    try {
      writeFileSync(sessionFilePath, fileBuffer)
      console.log("[ANALYZE] Stored session buffer:", sessionId, "Size:", fileBuffer.length)
    } catch (error) {
      console.error("[ANALYZE] Failed to store session buffer:", error)
    }

    const combinedAnalysis = {
      success: true,
      imageInfo: imageAnalysis.info,
      vulnerabilities: {
        critical: trivyResults.critical,
        high: trivyResults.high,
        medium: trivyResults.medium,
        low: trivyResults.low,
        total: trivyResults.total,
        byPackage: trivyResults.byPackage,
        findings: trivyResults.findings,
        isMockData: trivyResults.isMockData,
        scannerVersion: trivyResults.scannerVersion,
      },
      optimizationScore: imageAnalysis.optimization,
      optimizationRecommendations: imageAnalysis.recommendations,
      scanMetadata: {
        scannedAt: trivyResults.scanned_at,
        imageFile: imageIdentifier,
        source,
        fileSizeMB: (fileBuffer.length / 1024 / 1024).toFixed(2),
        fileSizeBytes: fileBuffer.length,
        sessionId, // Return session ID to client
      },
    }

    return NextResponse.json(combinedAnalysis)
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Failed to analyze image'
    return NextResponse.json(
      {
        error: errorMessage,
        success: false,
      },
      { status: 500 },
    )
  }
}

// Export for use by other API routes
export function getUploadedBuffer(sessionId: string): Buffer | null {
  try {
    const sessionFilePath = join(SESSION_DIR, `${sessionId}.tar`)
    
    if (!existsSync(sessionFilePath)) {
      console.log("[ANALYZE] Session file not found:", sessionId)
      return null
    }
    
    const buffer = readFileSync(sessionFilePath)
    console.log("[ANALYZE] Retrieved session buffer:", sessionId, "Size:", buffer.length)
    return buffer
  } catch (error) {
    console.error("[ANALYZE] Failed to retrieve session buffer:", error)
    return null
  }
}
