import { type NextRequest, NextResponse } from "next/server"
import { optimizeDockerImage } from "@/lib/docker-image-optimizer"
import { getUploadedBuffer } from "@/app/api/analyze/route"
import { writeFileSync, existsSync, mkdirSync } from "fs"
import { join } from "path"
import { tmpdir } from "os"

const SESSION_DIR = join(tmpdir(), "docker-optimizer-sessions")

if (!existsSync(SESSION_DIR)) {
  mkdirSync(SESSION_DIR, { recursive: true })
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { imageName, sessionId, optimizations } = body

    if (!imageName) {
      return NextResponse.json(
        { error: "Image name is required" },
        { status: 400 },
      )
    }

    if (!sessionId) {
      return NextResponse.json(
        { error: "Session ID is required for optimization" },
        { status: 400 },
      )
    }

    // Retrieve the original buffer from server memory using session ID
    const originalBuffer = getUploadedBuffer(sessionId)
    
    console.log("[OPTIMIZE] Session ID received:", sessionId)
    console.log("[OPTIMIZE] Original buffer found:", !!originalBuffer)
    
    if (!originalBuffer) {
      return NextResponse.json(
        { 
          error: "Image session expired. Please re-upload your image.",
          success: false 
        },
        { status: 400 },
      )
    }

    // Perform actual optimization
    console.log("[OPTIMIZE] Starting optimization for:", imageName)
    const result = await optimizeDockerImage(
      originalBuffer,
      imageName,
      optimizations || {
        useMultiStage: true,
        useAlpineBase: true,
        consolidateRuns: true,
        removeCache: true,
      },
    )

    if (!result.success) {
      let errorMessage = result.error || "Optimization failed"
      
      if (errorMessage.includes("dockerDesktopLinuxEngine") || 
          errorMessage.includes("docker daemon") ||
          errorMessage.includes("Cannot connect to the Docker daemon")) {
        errorMessage = "Docker is not running. Please start Docker Desktop and try again."
      }
      
      return NextResponse.json(
        { 
          error: errorMessage, 
          success: false 
        },
        { status: 500 },
      )
    }

    if (!result.optimizedBuffer) {
      return NextResponse.json(
        { 
          error: "Failed to get optimized image buffer",
          success: false 
        },
        { status: 500 },
      )
    }

    // Store optimized buffer with different session ID
    const optimizedSessionId = `${sessionId}-optimized`
    const optimizedFilePath = join(SESSION_DIR, `${optimizedSessionId}.tar`)
    
    try {
      writeFileSync(optimizedFilePath, result.optimizedBuffer)
      console.log("[OPTIMIZE] Stored optimized buffer:", optimizedSessionId, "Size:", result.optimizedBuffer.length)
    } catch (error) {
      console.error("[OPTIMIZE] Failed to store optimized buffer:", error)
    }

    console.log("[OPTIMIZE] Optimization complete:", {
      originalSize: result.originalSize,
      optimizedSize: result.optimizedSize,
      savings: `${result.percentSavings}%`,
    })

    return NextResponse.json({
      success: true,
      originalSize: result.originalSize,
      optimizedSize: result.optimizedSize,
      sizeSavings: result.sizeSavings,
      percentSavings: result.percentSavings,
      optimizedSessionId,
      message: `Optimized successfully! Saved ${result.percentSavings}% (${(result.sizeSavings / 1024 / 1024).toFixed(2)} MB)`,
    })
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : "Failed to optimize image"
    console.error("[OPTIMIZE] Error:", errorMessage, error)
    return NextResponse.json(
      {
        error: errorMessage,
        success: false,
      },
      { status: 500 },
    )
  }
}
