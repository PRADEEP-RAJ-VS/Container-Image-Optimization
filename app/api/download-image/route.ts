import { type NextRequest, NextResponse } from "next/server"
import { optimizeDockerImage } from "@/lib/docker-image-optimizer"
import { getUploadedBuffer } from "@/app/api/analyze/route"

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { imageName, sessionId, optimizations } = body

    // Redirect to the new optimize endpoint
    return NextResponse.json(
      { 
        error: "This endpoint is deprecated. Please use /api/optimize and /api/download-optimized instead.",
        success: false 
      },
      { status: 410 },
    )
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : "Failed to optimize image"
    console.error("[DOWNLOAD-IMAGE] Error:", errorMessage, error)
    return NextResponse.json(
      {
        error: errorMessage,
        success: false,
      },
      { status: 500 },
    )
  }
}
