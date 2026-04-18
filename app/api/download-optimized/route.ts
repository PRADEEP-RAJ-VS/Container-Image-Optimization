import { type NextRequest, NextResponse } from "next/server"
import { getUploadedBuffer } from "@/app/api/analyze/route"
import { proxyToBackend } from "@/lib/api-proxy"

export async function POST(request: NextRequest) {
  try {
    const proxiedResponse = await proxyToBackend(request, "/api/download-optimized")
    if (proxiedResponse) {
      return proxiedResponse
    }

    const body = await request.json()
    const { optimizedSessionId, imageName } = body

    if (!optimizedSessionId) {
      return NextResponse.json(
        { error: "Optimized session ID is required" },
        { status: 400 },
      )
    }

    // Retrieve the optimized buffer
    const optimizedBuffer = getUploadedBuffer(optimizedSessionId)
    
    console.log("[DOWNLOAD-OPTIMIZED] Session ID received:", optimizedSessionId)
    console.log("[DOWNLOAD-OPTIMIZED] Buffer found:", !!optimizedBuffer)
    
    if (!optimizedBuffer) {
      return NextResponse.json(
        { 
          error: "Optimized image not found. Please optimize the image first.",
          success: false 
        },
        { status: 404 },
      )
    }

    console.log("[DOWNLOAD-OPTIMIZED] Returning optimized buffer, size:", optimizedBuffer.length)

    return new NextResponse(optimizedBuffer as any, {
      status: 200,
      headers: {
        "Content-Type": "application/x-tar",
        "Content-Disposition": `attachment; filename="${imageName || 'docker-image'}-optimized.tar"`,
        "Content-Length": optimizedBuffer.length.toString(),
      },
    })
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : "Failed to download optimized image"
    console.error("[DOWNLOAD-OPTIMIZED] Error:", errorMessage, error)
    return NextResponse.json(
      {
        error: errorMessage,
        success: false,
      },
      { status: 500 },
    )
  }
}
