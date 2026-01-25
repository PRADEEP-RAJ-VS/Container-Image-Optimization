import { NextRequest, NextResponse } from "next/server"
import { ECRManager } from "@/lib/ecr-client"

/**
 * GET /api/ecr/auth
 * Get ECR authentication credentials
 */
export async function GET(request: NextRequest) {
  try {
    const searchParams = request.nextUrl.searchParams
    const region = searchParams.get("region") || process.env.AWS_REGION || "us-east-1"

    const ecrManager = new ECRManager(region)
    const credentials = await ecrManager.getAuthToken()

    return NextResponse.json({
      success: true,
      credentials: {
        username: credentials.username,
        registry: credentials.registry,
        expiresAt: credentials.expiresAt.toISOString(),
      },
      // Don't send password to client for security
    })
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error"
    console.error("[ECR-AUTH] Error:", message)

    return NextResponse.json(
      {
        success: false,
        error: message,
      },
      { status: 500 }
    )
  }
}
