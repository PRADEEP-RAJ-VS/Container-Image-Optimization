import { NextRequest, NextResponse } from "next/server"
import { ECRManager } from "@/lib/ecr-client"
import { getUploadedBuffer } from "@/app/api/analyze/route"

/**
 * POST /api/ecr/push
 * Push Docker image to ECR (both original and optimized)
 */
export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { sessionId, imageName, imageTag, repositoryName, region, imageType } = body

    // Validate required fields
    if (!sessionId) {
      return NextResponse.json(
        { success: false, error: "Session ID is required" },
        { status: 400 }
      )
    }

    if (!repositoryName) {
      return NextResponse.json(
        { success: false, error: "Repository name is required" },
        { status: 400 }
      )
    }

    if (!imageTag) {
      return NextResponse.json(
        { success: false, error: "Image tag is required" },
        { status: 400 }
      )
    }

    // Get the image buffer from session
    const buffer = getUploadedBuffer(sessionId)
    if (!buffer) {
      return NextResponse.json(
        {
          success: false,
          error: "Session expired. Please re-upload your image.",
        },
        { status: 404 }
      )
    }

    console.log(`[ECR-PUSH] Pushing ${imageType || "image"} to ECR: ${repositoryName}:${imageTag}`)

    // Initialize ECR manager
    const ecrManager = new ECRManager(region || process.env.AWS_REGION || "us-east-1")

    // Push image to ECR
    const result = await ecrManager.pushImageToECR({
      imageName: imageName || repositoryName,
      imageTag,
      tarBuffer: buffer,
      repositoryName,
      region,
    })

    if (!result.success) {
      return NextResponse.json(
        {
          success: false,
          error: result.error || "Failed to push image to ECR",
        },
        { status: 500 }
      )
    }

    console.log(`[ECR-PUSH] Successfully pushed: ${result.imageUri}`)

    return NextResponse.json({
      success: true,
      imageUri: result.imageUri,
      digest: result.digest,
      repositoryName,
      imageTag,
      message: `Image pushed successfully to ${result.imageUri}`,
    })
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error"
    console.error("[ECR-PUSH] Error:", message)

    return NextResponse.json(
      {
        success: false,
        error: `Failed to push to ECR: ${message}`,
      },
      { status: 500 }
    )
  }
}
