import { NextRequest, NextResponse } from "next/server"
import { ECRManager } from "@/lib/ecr-client"

/**
 * GET /api/ecr/list
 * List ECR repositories and their images
 */
export async function GET(request: NextRequest) {
  try {
    const searchParams = request.nextUrl.searchParams
    const region = searchParams.get("region") || process.env.AWS_REGION || "us-east-1"
    const repositoryName = searchParams.get("repository")

    const ecrManager = new ECRManager(region)

    if (repositoryName) {
      // Get images for a specific repository
      const images = await ecrManager.listImages(repositoryName)

      return NextResponse.json({
        success: true,
        repository: repositoryName,
        images,
        count: images.length,
      })
    } else {
      // List all repositories
      const repositories = await ecrManager.listRepositories()

      return NextResponse.json({
        success: true,
        repositories,
        count: repositories.length,
      })
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error"
    console.error("[ECR-LIST] Error:", message)

    return NextResponse.json(
      {
        success: false,
        error: message,
      },
      { status: 500 }
    )
  }
}
