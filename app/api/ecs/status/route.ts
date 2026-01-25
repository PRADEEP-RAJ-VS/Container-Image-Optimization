import { NextRequest, NextResponse } from "next/server"
import { ECSDeployer } from "@/lib/ecs-deployer"

/**
 * GET /api/ecs/status
 * Get ECS deployment status or list clusters
 */
export async function GET(request: NextRequest) {
  try {
    const searchParams = request.nextUrl.searchParams
    const region = searchParams.get("region") || process.env.AWS_REGION || "us-east-1"
    const cluster = searchParams.get("cluster")
    const taskArn = searchParams.get("taskArn")
    const action = searchParams.get("action") // "clusters" | "services" | "task-status"

    const deployer = new ECSDeployer(region)

    // List clusters
    if (action === "clusters" || (!cluster && !taskArn)) {
      const clusters = await deployer.listClusters()
      return NextResponse.json({
        success: true,
        clusters,
      })
    }

    // Get task status
    if (cluster && taskArn) {
      const status = await deployer.getTaskStatus(cluster, taskArn)
      return NextResponse.json({
        success: true,
        status,
      })
    }

    // List services in cluster
    if (cluster && action === "services") {
      const services = await deployer.listServices(cluster)
      return NextResponse.json({
        success: true,
        services: services.map((s) => ({
          name: s.serviceName,
          arn: s.serviceArn,
          status: s.status,
          desiredCount: s.desiredCount,
          runningCount: s.runningCount,
          pendingCount: s.pendingCount,
        })),
      })
    }

    return NextResponse.json(
      {
        success: false,
        error: "Invalid request parameters",
      },
      { status: 400 }
    )
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error"
    console.error("[ECS-STATUS] Error:", message)

    return NextResponse.json(
      {
        success: false,
        error: message,
      },
      { status: 500 }
    )
  }
}
