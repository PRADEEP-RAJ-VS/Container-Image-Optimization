import { NextRequest, NextResponse } from "next/server"
import { ECSDeployer } from "@/lib/ecs-deployer"
import { proxyToBackend } from "@/lib/api-proxy"

/**
 * POST /api/ecs/deploy
 * Deploy Docker image to ECS
 */
export async function POST(request: NextRequest) {
  try {
    const proxiedResponse = await proxyToBackend(request, "/api/ecs/deploy")
    if (proxiedResponse) {
      return proxiedResponse
    }

    const body = await request.json()
    const {
      cluster,
      serviceName,
      taskFamily,
      imageUri,
      cpu,
      memory,
      containerPort,
      environment,
      desiredCount,
      subnets,
      securityGroups,
      assignPublicIp,
      region,
    } = body

    // Validate required fields
    if (!cluster) {
      return NextResponse.json(
        { success: false, error: "Cluster name is required" },
        { status: 400 }
      )
    }

    if (!taskFamily) {
      return NextResponse.json(
        { success: false, error: "Task family name is required" },
        { status: 400 }
      )
    }

    if (!imageUri) {
      return NextResponse.json(
        { success: false, error: "Image URI is required" },
        { status: 400 }
      )
    }

    console.log(`[ECS-DEPLOY] Deploying ${imageUri} to cluster: ${cluster}`)

    // Initialize ECS deployer
    const deployer = new ECSDeployer(region || process.env.AWS_REGION || "us-east-1")

    // Resolve network configuration from request/env/default VPC fallbacks
    const resolvedNetwork = await deployer.resolveNetworkConfiguration({
      cluster,
      serviceName,
      taskFamily,
      imageUri,
      cpu: cpu || "256",
      memory: memory || "512",
      containerPort,
      environment: environment || {},
      desiredCount: desiredCount || 1,
      subnets,
      securityGroups,
      assignPublicIp,
    })

    console.log(`[ECS-DEPLOY] Network config - Subnets: ${resolvedNetwork.subnets.length}, Security Groups: ${resolvedNetwork.securityGroups.length}, Public IP: ${resolvedNetwork.assignPublicIp ? "enabled" : "disabled"}`)

    // Deploy to ECS
    const result = await deployer.deployOptimizedImage({
      cluster,
      serviceName,
      taskFamily,
      imageUri,
      cpu: cpu || "256",
      memory: memory || "512",
      containerPort,
      environment: environment || {},
      desiredCount: desiredCount || 1,
      subnets: resolvedNetwork.subnets,
      securityGroups: resolvedNetwork.securityGroups,
      assignPublicIp: resolvedNetwork.assignPublicIp,
    })

    if (!result.success) {
      return NextResponse.json(
        {
          success: false,
          error: result.error || "Failed to deploy to ECS",
        },
        { status: 500 }
      )
    }

    console.log(`[ECS-DEPLOY] Deployment successful`)

    return NextResponse.json({
      success: true,
      taskDefinitionArn: result.taskDefinitionArn,
      serviceArn: result.serviceArn,
      taskArn: result.taskArn,
      message: serviceName
        ? `Service ${serviceName} updated successfully`
        : `Task started successfully`,
    })
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error"
    console.error("[ECS-DEPLOY] Error:", message)

    return NextResponse.json(
      {
        success: false,
        error: `Failed to deploy to ECS: ${message}`,
      },
      { status: 500 }
    )
  }
}
