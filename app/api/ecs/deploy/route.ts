import { NextRequest, NextResponse } from "next/server"
import { ECSDeployer } from "@/lib/ecs-deployer"

/**
 * POST /api/ecs/deploy
 * Deploy Docker image to ECS
 */
export async function POST(request: NextRequest) {
  try {
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

    // Get network configuration from environment if not provided
    const ecsSubnets = subnets && subnets.length > 0 
      ? subnets 
      : (process.env.ECS_SUBNET_IDS || "").split(",").filter(s => s.trim())
    
    const ecsSecurityGroups = securityGroups && securityGroups.length > 0
      ? securityGroups
      : (process.env.ECS_SECURITY_GROUP_IDS || "").split(",").filter(s => s.trim())
    
    const ecsAssignPublicIp = assignPublicIp !== false && (process.env.ECS_ASSIGN_PUBLIC_IP !== "false")

    console.log(`[ECS-DEPLOY] Network config - Subnets: ${ecsSubnets.length}, Security Groups: ${ecsSecurityGroups.length}`)

    if (ecsSubnets.length === 0) {
      return NextResponse.json(
        { 
          success: false, 
          error: "No subnets configured. Please configure ECS_SUBNET_IDS in .env.local" 
        },
        { status: 400 }
      )
    }

    if (ecsSecurityGroups.length === 0) {
      return NextResponse.json(
        { 
          success: false, 
          error: "No security groups configured. Please configure ECS_SECURITY_GROUP_IDS in .env.local" 
        },
        { status: 400 }
      )
    }

    // Initialize ECS deployer
    const deployer = new ECSDeployer(region || process.env.AWS_REGION || "us-east-1")

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
      subnets: ecsSubnets,
      securityGroups: ecsSecurityGroups,
      assignPublicIp: ecsAssignPublicIp,
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
