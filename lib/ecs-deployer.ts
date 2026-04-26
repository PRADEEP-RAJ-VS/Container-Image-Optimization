import {
  ECSClient,
  RunTaskCommand,
  DescribeTasksCommand,
  RegisterTaskDefinitionCommand,
  UpdateServiceCommand,
  CreateServiceCommand,
  DescribeServicesCommand,
  ListTasksCommand,
  ListClustersCommand,
  DescribeClustersCommand,
  type Service,
  type Task,
  type Cluster,
  type TaskDefinition,
} from "@aws-sdk/client-ecs"
import { execSync } from "child_process"

export interface ECSDeploymentConfig {
  cluster: string
  serviceName?: string
  taskFamily: string
  imageUri: string
  cpu: string
  memory: string
  containerPort?: number
  environment?: Record<string, string>
  desiredCount?: number
  subnets?: string[]
  securityGroups?: string[]
  assignPublicIp?: boolean
}

export interface ECSNetworkConfiguration {
  subnets: string[]
  securityGroups: string[]
  assignPublicIp: boolean
}

export interface DeploymentResult {
  success: boolean
  taskDefinitionArn?: string
  serviceArn?: string
  taskArn?: string
  error?: string
}

export interface DeploymentStatus {
  status: "PENDING" | "RUNNING" | "STOPPED" | "UNKNOWN"
  taskArn: string
  lastStatus: string
  desiredStatus: string
  startedAt?: Date
  stoppedAt?: Date
  containers: Array<{
    name: string
    status: string
    exitCode?: number
  }>
}

export interface ECSCluster {
  name: string
  arn: string
  status: string
  runningTasks: number
  pendingTasks: number
  activeServices: number
}

/**
 * ECS Deployer for deploying optimized Docker images to Amazon ECS
 */
export class ECSDeployer {
  private client: ECSClient
  private region: string

  constructor(region = "us-east-1") {
    this.region = region
    this.client = new ECSClient({ region })
  }

  /**
   * Resolve ECS network configuration.
   * Uses explicit config first, then environment variables, and finally discovers
   * the default VPC's subnets and the shared ECS security group via AWS CLI.
   */
  async resolveNetworkConfiguration(config: ECSDeploymentConfig): Promise<ECSNetworkConfiguration> {
    const envSubnets = (process.env.ECS_SUBNET_IDS || "")
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean)

    const envSecurityGroups = (process.env.ECS_SECURITY_GROUP_IDS || "")
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean)

    const subnets = config.subnets && config.subnets.length > 0
      ? config.subnets
      : envSubnets.length > 0
        ? envSubnets
        : await this.discoverDefaultSubnetIds()

    const securityGroups = config.securityGroups && config.securityGroups.length > 0
      ? config.securityGroups
      : envSecurityGroups.length > 0
        ? envSecurityGroups
        : [await this.ensureEcsSecurityGroup()]

    const assignPublicIp = config.assignPublicIp !== false && process.env.ECS_ASSIGN_PUBLIC_IP !== "false"

    return { subnets, securityGroups, assignPublicIp }
  }

  /**
   * Deploy optimized image to ECS (creates or updates service)
   */
  async deployOptimizedImage(config: ECSDeploymentConfig): Promise<DeploymentResult> {
    try {
      console.log(`[ECS] Starting deployment for ${config.taskFamily}`)

      const resolvedNetwork = await this.resolveNetworkConfiguration(config)
      config.subnets = resolvedNetwork.subnets
      config.securityGroups = resolvedNetwork.securityGroups
      config.assignPublicIp = resolvedNetwork.assignPublicIp

      console.log(
        `[ECS] Resolved network config - Subnets: ${config.subnets.length}, Security Groups: ${config.securityGroups.length}, Public IP: ${config.assignPublicIp ? "enabled" : "disabled"}`,
      )

      // 1. Register new task definition
      const taskDefArn = await this.registerTaskDefinition(config)
      console.log(`[ECS] Registered task definition: ${taskDefArn}`)

      // 2. Check if service exists
      if (config.serviceName) {
        const serviceExists = await this.serviceExists(config.cluster, config.serviceName)

        if (serviceExists) {
          // Update existing service
          console.log(`[ECS] Updating existing service: ${config.serviceName}`)
          const serviceArn = await this.updateService(config.cluster, config.serviceName, taskDefArn)
          return {
            success: true,
            taskDefinitionArn: taskDefArn,
            serviceArn,
          }
        } else {
          // Create new service
          console.log(`[ECS] Creating new service: ${config.serviceName}`)
          const serviceArn = await this.createService(config, taskDefArn)
          return {
            success: true,
            taskDefinitionArn: taskDefArn,
            serviceArn,
          }
        }
      } else {
        // Run as a standalone task (no service)
        console.log(`[ECS] Running standalone task`)
        const taskArn = await this.runTask(config, taskDefArn)
        return {
          success: true,
          taskDefinitionArn: taskDefArn,
          taskArn,
        }
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown error"
      console.error(`[ECS] Deployment failed:`, message)
      return {
        success: false,
        error: message,
      }
    }
  }

  /**
   * Discover the default VPC subnets using AWS CLI.
   */
  private async discoverDefaultSubnetIds(): Promise<string[]> {
    try {
      console.log(`[ECS] Discovering default VPC subnets in region ${this.region}`)
      const vpcId = this.execAwsText(
        `ec2 describe-vpcs --region ${this.region} --filters Name=isDefault,Values=true --query "Vpcs[0].VpcId" --output text`,
      )

      console.log(`[ECS] Default VPC ID: ${vpcId}`)

      if (!vpcId || vpcId === "None") {
        throw new Error("Unable to determine the default VPC for ECS networking")
      }

      const subnetsRaw = this.execAwsText(
        `ec2 describe-subnets --region ${this.region} --filters Name=vpc-id,Values=${vpcId} --query "Subnets[*].SubnetId" --output text`,
      )

      console.log(`[ECS] Subnets raw output: "${subnetsRaw}"`)

      const subnets = subnetsRaw
        .split(/\s+/)
        .map((value) => value.trim())
        .filter(Boolean)

      console.log(`[ECS] Discovered ${subnets.length} subnets: ${subnets.join(",")}`)

      if (subnets.length === 0) {
        throw new Error(`No subnets found in default VPC ${vpcId}`)
      }

      return subnets
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      console.error(`[ECS] Failed to discover subnets: ${message}`)
      throw error
    }
  }

  /**
   * Ensure a shared ECS security group exists and has the required ingress rules.
   */
  private async ensureEcsSecurityGroup(): Promise<string> {
    try {
      console.log(`[ECS] Ensuring ECS security group in region ${this.region}`)
      const vpcId = this.execAwsText(
        `ec2 describe-vpcs --region ${this.region} --filters Name=isDefault,Values=true --query "Vpcs[0].VpcId" --output text`,
      )

      console.log(`[ECS] Default VPC ID for security group: ${vpcId}`)

      if (!vpcId || vpcId === "None") {
        throw new Error("Unable to determine the default VPC for ECS security group setup")
      }

      const existingGroupId = this.execAwsText(
        `ec2 describe-security-groups --region ${this.region} --filters Name=group-name,Values=docker-optimizer-ecs Name=vpc-id,Values=${vpcId} --query "SecurityGroups[0].GroupId" --output text`,
      )

      console.log(`[ECS] Existing security group query result: "${existingGroupId}"`)

      if (existingGroupId && existingGroupId !== "None") {
        console.log(`[ECS] Using existing security group: ${existingGroupId}`)
        return existingGroupId
      }

      console.log(`[ECS] Creating new security group docker-optimizer-ecs`)
      const createdGroupId = this.execAwsText(
        `ec2 create-security-group --region ${this.region} --group-name docker-optimizer-ecs --description "Security group for Docker Optimizer ECS tasks" --vpc-id ${vpcId} --query "GroupId" --output text`,
      )

      console.log(`[ECS] Created security group: ${createdGroupId}`)

      const ingressRules = [80, 443, 8080, 3000]
      for (const port of ingressRules) {
        try {
          this.execAwsText(
            `ec2 authorize-security-group-ingress --region ${this.region} --group-id ${createdGroupId} --protocol tcp --port ${port} --cidr 0.0.0.0/0 --output text`,
          )
          console.log(`[ECS] Added ingress rule for port ${port}`)
        } catch (error) {
          console.warn(`[ECS] Could not add ingress rule for port ${port}:`, error instanceof Error ? error.message : error)
        }
      }

      return createdGroupId
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      console.error(`[ECS] Failed to ensure security group: ${message}`)
      throw error
    }
  }

  /**
   * Execute an AWS CLI command and return trimmed text output.
   */
  private execAwsText(command: string): string {
    try {
      return execSync(`aws ${command}`, { encoding: "utf-8", stdio: "pipe" }).trim()
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown AWS CLI error"
      throw new Error(`AWS CLI command failed: aws ${command} (${message})`)
    }
  }

  /**
   * Register a new task definition
   */
  private async registerTaskDefinition(config: ECSDeploymentConfig): Promise<string> {
    const containerDefinition = {
      name: config.taskFamily,
      image: config.imageUri,
      essential: true,
      memory: parseInt(config.memory),
      cpu: parseInt(config.cpu),
      environment: Object.entries(config.environment || {}).map(([name, value]) => ({
        name,
        value,
      })),
      logConfiguration: {
        logDriver: "awslogs" as const,
        options: {
          "awslogs-group": `/ecs/${config.taskFamily}`,
          "awslogs-region": this.region,
          "awslogs-stream-prefix": "ecs",
          "awslogs-create-group": "true",
        },
      },
    }

    // Add port mappings if containerPort is specified
    if (config.containerPort) {
      Object.assign(containerDefinition, {
        portMappings: [
          {
            containerPort: config.containerPort,
            protocol: "tcp",
          },
        ],
      })
    }

    const command = new RegisterTaskDefinitionCommand({
      family: config.taskFamily,
      cpu: config.cpu,
      memory: config.memory,
      networkMode: "awsvpc",
      requiresCompatibilities: ["FARGATE"],
      executionRoleArn: `arn:aws:iam::${await this.getAccountId()}:role/ecsTaskExecutionRole`,
      containerDefinitions: [containerDefinition],
    })

    const response = await this.client.send(command)
    return response.taskDefinition!.taskDefinitionArn!
  }

  /**
   * Create a new ECS service
   */
  private async createService(config: ECSDeploymentConfig, taskDefinitionArn: string): Promise<string> {
    const networkConfiguration = {
      awsvpcConfiguration: {
        subnets: config.subnets || [],
        securityGroups: config.securityGroups || [],
        assignPublicIp: config.assignPublicIp ? "ENABLED" : "DISABLED",
      },
    }

    const command = new CreateServiceCommand({
      cluster: config.cluster,
      serviceName: config.serviceName!,
      taskDefinition: taskDefinitionArn,
      desiredCount: config.desiredCount || 1,
      launchType: "FARGATE",
      networkConfiguration: networkConfiguration as any,
    })

    const response = await this.client.send(command)
    return response.service!.serviceArn!
  }

  /**
   * Update an existing ECS service
   */
  private async updateService(cluster: string, serviceName: string, taskDefinition: string): Promise<string> {
    const command = new UpdateServiceCommand({
      cluster,
      service: serviceName,
      taskDefinition,
      forceNewDeployment: true,
    })

    const response = await this.client.send(command)
    return response.service!.serviceArn!
  }

  /**
   * Run a standalone ECS task (no service)
   */
  private async runTask(config: ECSDeploymentConfig, taskDefinitionArn: string): Promise<string> {
    const networkConfiguration = {
      awsvpcConfiguration: {
        subnets: config.subnets || [],
        securityGroups: config.securityGroups || [],
        assignPublicIp: config.assignPublicIp ? "ENABLED" : "DISABLED",
      },
    }

    const command = new RunTaskCommand({
      cluster: config.cluster,
      taskDefinition: taskDefinitionArn,
      launchType: "FARGATE",
      networkConfiguration: networkConfiguration as any,
      count: config.desiredCount || 1,
    })

    const response = await this.client.send(command)
    return response.tasks?.[0]?.taskArn || ""
  }

  /**
   * Check if a service exists
   */
  private async serviceExists(cluster: string, serviceName: string): Promise<boolean> {
    try {
      const command = new DescribeServicesCommand({
        cluster,
        services: [serviceName],
      })

      const response = await this.client.send(command)
      const service = response.services?.[0]

      return service !== undefined && service.status !== "INACTIVE"
    } catch {
      return false
    }
  }

  /**
   * Get deployment status for a task
   */
  async getTaskStatus(cluster: string, taskArn: string): Promise<DeploymentStatus> {
    try {
      const command = new DescribeTasksCommand({
        cluster,
        tasks: [taskArn],
      })

      const response = await this.client.send(command)
      const task = response.tasks?.[0]

      if (!task) {
        return {
          status: "UNKNOWN",
          taskArn,
          lastStatus: "UNKNOWN",
          desiredStatus: "UNKNOWN",
          containers: [],
        }
      }

      const status = this.mapTaskStatus(task.lastStatus || "UNKNOWN")
      const containers = (task.containers || []).map((c) => ({
        name: c.name || "unknown",
        status: c.lastStatus || "unknown",
        exitCode: c.exitCode,
      }))

      return {
        status,
        taskArn,
        lastStatus: task.lastStatus || "UNKNOWN",
        desiredStatus: task.desiredStatus || "UNKNOWN",
        startedAt: task.startedAt,
        stoppedAt: task.stoppedAt,
        containers,
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown error"
      throw new Error(`Failed to get task status: ${message}`)
    }
  }

  /**
   * List all ECS clusters
   */
  async listClusters(): Promise<ECSCluster[]> {
    try {
      // Get cluster ARNs
      const listCommand = new ListClustersCommand({})
      const listResponse = await this.client.send(listCommand)

      if (!listResponse.clusterArns || listResponse.clusterArns.length === 0) {
        return []
      }

      // Get detailed cluster information
      const describeCommand = new DescribeClustersCommand({
        clusters: listResponse.clusterArns,
        include: ["STATISTICS"],
      })

      const describeResponse = await this.client.send(describeCommand)

      return (describeResponse.clusters || []).map((cluster) => ({
        name: cluster.clusterName!,
        arn: cluster.clusterArn!,
        status: cluster.status || "UNKNOWN",
        runningTasks: cluster.runningTasksCount || 0,
        pendingTasks: cluster.pendingTasksCount || 0,
        activeServices: cluster.activeServicesCount || 0,
      }))
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown error"
      throw new Error(`Failed to list clusters: ${message}`)
    }
  }

  /**
   * List services in a cluster
   */
  async listServices(cluster: string): Promise<Service[]> {
    try {
      const command = new DescribeServicesCommand({
        cluster,
        services: [], // Empty array to get all services
      })

      const response = await this.client.send(command)
      return response.services || []
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown error"
      throw new Error(`Failed to list services: ${message}`)
    }
  }

  /**
   * Map ECS task status to simplified status
   */
  private mapTaskStatus(status: string): "PENDING" | "RUNNING" | "STOPPED" | "UNKNOWN" {
    const upperStatus = status.toUpperCase()

    if (upperStatus === "RUNNING") return "RUNNING"
    if (upperStatus === "STOPPED") return "STOPPED"
    if (["PENDING", "PROVISIONING", "ACTIVATING"].includes(upperStatus)) return "PENDING"

    return "UNKNOWN"
  }

  /**
   * Get AWS account ID (needed for IAM role ARN)
   */
  private async getAccountId(): Promise<string> {
    // In a real implementation, you'd use STS to get the account ID
    // For now, we'll extract it from the cluster ARN
    try {
      const clusters = await this.listClusters()
      if (clusters.length > 0) {
        const arnParts = clusters[0].arn.split(":")
        return arnParts[4] // Account ID is the 5th element
      }
    } catch {
      // Fallback: return a placeholder that will be replaced
    }

    // Return a placeholder - the user will need to configure this
    return "YOUR_ACCOUNT_ID"
  }
}
