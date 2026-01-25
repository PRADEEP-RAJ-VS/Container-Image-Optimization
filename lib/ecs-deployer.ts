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
   * Deploy optimized image to ECS (creates or updates service)
   */
  async deployOptimizedImage(config: ECSDeploymentConfig): Promise<DeploymentResult> {
    try {
      console.log(`[ECS] Starting deployment for ${config.taskFamily}`)

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
