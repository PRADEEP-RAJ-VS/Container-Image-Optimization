import {
  ECRClient,
  GetAuthorizationTokenCommand,
  DescribeRepositoriesCommand,
  CreateRepositoryCommand,
  DescribeImagesCommand,
  BatchDeleteImageCommand,
  PutImageCommand,
  type Repository,
  type ImageIdentifier,
} from "@aws-sdk/client-ecr"
import { execSync } from "child_process"
import { writeFileSync, unlinkSync, existsSync } from "fs"
import path from "path"
import { tmpdir } from "os"

export interface ECRCredentials {
  username: string
  password: string
  registry: string
  expiresAt: Date
}

export interface ECRRepository {
  name: string
  uri: string
  createdAt: Date
  imageCount: number
}

export interface ECRImage {
  tag: string
  digest: string
  sizeInBytes: number
  pushedAt: Date
}

export interface PushImageOptions {
  imageName: string
  imageTag: string
  tarBuffer: Buffer
  repositoryName: string
  region?: string
}

export interface PushResult {
  success: boolean
  imageUri: string
  digest?: string
  error?: string
}

/**
 * ECR Client for managing Docker images in Amazon Elastic Container Registry
 */
export class ECRManager {
  private client: ECRClient
  private region: string
  private accountId?: string

  constructor(region = "us-east-1") {
    this.region = region
    this.client = new ECRClient({ region })
  }

  /**
   * Get ECR authentication token and credentials
   */
  async getAuthToken(): Promise<ECRCredentials> {
    try {
      const command = new GetAuthorizationTokenCommand({})
      const response = await this.client.send(command)

      const authData = response.authorizationData?.[0]
      if (!authData || !authData.authorizationToken) {
        throw new Error("No ECR authorization data returned from AWS")
      }

      const token = Buffer.from(authData.authorizationToken, "base64").toString()
      const [username, password] = token.split(":")

      // Extract account ID from registry URL
      const registryUrl = authData.proxyEndpoint?.replace("https://", "") || ""
      this.accountId = registryUrl.split(".")[0]

      return {
        username,
        password,
        registry: registryUrl,
        expiresAt: authData.expiresAt || new Date(Date.now() + 12 * 60 * 60 * 1000),
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown error"
      throw new Error(`Failed to get ECR auth token: ${message}`)
    }
  }

  /**
   * Create a new ECR repository if it doesn't exist
   */
  async createRepository(name: string): Promise<Repository> {
    try {
      const command = new CreateRepositoryCommand({
        repositoryName: name,
        imageScanningConfiguration: {
          scanOnPush: true, // Enable automatic Trivy scanning in ECR
        },
        encryptionConfiguration: {
          encryptionType: "AES256",
        },
      })

      const response = await this.client.send(command)
      console.log(`[ECR] Created repository: ${name}`)
      return response.repository!
    } catch (error: any) {
      if (error.name === "RepositoryAlreadyExistsException") {
        console.log(`[ECR] Repository already exists: ${name}`)
        return await this.getRepository(name)
      }
      throw new Error(`Failed to create repository: ${error.message}`)
    }
  }

  /**
   * Get repository details
   */
  async getRepository(name: string): Promise<Repository> {
    const command = new DescribeRepositoriesCommand({
      repositoryNames: [name],
    })

    const response = await this.client.send(command)
    if (!response.repositories || response.repositories.length === 0) {
      throw new Error(`Repository not found: ${name}`)
    }

    return response.repositories[0]
  }

  /**
   * List all ECR repositories
   */
  async listRepositories(): Promise<ECRRepository[]> {
    try {
      const command = new DescribeRepositoriesCommand({})
      const response = await this.client.send(command)

      const repositories: ECRRepository[] = []

      for (const repo of response.repositories || []) {
        // Get image count for each repository
        const images = await this.listImages(repo.repositoryName!)

        repositories.push({
          name: repo.repositoryName!,
          uri: repo.repositoryUri!,
          createdAt: repo.createdAt || new Date(),
          imageCount: images.length,
        })
      }

      return repositories
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown error"
      throw new Error(`Failed to list repositories: ${message}`)
    }
  }

  /**
   * List images in a repository
   */
  async listImages(repositoryName: string): Promise<ECRImage[]> {
    try {
      const command = new DescribeImagesCommand({
        repositoryName,
      })

      const response = await this.client.send(command)
      const images: ECRImage[] = []

      for (const image of response.imageDetails || []) {
        const tag = image.imageTags?.[0] || "untagged"
        images.push({
          tag,
          digest: image.imageDigest!,
          sizeInBytes: image.imageSizeInBytes || 0,
          pushedAt: image.imagePushedAt || new Date(),
        })
      }

      return images.sort((a, b) => b.pushedAt.getTime() - a.pushedAt.getTime())
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown error"
      throw new Error(`Failed to list images: ${message}`)
    }
  }

  /**
   * Push Docker image to ECR from tar buffer
   */
  async pushImageToECR(options: PushImageOptions): Promise<PushResult> {
    const { imageName, imageTag, tarBuffer, repositoryName, region = this.region } = options
    const tempDir = path.join(tmpdir(), `ecr-push-${Date.now()}`)
    const tarPath = path.join(tempDir, "image.tar")

    try {
      // Check Docker availability
      try {
        execSync("docker --version", { stdio: "pipe" })
      } catch {
        return {
          success: false,
          imageUri: "",
          error: "Docker is not installed or not running. Please start Docker Desktop.",
        }
      }

      // Create temp directory
      if (!existsSync(tempDir)) {
        require("fs").mkdirSync(tempDir, { recursive: true })
      }

      // Write tar to temp file
      writeFileSync(tarPath, tarBuffer)
      console.log(`[ECR] Wrote image tar to: ${tarPath}`)

      // Get ECR credentials
      const creds = await this.getAuthToken()
      console.log(`[ECR] Got auth token for registry: ${creds.registry}`)

      // Ensure repository exists
      await this.createRepository(repositoryName)

      // Load image into Docker
      console.log(`[ECR] Loading image into Docker...`)
      const loadOutput = execSync(`docker load -i "${tarPath}"`, { 
        encoding: "utf-8",
        stdio: "pipe" 
      })
      
      console.log(`[ECR] Docker load output: ${loadOutput}`)

      // Extract image ID from load output (works on all platforms)
      // Output format: "Loaded image: <image>:<tag>" or "Loaded image ID: sha256:..."
      let imageId = ""
      const idMatch = loadOutput.match(/Loaded image ID: sha256:([a-f0-9]+)/)
      const nameMatch = loadOutput.match(/Loaded image: (.+)/)
      
      if (idMatch) {
        imageId = `sha256:${idMatch[1]}`
      } else if (nameMatch) {
        // If we got an image name, get its ID
        imageId = execSync(`docker images -q "${nameMatch[1]}"`, {
          encoding: "utf-8",
          stdio: "pipe",
        }).trim().split('\n')[0]
      } else {
        // Fallback: get the most recent image
        const images = execSync(`docker images -q`, {
          encoding: "utf-8",
          stdio: "pipe",
        }).trim()
        imageId = images.split('\n')[0]
      }

      if (!imageId) {
        throw new Error("Failed to load image into Docker")
      }
      
      console.log(`[ECR] Loaded image ID: ${imageId}`)

      // Tag for ECR
      const ecrImageUri = `${creds.registry}/${repositoryName}:${imageTag}`
      console.log(`[ECR] Tagging image as: ${ecrImageUri}`)
      execSync(`docker tag ${imageId} ${ecrImageUri}`, { stdio: "pipe" })

      // Login to ECR
      console.log(`[ECR] Logging in to ECR...`)
      if (process.platform === "win32") {
        execSync(`echo ${creds.password} | docker login -u ${creds.username} --password-stdin ${creds.registry}`, {
          stdio: "pipe",
          shell: "powershell.exe",
        })
      } else {
        execSync(`echo "${creds.password}" | docker login -u ${creds.username} --password-stdin ${creds.registry}`, {
          stdio: "pipe",
        })
      }

      // Push to ECR
      console.log(`[ECR] Pushing image to ECR...`)
      const pushOutput = execSync(`docker push ${ecrImageUri}`, {
        encoding: "utf-8",
        stdio: "pipe",
      })

      // Extract digest from push output
      const digestMatch = pushOutput.match(/digest: (sha256:[a-f0-9]{64})/)
      const digest = digestMatch ? digestMatch[1] : undefined

      console.log(`[ECR] Successfully pushed image: ${ecrImageUri}`)

      return {
        success: true,
        imageUri: ecrImageUri,
        digest,
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown error"
      console.error(`[ECR] Push failed:`, message)
      return {
        success: false,
        imageUri: "",
        error: message,
      }
    } finally {
      // Cleanup
      try {
        if (existsSync(tarPath)) unlinkSync(tarPath)
        if (existsSync(tempDir)) require("fs").rmSync(tempDir, { recursive: true, force: true })
      } catch {
        // Ignore cleanup errors
      }
    }
  }

  /**
   * Delete an image from ECR
   */
  async deleteImage(repositoryName: string, imageTag: string): Promise<void> {
    try {
      const imageIds: ImageIdentifier[] = [{ imageTag }]

      const command = new BatchDeleteImageCommand({
        repositoryName,
        imageIds,
      })

      await this.client.send(command)
      console.log(`[ECR] Deleted image: ${repositoryName}:${imageTag}`)
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown error"
      throw new Error(`Failed to delete image: ${message}`)
    }
  }

  /**
   * Get the ECR registry URL for this account
   */
  async getRegistryUrl(): Promise<string> {
    if (this.accountId) {
      return `${this.accountId}.dkr.ecr.${this.region}.amazonaws.com`
    }

    const creds = await this.getAuthToken()
    return creds.registry
  }
}
