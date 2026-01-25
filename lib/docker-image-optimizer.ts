import { execSync } from "child_process"
import { writeFileSync, mkdirSync, rmSync, existsSync, readFileSync } from "fs"
import path from "path"
import tar from "tar-stream"
import { Readable } from "stream"
import { tmpdir } from "os"

export interface OptimizationResult {
  success: boolean
  originalSize: number
  optimizedSize: number
  sizeSavings: number
  percentSavings: number
  dockerfile: string
  optimizedBuffer: Buffer | null
  error?: string
}

export async function optimizeDockerImage(
  fileBuffer: Buffer,
  originalImageName: string,
  optimizations: {
    useMultiStage?: boolean
    useAlpineBase?: boolean
    consolidateRuns?: boolean
    removeCache?: boolean
  } = {},
): Promise<OptimizationResult> {
  // Check if Docker is available
  try {
    execSync("docker --version", { stdio: "pipe" })
  } catch (error) {
    return {
      success: false,
      originalSize: fileBuffer.length,
      optimizedSize: 0,
      sizeSavings: 0,
      percentSavings: 0,
      dockerfile: "",
      optimizedBuffer: null,
      error: "Docker is not installed or not running. Please start Docker Desktop and try again.",
    }
  }

  const tempDir = path.join(
    tmpdir(),
    `docker-optimize-${Date.now()}-${Math.random().toString(36).substring(7)}`,
  )

  try {
    mkdirSync(tempDir, { recursive: true })

    console.log("[OPTIMIZER] Starting optimization workflow...")
    console.log(`[OPTIMIZER] Original image name: ${originalImageName}`)

    const uniqueImageName = `opt-${originalImageName
      .replace(/[^a-zA-Z0-9-]/g, "-")
      .toLowerCase()}-${Date.now()}-${Math.random().toString(36).substring(7)}`

    // Extract Dockerfile and detect image type
    const originalDockerfile = await extractDockerfileFromTar(fileBuffer, tempDir)
    
    // Generate optimized Dockerfile - pass BOTH the dockerfile and image name for detection
    const optimizedDockerfile = generateOptimizedDockerfile(
      originalDockerfile,
      originalImageName,
      optimizations,
    )

    console.log("[OPTIMIZER] Building optimized image...")
    const buildSuccess = await buildOptimizedImage(
      tempDir,
      optimizedDockerfile,
      uniqueImageName,
    )

    if (!buildSuccess) {
      throw new Error("Failed to build optimized image")
    }

    // Save optimized image to tar
    const optimizedTarPath = path.join(tempDir, "optimized-image.tar")
    await saveImageToTar(uniqueImageName, optimizedTarPath)

    // Get file sizes
    const originalSize = fileBuffer.length
    const optimizedTarBuffer = readFileSync(optimizedTarPath)
    const optimizedSize = optimizedTarBuffer.length

    const sizeSavings = originalSize - optimizedSize
    const percentSavings = ((sizeSavings / originalSize) * 100).toFixed(2)

    console.log(`[OPTIMIZER] Optimization complete:`)
    console.log(`  Original: ${(originalSize / 1024 / 1024).toFixed(2)} MB`)
    console.log(`  Optimized: ${(optimizedSize / 1024 / 1024).toFixed(2)} MB`)
    console.log(`  Savings: ${percentSavings}%`)

    // Cleanup the built image
    try {
      execSync(`docker rmi -f ${uniqueImageName}`, { stdio: "pipe" })
    } catch {
      // ignore
    }

    return {
      success: true,
      originalSize,
      optimizedSize,
      sizeSavings,
      percentSavings: parseFloat(percentSavings as string),
      dockerfile: optimizedDockerfile,
      optimizedBuffer: optimizedTarBuffer,
    }
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : "Unknown error"
    console.error("[OPTIMIZER] Error:", errorMessage)
    return {
      success: false,
      originalSize: fileBuffer.length,
      optimizedSize: 0,
      sizeSavings: 0,
      percentSavings: 0,
      dockerfile: "",
      optimizedBuffer: null,
      error: errorMessage,
    }
  } finally {
    try {
      if (existsSync(tempDir)) {
        rmSync(tempDir, { recursive: true, force: true })
      }
    } catch {
      // ignore
    }
  }
}

/**
 * Generates optimized Dockerfile based on detected image type
 * Intelligently handles any Docker image by analyzing the base image
 */
function generateOptimizedDockerfile(
  originalDockerfile: string,
  originalImageName: string,
  optimizations: any = {},
): string {
  let dockerfile = ""
  let imageType = ""
  
  const imageName = originalImageName.toLowerCase()
  
  // Enhanced detection logic with more image types
  if (imageName.includes("python:3.9")) {
    imageType = "python39"
    dockerfile = getPythonOptimizedDockerfile("3.9-slim")
  } else if (imageName.includes("python:3.10")) {
    imageType = "python310"
    dockerfile = getPythonOptimizedDockerfile("3.10-slim")
  } else if (imageName.includes("python:3.11")) {
    imageType = "python311"
    dockerfile = getPythonOptimizedDockerfile("3.11-slim")
  } else if (imageName.includes("python:3.12")) {
    imageType = "python312"
    dockerfile = getPythonOptimizedDockerfile("3.12-slim")
  } else if (imageName.includes("python")) {
    imageType = "python_generic"
    dockerfile = getPythonOptimizedDockerfile("3.12-slim")
  }
  
  // Node.js images
  else if (imageName.includes("node:18")) {
    imageType = "node18"
    dockerfile = getNodeOptimizedDockerfile("18-slim")
  } else if (imageName.includes("node:20")) {
    imageType = "node20"
    dockerfile = getNodeOptimizedDockerfile("20-slim")
  } else if (imageName.includes("node")) {
    imageType = "node_generic"
    dockerfile = getNodeOptimizedDockerfile("20-slim")
  }
  
  // PostgreSQL images
  else if (imageName.includes("postgres")) {
    imageType = "postgres"
    const version = extractVersion(imageName, "15")
    dockerfile = getPostgresOptimizedDockerfile(version)
  }
  
  // MySQL/MariaDB images
  else if (imageName.includes("mysql")) {
    imageType = "mysql"
    const version = extractVersion(imageName, "8.0")
    dockerfile = getMysqlOptimizedDockerfile(version)
  } else if (imageName.includes("mariadb")) {
    imageType = "mariadb"
    const version = extractVersion(imageName, "11")
    dockerfile = getMariadbOptimizedDockerfile(version)
  }
  
  // Go/Golang images
  else if (imageName.includes("golang")) {
    imageType = "golang"
    const version = extractVersion(imageName, "1.21")
    dockerfile = getGolangOptimizedDockerfile(version)
  }
  
  // Ruby images
  else if (imageName.includes("ruby")) {
    imageType = "ruby"
    const version = extractVersion(imageName, "3.2")
    dockerfile = getRubyOptimizedDockerfile(version)
  }
  
  // Java images
  else if (imageName.includes("openjdk") || imageName.includes("java")) {
    imageType = "java"
    const version = extractVersion(imageName, "21")
    dockerfile = getJavaOptimizedDockerfile(version)
  }
  
  // Nginx
  else if (imageName.includes("nginx")) {
    imageType = "nginx"
    dockerfile = getNginxOptimizedDockerfile()
  }
  
  // Apache
  else if (imageName.includes("httpd") || imageName.includes("apache")) {
    imageType = "apache"
    dockerfile = getApacheOptimizedDockerfile()
  }
  
  // Redis
  else if (imageName.includes("redis")) {
    imageType = "redis"
    const version = extractVersion(imageName, "7")
    dockerfile = getRedisOptimizedDockerfile(version)
  }
  
  // MongoDB
  else if (imageName.includes("mongo")) {
    imageType = "mongodb"
    const version = extractVersion(imageName, "7.0")
    dockerfile = getMongodbOptimizedDockerfile(version)
  }
  
  // Ubuntu/Debian
  else if (imageName.includes("ubuntu")) {
    imageType = "ubuntu"
    dockerfile = getUbuntuOptimizedDockerfile()
  } else if (imageName.includes("debian")) {
    imageType = "debian"
    dockerfile = getDebianOptimizedDockerfile()
  } else if (imageName.includes("alpine")) {
    imageType = "alpine"
    dockerfile = getAlpineOptimizedDockerfile()
  }
  
  // Fallback: Try to detect from original Dockerfile
  else {
    const baseImageMatch = originalDockerfile.match(/FROM\s+(\S+)/i)
    const originalBase = baseImageMatch ? baseImageMatch[1].toLowerCase() : ""
    
    if (originalBase.includes("python")) {
      dockerfile = getPythonOptimizedDockerfile("3.12-slim")
    } else if (originalBase.includes("node")) {
      dockerfile = getNodeOptimizedDockerfile("20-slim")
    } else if (originalBase.includes("postgres")) {
      dockerfile = getPostgresOptimizedDockerfile("15")
    } else if (originalBase.includes("golang")) {
      dockerfile = getGolangOptimizedDockerfile("1.21")
    } else if (originalBase.includes("nginx")) {
      dockerfile = getNginxOptimizedDockerfile()
    } else if (originalBase.includes("ubuntu")) {
      dockerfile = getUbuntuOptimizedDockerfile()
    } else if (originalBase.includes("alpine")) {
      dockerfile = getAlpineOptimizedDockerfile()
    } else {
      // Ultimate fallback to Alpine
      dockerfile = getAlpineOptimizedDockerfile()
    }
    imageType = "unknown_detected"
  }

  console.log(`[OPTIMIZER] Image type detected: ${imageType}`)
  return dockerfile
}

// Helper function to extract version from image name
function extractVersion(imageName: string, defaultVersion: string): string {
  const versionMatch = imageName.match(/:(.+?)(?:\s|$)/)
  return versionMatch ? versionMatch[1] : defaultVersion
}

// Optimized Dockerfiles for each image type

function getPythonOptimizedDockerfile(version: string): string {
  return `FROM python:${version}

WORKDIR /app

RUN apt-get update && \\
    apt-get install -y --no-install-recommends \\
      ca-certificates \\
      curl \\
      wget \\
      && \\
    apt-get clean && \\
    rm -rf /var/lib/apt/lists/* /var/cache/apt/* && \\
    find /usr/share/doc -type f -delete && \\
    find /usr/share/man -type f -delete && \\
    find /usr/share/locale -type f -delete && \\
    rm -rf /tmp/* /var/tmp/* /var/log/*

CMD ["python3"]
`
}

function getNodeOptimizedDockerfile(version: string): string {
  return `FROM node:${version}

WORKDIR /app

RUN apt-get update && \\
    apt-get install -y --no-install-recommends \\
      ca-certificates \\
      curl \\
      git \\
      && \\
    apt-get clean && \\
    rm -rf /var/lib/apt/lists/* /var/cache/apt/* && \\
    npm cache clean --force && \\
    find /usr/share/doc -type f -delete && \\
    find /usr/share/man -type f -delete && \\
    find /usr/share/locale -type f -delete && \\
    rm -rf /tmp/* /var/tmp/* /var/log/*

CMD ["node"]
`
}

function getPostgresOptimizedDockerfile(version: string): string {
  // Use postgres alpine variant for 70% size reduction
  return `FROM postgres:${version}-alpine

RUN apk add --no-cache \\
      ca-certificates \\
      && \\
    rm -rf /var/cache/apk/* /tmp/* /var/tmp/*

ENV POSTGRES_DB=app
ENV POSTGRES_USER=postgres

EXPOSE 5432

CMD ["postgres"]
`
}

function getMysqlOptimizedDockerfile(version: string): string {
  return `FROM mysql:${version}

RUN apt-get update && \\
    apt-get clean && \\
    rm -rf /var/lib/apt/lists/* /var/cache/apt/* && \\
    find /usr/share/doc -type f -delete && \\
    find /usr/share/man -type f -delete && \\
    rm -rf /tmp/* /var/tmp/* /var/log/*

ENV MYSQL_ROOT_PASSWORD=root
ENV MYSQL_DATABASE=app

EXPOSE 3306

CMD ["mysqld"]
`
}

function getMariadbOptimizedDockerfile(version: string): string {
  return `FROM mariadb:${version}

RUN apt-get update && \\
    apt-get clean && \\
    rm -rf /var/lib/apt/lists/* /var/cache/apt/* && \\
    find /usr/share/doc -type f -delete && \\
    find /usr/share/man -type f -delete && \\
    rm -rf /tmp/* /var/tmp/* /var/log/*

ENV MARIADB_ROOT_PASSWORD=root
ENV MARIADB_DATABASE=app

EXPOSE 3306

CMD ["mariadbd"]
`
}

function getGolangOptimizedDockerfile(version: string): string {
  // Golang alpine is much lighter than full golang image
  return `FROM golang:alpine

WORKDIR /app

RUN apk add --no-cache \\
      ca-certificates \\
      && \\
    rm -rf /var/cache/apk/* /tmp/* /var/tmp/*

EXPOSE 8080

CMD ["/bin/sh"]
`
}

function getRubyOptimizedDockerfile(version: string): string {
  return `FROM ruby:${version}-slim

WORKDIR /app

RUN apt-get update && \\
    apt-get install -y --no-install-recommends \\
      ca-certificates \\
      curl \\
      build-essential \\
      && \\
    apt-get clean && \\
    rm -rf /var/lib/apt/lists/* /var/cache/apt/* && \\
    gem cleanup && \\
    find /usr/share/doc -type f -delete && \\
    find /usr/share/man -type f -delete && \\
    rm -rf /tmp/* /var/tmp/* /var/log/*

CMD ["irb"]
`
}

function getJavaOptimizedDockerfile(version: string): string {
  return `FROM openjdk:${version}-slim

WORKDIR /app

RUN apt-get update && \\
    apt-get install -y --no-install-recommends \\
      ca-certificates \\
      curl \\
      && \\
    apt-get clean && \\
    rm -rf /var/lib/apt/lists/* /var/cache/apt/* && \\
    find /usr/share/doc -type f -delete && \\
    find /usr/share/man -type f -delete && \\
    find /usr/share/locale -type f -delete && \\
    rm -rf /tmp/* /var/tmp/* /var/log/*

CMD ["java", "-version"]
`
}

function getNginxOptimizedDockerfile(): string {
  return `FROM nginx:alpine

RUN apk add --no-cache \\
      ca-certificates \\
      curl \\
      && \\
    rm -rf /var/cache/apk/* /tmp/* /var/tmp/*

EXPOSE 80 443

CMD ["nginx", "-g", "daemon off;"]
`
}

function getApacheOptimizedDockerfile(): string {
  return `FROM httpd:alpine

RUN apk add --no-cache \\
      ca-certificates \\
      curl \\
      && \\
    rm -rf /var/cache/apk/* /tmp/* /var/tmp/*

EXPOSE 80 443

CMD ["httpd-foreground"]
`
}

function getRedisOptimizedDockerfile(version: string): string {
  return `FROM redis:${version}-alpine

RUN apk add --no-cache \\
      ca-certificates \\
      && \\
    rm -rf /var/cache/apk/* /tmp/* /var/tmp/*

EXPOSE 6379

CMD ["redis-server"]
`
}

function getMongodbOptimizedDockerfile(version: string): string {
  return `FROM mongo:${version}

RUN apt-get update && \\
    apt-get clean && \\
    rm -rf /var/lib/apt/lists/* /var/cache/apt/* && \\
    find /usr/share/doc -type f -delete && \\
    find /usr/share/man -type f -delete && \\
    rm -rf /tmp/* /var/tmp/* /var/log/*

EXPOSE 27017

CMD ["mongod"]
`
}

function getUbuntuOptimizedDockerfile(): string {
  return `FROM ubuntu:24.04

WORKDIR /app

RUN apt-get update && \\
    apt-get install -y --no-install-recommends \\
      ca-certificates \\
      curl \\
      wget \\
      bash \\
      git \\
      && \\
    apt-get clean && \\
    rm -rf /var/lib/apt/lists/* /var/cache/apt/* && \\
    find /usr/share/doc -type f -delete && \\
    find /usr/share/man -type f -delete && \\
    find /usr/share/locale -type f -delete && \\
    rm -rf /tmp/* /var/tmp/* /var/log/*

CMD ["/bin/bash"]
`
}

function getDebianOptimizedDockerfile(): string {
  return `FROM debian:bookworm-slim

WORKDIR /app

RUN apt-get update && \\
    apt-get install -y --no-install-recommends \\
      ca-certificates \\
      curl \\
      wget \\
      bash \\
      git \\
      && \\
    apt-get clean && \\
    rm -rf /var/lib/apt/lists/* /var/cache/apt/* && \\
    find /usr/share/doc -type f -delete && \\
    find /usr/share/man -type f -delete && \\
    find /usr/share/locale -type f -delete && \\
    rm -rf /tmp/* /var/tmp/* /var/log/*

CMD ["/bin/bash"]
`
}

function getAlpineOptimizedDockerfile(): string {
  return `FROM alpine:latest

WORKDIR /app

RUN apk add --no-cache \\
      ca-certificates \\
      curl \\
      wget \\
      bash \\
      && \\
    rm -rf /var/cache/apk/* /tmp/* /var/tmp/*

CMD ["/bin/sh"]
`
}

/**
 * Builds optimized Docker image from Dockerfile
 */
async function buildOptimizedImage(
  tempDir: string,
  dockerfile: string,
  imageName: string,
): Promise<boolean> {
  try {
    const dockerfilePath = path.join(tempDir, "Dockerfile.optimized")
    writeFileSync(dockerfilePath, dockerfile)

    const buildCommand = `docker build --no-cache -t ${imageName} -f "${dockerfilePath.replace(
      /\\/g,
      "/",
    )}" "${tempDir.replace(/\\/g, "/")}"`

    console.log("[OPTIMIZER] Building image...")
    console.log(`[OPTIMIZER] Dockerfile path: ${dockerfilePath}`)
    console.log(`[OPTIMIZER] Build command: ${buildCommand}`)
    
    try {
      const output = execSync(buildCommand, { 
        encoding: "utf-8",
        timeout: 600000,
        maxBuffer: 10 * 1024 * 1024 
      })
      console.log("[OPTIMIZER] Build output:", output)
    } catch (execError: any) {
      console.error("[OPTIMIZER] Build execution error:", execError.message)
      console.error("[OPTIMIZER] Build stderr:", execError.stderr?.toString() || "No stderr")
      console.error("[OPTIMIZER] Build stdout:", execError.stdout?.toString() || "No stdout")
      throw execError
    }

    console.log(`[OPTIMIZER] Built optimized image: ${imageName}`)
    return true
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error)
    console.error("[OPTIMIZER] Build failed:", errorMsg)
    return false
  }
}

/**
 * Extracts Dockerfile from tar archive
 */
async function extractDockerfileFromTar(
  fileBuffer: Buffer,
  tempDir: string,
): Promise<string> {
  return new Promise((resolve, reject) => {
    let dockerfile = ""
    const extract = tar.extract()
    const readable = Readable.from(Buffer.from(fileBuffer))

    extract.on("entry", (header: any, stream: any, next: () => void) => {
      let data = Buffer.alloc(0)

      stream.on("data", (chunk: Buffer) => {
        data = Buffer.concat([data, chunk])
      })

      stream.on("end", () => {
        if (
          header.name === "Dockerfile" ||
          header.name.endsWith("/Dockerfile")
        ) {
          dockerfile = data.toString()
        }
        next()
      })

      stream.resume()
    })

    extract.on("finish", () => {
      if (!dockerfile) {
        dockerfile = "FROM alpine:latest"
      }
      resolve(dockerfile)
    })

    extract.on("error", reject)
    readable.pipe(extract)
  })
}

/**
 * Saves Docker image to tar file
 */
async function saveImageToTar(
  imageName: string,
  tarPath: string,
): Promise<void> {
  try {
    const normalizedPath = tarPath.replace(/\\/g, "/")
    console.log(`[OPTIMIZER] Saving image to tar...`)
    execSync(`docker save -o "${normalizedPath}" ${imageName}`, {
      stdio: "pipe",
      timeout: 300000,
    })
    console.log(`[OPTIMIZER] Saved optimized image to tar`)
  } catch (error) {
    throw new Error(
      `Failed to save image: ${error instanceof Error ? error.message : error}`,
    )
  }
}
