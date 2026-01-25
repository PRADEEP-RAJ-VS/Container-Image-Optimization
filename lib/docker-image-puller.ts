import { execSync } from "child_process"
import { readFileSync, unlinkSync, existsSync, mkdirSync, rmSync } from "fs"
import path from "path"

/**
 * Pulls a Docker image from Docker Hub and converts it to a tar archive
 * Falls back to mock analysis if Docker is not available
 */
export async function pullAndConvertDockerImage(imageName: string): Promise<{ buffer: Buffer; imageInfo: any }> {
  const tempDir = path.join("/tmp", `docker-pull-${Date.now()}-${Math.random().toString(36).substring(7)}`)
  const tarPath = path.join(tempDir, `${imageName.replace(/[/:]/g, "-")}.tar`)

  try {
    // Create temp directory
    if (!existsSync(tempDir)) {
      mkdirSync(tempDir, { recursive: true })
    }

    // Try to pull and save the image using Docker CLI
    try {
      console.log("[v0] Attempting to pull Docker image:", imageName)

      // First, try to pull the image
      const pullCommand = `docker pull ${imageName}`
      try {
        execSync(pullCommand, { stdio: "pipe", timeout: 60000 })
        console.log("[v0] Successfully pulled image:", imageName)
      } catch (pullError) {
        const errorMsg = pullError instanceof Error ? pullError.message : String(pullError)
        console.log("[v0] Failed to pull image with Docker CLI:", errorMsg)
        throw new Error(`Docker pull failed: ${errorMsg}`)
      }

      // Then save it to tar
      const saveCommand = `docker save -o "${tarPath}" ${imageName}`
      try {
        execSync(saveCommand, { stdio: "pipe" })
        console.log("[v0] Successfully saved image to tar:", tarPath)
      } catch (saveError) {
        const errorMsg = saveError instanceof Error ? saveError.message : String(saveError)
        console.log("[v0] Failed to save image to tar:", errorMsg)
        throw new Error(`Docker save failed: ${errorMsg}`)
      }

      if (existsSync(tarPath) && readFileSync(tarPath).length > 0) {
        const buffer = readFileSync(tarPath)
        const imageInfo = {
          source: "docker-hub",
          imageName,
          pulledAt: new Date().toISOString(),
          method: "docker-cli",
        }
        console.log("[v0] Successfully loaded tar buffer, size:", buffer.length)
        return { buffer, imageInfo }
      } else {
        throw new Error("Generated tar file is empty or missing")
      }
    } catch (dockerError) {
      const errorMsg = dockerError instanceof Error ? dockerError.message : String(dockerError)
      console.log("[v0] Docker CLI not available, using fallback for:", imageName, "Reason:", errorMsg)
      // Return mock for Docker Hub images since Docker is not available
      return generateMockImageBuffer(imageName)
    }
  } finally {
    try {
      if (existsSync(tarPath)) {
        unlinkSync(tarPath)
        console.log("[v0] Cleaned up tar file")
      }
      if (existsSync(tempDir)) {
        rmSync(tempDir, { recursive: true, force: true })
        console.log("[v0] Cleaned up temp directory")
      }
    } catch (cleanupError) {
      console.log("[v0] Cleanup warning:", cleanupError instanceof Error ? cleanupError.message : "Unknown error")
    }
  }
}

/**
 * Generates a realistic mock tar buffer when Docker is not available
 * Create a valid minimal tar file instead of trying to construct one
 */
function generateMockImageBuffer(imageName: string): { buffer: Buffer; imageInfo: any } {
  // Create a minimal but valid tar archive
  // This is a proper tar structure with a single file entry
  const mockTarBuffer = createMinimalTar()

  const imageInfo = {
    source: "mock",
    imageName,
    method: "fallback-mock",
    generatedAt: new Date().toISOString(),
    note: "Docker CLI not available. Results are simulated for demonstration.",
  }

  console.log("[v0] Generated mock buffer for:", imageName, "Size:", mockTarBuffer.length)
  return { buffer: mockTarBuffer, imageInfo }
}

/**
 * Create a valid minimal tar file that can be parsed safely
 */
function createMinimalTar(): Buffer {
  // Create a valid tar file with a simple text file entry
  const fileName = "manifest.json"
  const fileContent = Buffer.from('{"name":"docker-image","version":"1.0"}')

  // TAR headers are 512 bytes each
  const header = Buffer.alloc(512)

  // File name (0-99)
  Buffer.from(fileName).copy(header, 0)

  // File mode (100-107) - 0644 in octal
  Buffer.from("0000644\0").copy(header, 100)

  // Owner uid (108-115)
  Buffer.from("0000000\0").copy(header, 108)

  // Group gid (116-123)
  Buffer.from("0000000\0").copy(header, 116)

  // File size in bytes (124-135) - in octal
  const size = fileContent.length.toString(8).padStart(11, "0")
  Buffer.from(size + "\0").copy(header, 124)

  // Modification time (136-147)
  Buffer.from("14000000000\0").copy(header, 136)

  // Checksum (148-155) - calculate later
  Buffer.from("        ").copy(header, 148)

  // Type flag (156) - '0' for regular file
  header[156] = 0x30

  // Link name (157-256) - leave empty
  // Ustar indicator (257-262)
  Buffer.from("ustar").copy(header, 257)

  // Ustar version (263-264)
  Buffer.from("00").copy(header, 263)

  // Calculate checksum (sum of header bytes, with checksum field treated as spaces)
  let checksum = 0
  for (let i = 0; i < 512; i++) {
    if (i >= 148 && i < 156) {
      checksum += 0x20 // space character
    } else {
      checksum += header[i]
    }
  }

  // Write checksum in octal format
  const checksumStr = checksum.toString(8).padStart(6, "0") + "\0 "
  Buffer.from(checksumStr).copy(header, 148)

  // Pad file content to 512 byte boundary
  const paddedContent = Buffer.alloc(512)
  fileContent.copy(paddedContent, 0)

  // Create final tar: header + content + two empty blocks (end marker)
  const endMarker = Buffer.alloc(1024) // Two 512-byte blocks of zeros

  return Buffer.concat([header, paddedContent, endMarker])
}

/**
 * Validates if an image name is a valid Docker Hub image reference
 */
export function validateImageName(imageName: string): boolean {
  // Format: [REGISTRY_HOST[:REGISTRY_PORT]/]NAME[:TAG]
  const imageRegex =
    /^([a-z0-9]([a-z0-9\-.]*[a-z0-9])?\.)*([a-z0-9]([a-z0-9-]*[a-z0-9])?)(\/[a-z0-9]([a-z0-9\-.]*[a-z0-9])?)*(:[\w][\w.-]{0,127})?(@sha256:[a-f0-9]{64})?$/i
  const isValid = imageRegex.test(imageName)
  console.log("[v0] Image name validation for", imageName, ":", isValid)
  return isValid
}
