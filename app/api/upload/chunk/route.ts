import { type NextRequest, NextResponse } from "next/server"
import { appendFileSync, existsSync, mkdirSync, rmSync, statSync } from "fs"
import { join } from "path"
import { tmpdir } from "os"
import { proxyToBackend } from "@/lib/api-proxy"

const CHUNK_DIR = join(tmpdir(), "docker-optimizer-upload-chunks")

function ensureChunkDirExists() {
  if (!existsSync(CHUNK_DIR)) {
    mkdirSync(CHUNK_DIR, { recursive: true })
  }
}

function cleanupOldChunks() {
  try {
    ensureChunkDirExists()
    const maxAgeMs = 2 * 60 * 60 * 1000
    const now = Date.now()
    const fs = require("fs") as typeof import("fs")

    for (const fileName of fs.readdirSync(CHUNK_DIR)) {
      const filePath = join(CHUNK_DIR, fileName)
      const stats = statSync(filePath)
      if (now - stats.mtimeMs > maxAgeMs) {
        rmSync(filePath, { force: true })
      }
    }
  } catch (error) {
    console.warn("[UPLOAD-CHUNK] Cleanup warning:", error)
  }
}

export async function POST(request: NextRequest) {
  try {
    const proxiedResponse = await proxyToBackend(request, "/api/upload/chunk")
    if (proxiedResponse) {
      return proxiedResponse
    }

    cleanupOldChunks()
    ensureChunkDirExists()

    const formData = await request.formData()
    const uploadId = String(formData.get("uploadId") || "").trim()
    const chunkIndexRaw = String(formData.get("chunkIndex") || "").trim()
    const totalChunksRaw = String(formData.get("totalChunks") || "").trim()
    const chunk = formData.get("chunk") as File | null

    if (!uploadId || !chunk || chunk.size === 0) {
      return NextResponse.json(
        { success: false, error: "Missing uploadId or chunk payload" },
        { status: 400 },
      )
    }

    const chunkIndex = Number.parseInt(chunkIndexRaw, 10)
    const totalChunks = Number.parseInt(totalChunksRaw, 10)

    if (Number.isNaN(chunkIndex) || Number.isNaN(totalChunks) || totalChunks <= 0 || chunkIndex < 0 || chunkIndex >= totalChunks) {
      return NextResponse.json(
        { success: false, error: "Invalid chunk index metadata" },
        { status: 400 },
      )
    }

    const targetPath = join(CHUNK_DIR, `${uploadId}.tar`)

    if (chunkIndex === 0 && existsSync(targetPath)) {
      rmSync(targetPath, { force: true })
    }

    const buffer = Buffer.from(await chunk.arrayBuffer())
    appendFileSync(targetPath, buffer)

    return NextResponse.json({
      success: true,
      uploadId,
      receivedChunk: chunkIndex,
      totalChunks,
      complete: chunkIndex === totalChunks - 1,
    })
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown chunk upload error"
    return NextResponse.json(
      { success: false, error: message },
      { status: 500 },
    )
  }
}