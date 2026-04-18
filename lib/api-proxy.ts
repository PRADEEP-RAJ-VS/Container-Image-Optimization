import { NextResponse, type NextRequest } from "next/server"

export function getBackendBaseUrl(): string | null {
  return process.env.BACKEND_API_BASE_URL?.replace(/\/$/, "") || null
}

export async function proxyToBackend(request: NextRequest, backendPath: string) {
  const backendBaseUrl = getBackendBaseUrl()

  if (!backendBaseUrl) {
    return null
  }

  const targetUrl = new URL(backendPath, `${backendBaseUrl}/`)
  targetUrl.search = request.nextUrl.search

  const headers = new Headers(request.headers)
  headers.delete("host")

  const init: RequestInit = {
    method: request.method,
    headers,
    redirect: "manual",
  }

  if (request.method !== "GET" && request.method !== "HEAD") {
    init.body = await request.arrayBuffer()
  }

  const backendResponse = await fetch(targetUrl, init)
  const responseHeaders = new Headers(backendResponse.headers)

  return new NextResponse(backendResponse.body, {
    status: backendResponse.status,
    statusText: backendResponse.statusText,
    headers: responseHeaders,
  })
}