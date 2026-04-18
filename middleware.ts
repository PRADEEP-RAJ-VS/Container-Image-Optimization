import { NextRequest, NextResponse } from "next/server"

function resolveAllowedOrigin(request: NextRequest): string {
  const requestOrigin = request.headers.get("origin")
  const raw = process.env.CORS_ALLOWED_ORIGINS || ""
  const allowed = raw
    .split(",")
    .map((v) => v.trim())
    .filter(Boolean)

  if (!requestOrigin) {
    return allowed[0] || "*"
  }

  if (allowed.length === 0) {
    return "*"
  }

  return allowed.includes(requestOrigin) ? requestOrigin : allowed[0]
}

function withCorsHeaders(response: NextResponse, request: NextRequest): NextResponse {
  response.headers.set("Access-Control-Allow-Origin", resolveAllowedOrigin(request))
  response.headers.set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
  response.headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
  response.headers.set("Access-Control-Max-Age", "86400")
  response.headers.set("Vary", "Origin")
  return response
}

export function middleware(request: NextRequest) {
  if (request.method === "OPTIONS") {
    return withCorsHeaders(new NextResponse(null, { status: 204 }), request)
  }

  return withCorsHeaders(NextResponse.next(), request)
}

export const config = {
  matcher: ["/api/:path*"],
}
