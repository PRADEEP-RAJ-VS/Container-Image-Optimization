import { getOptimizationStats } from '@/lib/runtime-optimizer'
import { NextRequest, NextResponse } from 'next/server'
import { proxyToBackend } from '@/lib/api-proxy'

export async function GET(request: NextRequest) {
  const proxiedResponse = await proxyToBackend(request, '/api/optimization-stats')
  if (proxiedResponse) {
    return proxiedResponse
  }

  try {
    const stats = getOptimizationStats()
    
    return NextResponse.json({
      timestamp: new Date().toISOString(),
      ...stats,
      status: 'operational',
    })
  } catch (error) {
    return NextResponse.json(
      {
        status: 'error',
        message: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    )
  }
}
