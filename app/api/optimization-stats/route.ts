import { getOptimizationStats } from '@/lib/runtime-optimizer'
import { NextResponse } from 'next/server'

export async function GET() {
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
