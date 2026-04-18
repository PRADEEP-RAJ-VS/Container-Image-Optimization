import { startRuntimeOptimizer, getOptimizationStats } from '@/lib/runtime-optimizer'
import { NextResponse, type NextRequest } from 'next/server'
import { proxyToBackend } from '@/lib/api-proxy'

let optimizerStarted = false

export async function GET(request: NextRequest) {
  const proxiedResponse = await proxyToBackend(request, '/api/init')
  if (proxiedResponse) {
    return proxiedResponse
  }

  if (!optimizerStarted && process.env.RUNTIME_OPTIMIZER_ENABLED === 'true') {
    optimizerStarted = true
    
    // Start the runtime optimizer with 5-minute interval
    startRuntimeOptimizer({
      interval: 5 * 60 * 1000, // 5 minutes
      aggressive: process.env.RUNTIME_OPTIMIZER_AGGRESSIVE === 'true',
      dryRun: process.env.RUNTIME_OPTIMIZER_DRY_RUN === 'true',
    })
    
    console.log('✅ Runtime optimizer initialized')
  }
  
  return NextResponse.json({
    status: 'ok',
    optimizerEnabled: process.env.RUNTIME_OPTIMIZER_ENABLED === 'true',
    optimizerStarted,
    stats: getOptimizationStats(),
  })
}
