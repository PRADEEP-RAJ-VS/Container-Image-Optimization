"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { ProgressBar } from "@/components/progress-bar"
import { useEffect, useState } from "react"

interface LayerBreakdownProps {
  analysis: any
}

export default function LayerBreakdown({ analysis }: LayerBreakdownProps) {
  const [totalSize, setTotalSize] = useState(0)
  const layers = analysis.imageInfo?.layerDetails || []

  useEffect(() => {
    // Calculate total size
    const total = layers.reduce((sum: number, layer: any) => {
      const sizeMatch = layer.size.match(/(\d+)/)
      return sum + (sizeMatch ? Number.parseInt(sizeMatch[0]) : 0)
    }, 0)
    setTotalSize(total)
  }, [layers])

  return (
    <Card className="bg-slate-800/50 border-slate-700/50">
      <CardHeader>
        <CardTitle className="text-white">Image Layers ({layers.length})</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {layers.length > 0 ? (
            layers.map((layer: any, idx: number) => {
              const sizeMatch = layer.size.match(/(\d+)/)
              const sizeNum = sizeMatch ? Number.parseInt(sizeMatch[0]) : 0
              const percentage = totalSize > 0 ? (sizeNum / totalSize) * 100 : 0

              return (
                <div key={idx} className="bg-slate-900/50 border border-slate-700 rounded-lg p-4">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex-1">
                      <p className="font-mono text-sm text-blue-400 truncate">{layer.digest?.slice(0, 16)}...</p>
                      <p className="text-xs text-slate-400 mt-1 font-mono line-clamp-2">{layer.command}</p>
                    </div>
                    <div className="text-right ml-4">
                      <span className="text-sm font-semibold text-slate-300">{layer.size}</span>
                      <p className="text-xs text-slate-500">{percentage.toFixed(1)}%</p>
                    </div>
                  </div>
                  <ProgressBar value={percentage} className="h-2" />
                </div>
              )
            })
          ) : (
            <p className="text-slate-400 text-sm text-center py-8">No layer details available</p>
          )}
        </div>
      </CardContent>
    </Card>
  )
}
