"use client"

import { cn } from "@/lib/utils"

interface ProgressBarProps {
  value: number
  className?: string
  indicatorClassName?: string
}

export function ProgressBar({ value, className = "", indicatorClassName = "" }: ProgressBarProps) {
  return (
    <div className={cn("w-full bg-slate-700/50 rounded-full overflow-hidden", className)}>
      <div
        className={cn(
          "bg-gradient-to-r from-blue-500 to-cyan-500 h-full transition-all duration-300",
          indicatorClassName,
        )}
        style={{ width: `${Math.min(100, Math.max(0, value))}%` }}
      />
    </div>
  )
}
