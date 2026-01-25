export interface OptimizationTip {
  id: string
  title: string
  description: string
  category: "size" | "security" | "performance" | "best-practice"
  impact: "High" | "Medium" | "Low"
  priority: number
  dockerfile?: string
  estimatedSavings?: string
}

export interface OptimizationAnalysis {
  score: number
  percentSavings: string
  imageSizeBeforeMB: string
  imageSizeAfterMB: string
  tipsCount: number
  tips: OptimizationTip[]
  summary: string
}

export function analyzeOptimization(
  imageSize: number,
  layerCount: number,
  vulnerabilities: { critical: number; high: number; medium: number; low: number },
): OptimizationAnalysis {
  const tips: OptimizationTip[] = []
  const sizeInMB = imageSize / 1024 / 1024

  // SIZE OPTIMIZATION TIPS
  if (sizeInMB > 500) {
    tips.push({
      id: "multi-stage",
      title: "Implement Multi-stage Builds",
      description:
        "Use Docker multi-stage builds to separate build dependencies from runtime, reducing final image size by 30-50%.",
      category: "size",
      impact: "High",
      priority: 1,
      dockerfile: `# Build stage
FROM node:18 AS builder
WORKDIR /app
COPY . .
RUN npm install
RUN npm run build

# Production stage
FROM node:18-alpine
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
CMD ["node", "dist/index.js"]`,
      estimatedSavings: "40%",
    })
  }

  if (sizeInMB > 800) {
    tips.push({
      id: "lightweight-base",
      title: "Use Lightweight Base Image",
      description: "Switch to alpine-based or distroless base images instead of full OS images.",
      category: "size",
      impact: "High",
      priority: 2,
      dockerfile: `# Instead of:
FROM ubuntu:22.04

# Use:
FROM alpine:3.18
# or
FROM gcr.io/distroless/base`,
      estimatedSavings: "60-70%",
    })
  }

  // LAYER OPTIMIZATION TIPS
  if (layerCount > 20) {
    tips.push({
      id: "consolidate-runs",
      title: "Consolidate RUN Commands",
      description: "Combine multiple RUN commands into a single layer using && to reduce image layers.",
      category: "size",
      impact: "Medium",
      priority: 3,
      dockerfile: `# Bad: Creates multiple layers
RUN apt-get update
RUN apt-get install -y curl
RUN apt-get install -y git

# Good: Single layer
RUN apt-get update && \\
    apt-get install -y curl git && \\
    apt-get clean && \\
    rm -rf /var/lib/apt/lists/*`,
      estimatedSavings: "15-25%",
    })
  }

  // CACHE AND CLEANUP TIPS
  tips.push({
    id: "cache-cleanup",
    title: "Clean Up Package Manager Cache",
    description: "Remove package manager cache after installing dependencies to reduce bloat.",
    category: "size",
    impact: "Medium",
    priority: 4,
    dockerfile: `RUN apt-get update && \\
    apt-get install -y package1 package2 && \\
    apt-get clean && \\
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*`,
    estimatedSavings: "10-20%",
  })

  // COPY OPTIMIZATION
  tips.push({
    id: "copy-optimization",
    title: "Optimize COPY Instructions",
    description: "Use .dockerignore to exclude unnecessary files and order COPY by change frequency.",
    category: "performance",
    impact: "Medium",
    priority: 5,
  })

  // SECURITY TIPS
  if (vulnerabilities.critical > 0) {
    tips.push({
      id: "critical-vulns",
      title: "Fix Critical Vulnerabilities",
      description: `Your image has ${vulnerabilities.critical} critical vulnerabilities. Update affected packages immediately.`,
      category: "security",
      impact: "High",
      priority: 0,
    })
  }

  if (vulnerabilities.high > 0) {
    tips.push({
      id: "high-vulns",
      title: "Address High-Severity Vulnerabilities",
      description: `Found ${vulnerabilities.high} high-severity vulnerabilities. Consider updating affected packages.`,
      category: "security",
      impact: "High",
      priority: 1,
    })
  }

  // BEST PRACTICES
  tips.push({
    id: "non-root-user",
    title: "Run Containers as Non-root User",
    description: "Create and use a non-root user for better security.",
    category: "best-practice",
    impact: "Medium",
    priority: 6,
    dockerfile: `RUN useradd -m -u 1000 appuser
USER appuser`,
  })

  tips.push({
    id: "health-check",
    title: "Add Health Check",
    description: "Implement HEALTHCHECK instruction for better container orchestration.",
    category: "best-practice",
    impact: "Low",
    priority: 7,
    dockerfile: `HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\
    CMD curl -f http://localhost:3000/health || exit 1`,
  })

  tips.push({
    id: "labels",
    title: "Add Metadata Labels",
    description: "Include LABEL instructions for better image documentation and tracking.",
    category: "best-practice",
    impact: "Low",
    priority: 8,
    dockerfile: `LABEL maintainer="your-email@example.com"
LABEL version="1.0"
LABEL description="Application description"`,
  })

  // Calculate optimization score
  const score = calculateScore(sizeInMB, layerCount, vulnerabilities)
  const percentSavings = calculateSavings(sizeInMB, layerCount)
  const sizeAfterOptimization = sizeInMB * (1 - percentSavings / 100)

  return {
    score,
    percentSavings: `${percentSavings}%`,
    imageSizeBeforeMB: `${sizeInMB.toFixed(2)}`,
    imageSizeAfterMB: `${sizeAfterOptimization.toFixed(2)}`,
    tipsCount: tips.length,
    tips: tips.sort((a, b) => a.priority - b.priority),
    summary: generateSummary(score, vulnerabilities),
  }
}

function calculateScore(sizeInMB: number, layerCount: number, vulnerabilities: any): number {
  let score = 100

  // Size penalties
  if (sizeInMB > 1000) score -= 25
  else if (sizeInMB > 500) score -= 15
  else if (sizeInMB > 200) score -= 5

  // Layer penalties
  if (layerCount > 30) score -= 15
  else if (layerCount > 20) score -= 10
  else if (layerCount > 15) score -= 5

  // Vulnerability penalties
  score -= (vulnerabilities.critical || 0) * 5
  score -= (vulnerabilities.high || 0) * 2
  score -= (vulnerabilities.medium || 0) * 0.5

  return Math.max(0, Math.min(100, score))
}

function calculateSavings(sizeInMB: number, layerCount: number): number {
  let savings = 0

  // Size-based savings (0-25%)
  if (sizeInMB < 100) savings += 5
  else if (sizeInMB < 200) savings += 10
  else if (sizeInMB < 500) savings += 15
  else if (sizeInMB < 800) savings += 20
  else if (sizeInMB < 1000) savings += 25
  else savings += 30

  // Layer-based savings (0-20%)
  if (layerCount > 50) savings += 20
  else if (layerCount > 30) savings += 18
  else if (layerCount > 20) savings += 15
  else if (layerCount > 15) savings += 10
  else if (layerCount > 10) savings += 5

  return Math.min(65, Math.max(5, savings))
}

function generateSummary(score: number, vulnerabilities: any): string {
  if (score >= 80) {
    return "Your Docker image is well-optimized and secure. Keep following best practices."
  }
  if (score >= 60) {
    return "Good optimization score. Consider implementing the recommended improvements to further optimize your image."
  }
  if (score >= 40) {
    return "Your image has significant optimization opportunities. Implement multi-stage builds and reduce layer count."
  }
  return "Critical optimization needed. Address vulnerabilities and implement major size reduction strategies."
}
