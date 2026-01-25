"use client"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Upload, Loader2, CheckCircle2, XCircle } from "lucide-react"

interface ECRPushDialogProps {
  sessionId: string
  imageName: string
  imageType?: "original" | "optimized"
  onPushSuccess?: (imageUri: string) => void
}

export function ECRPushDialog({ sessionId, imageName, imageType = "optimized", onPushSuccess }: ECRPushDialogProps) {
  const [open, setOpen] = useState(false)
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<{
    success: boolean
    message: string
    imageUri?: string
  } | null>(null)

  // Sanitize repository name to match ECR requirements: lowercase, alphanumeric, hyphens, underscores, slashes
  const sanitizeRepoName = (name: string) => {
    return name
      .toLowerCase()
      .replace(/[^a-z0-9._\/-]/g, "-")
      .replace(/^[._-]+|[._-]+$/g, "")
      .replace(/[._-]{2,}/g, "-")
      .slice(0, 256) || "docker-image"
  }
  
  const [repositoryName, setRepositoryName] = useState(
    sanitizeRepoName(imageName)
  )
  const [imageTag, setImageTag] = useState(imageType === "optimized" ? "optimized-latest" : "original")
  const [region, setRegion] = useState("us-east-1")

  const handlePush = async () => {
    setLoading(true)
    setResult(null)

    try {
      const response = await fetch("/api/ecr/push", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          sessionId,
          imageName,
          imageTag,
          repositoryName,
          region,
          imageType,
        }),
      })

      const data = await response.json()

      if (data.success) {
        setResult({
          success: true,
          message: data.message || "Image pushed successfully",
          imageUri: data.imageUri,
        })
        
        // Call onPushSuccess callback if provided
        if (onPushSuccess && data.imageUri) {
          onPushSuccess(data.imageUri)
        }
      } else {
        setResult({
          success: false,
          message: data.error || "Failed to push image",
        })
      }
    } catch (error) {
      setResult({
        success: false,
        message: error instanceof Error ? error.message : "Unknown error occurred",
      })
    } finally {
      setLoading(false)
    }
  }

  const handleClose = () => {
    setOpen(false)
    setResult(null)
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant={imageType === "optimized" ? "default" : "outline"} size="sm">
          <Upload className="mr-2 h-4 w-4" />
          Push {imageType === "optimized" ? "Optimized" : "Original"} to ECR
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-[500px]">
        <DialogHeader>
          <DialogTitle>Push to Amazon ECR</DialogTitle>
          <DialogDescription>
            Push your {imageType} Docker image to Amazon Elastic Container Registry
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-4">
          <div className="space-y-2">
            <Label htmlFor="repository">Repository Name</Label>
            <Input
              id="repository"
              value={repositoryName}
              onChange={(e) => setRepositoryName(sanitizeRepoName(e.target.value))}
              placeholder="my-app"
              disabled={loading}
            />
            <p className="text-xs text-muted-foreground">
              Only lowercase letters, numbers, hyphens, underscores, and slashes allowed
            </p>
          </div>

          <div className="space-y-2">
            <Label htmlFor="tag">Image Tag</Label>
            <Input
              id="tag"
              value={imageTag}
              onChange={(e) => setImageTag(e.target.value)}
              placeholder="latest"
              disabled={loading}
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="region">AWS Region</Label>
            <Select value={region} onValueChange={setRegion} disabled={loading}>
              <SelectTrigger id="region">
                <SelectValue placeholder="Select region" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="us-east-1">US East (N. Virginia)</SelectItem>
                <SelectItem value="us-east-2">US East (Ohio)</SelectItem>
                <SelectItem value="us-west-1">US West (N. California)</SelectItem>
                <SelectItem value="us-west-2">US West (Oregon)</SelectItem>
                <SelectItem value="eu-west-1">EU (Ireland)</SelectItem>
                <SelectItem value="eu-central-1">EU (Frankfurt)</SelectItem>
                <SelectItem value="ap-south-1">Asia Pacific (Mumbai)</SelectItem>
                <SelectItem value="ap-southeast-1">Asia Pacific (Singapore)</SelectItem>
                <SelectItem value="ap-northeast-1">Asia Pacific (Tokyo)</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {result && (
            <Alert variant={result.success ? "default" : "destructive"}>
              <div className="flex items-start gap-2">
                {result.success ? (
                  <CheckCircle2 className="h-4 w-4 mt-0.5" />
                ) : (
                  <XCircle className="h-4 w-4 mt-0.5" />
                )}
                <div className="flex-1">
                  <AlertDescription>{result.message}</AlertDescription>
                  {result.imageUri && (
                    <p className="text-xs mt-2 font-mono break-all">{result.imageUri}</p>
                  )}
                </div>
              </div>
            </Alert>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={handleClose} disabled={loading}>
            {result?.success ? "Close" : "Cancel"}
          </Button>
          <Button onClick={handlePush} disabled={loading || result?.success}>
            {loading ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Pushing...
              </>
            ) : (
              <>
                <Upload className="mr-2 h-4 w-4" />
                Push to ECR
              </>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
