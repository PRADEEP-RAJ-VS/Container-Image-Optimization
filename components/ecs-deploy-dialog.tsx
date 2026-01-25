"use client"

import { useState, useEffect } from "react"
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
import { Rocket, Loader2, CheckCircle2, XCircle, Server } from "lucide-react"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"

interface ECSDeployDialogProps {
  imageUri: string
  imageName: string
}

interface Cluster {
  name: string
  arn: string
  status: string
  runningTasks: number
  activeServices: number
}

export function ECSDeployDialog({ imageUri, imageName }: ECSDeployDialogProps) {
  const [open, setOpen] = useState(false)
  const [loading, setLoading] = useState(false)
  const [loadingClusters, setLoadingClusters] = useState(false)
  const [result, setResult] = useState<{
    success: boolean
    message: string
    taskDefinitionArn?: string
  } | null>(null)

  const [clusters, setClusters] = useState<Cluster[]>([])
  const [cluster, setCluster] = useState("")
  const [deployType, setDeployType] = useState<"service" | "task">("task")
  const [serviceName, setServiceName] = useState("")
  const [taskFamily, setTaskFamily] = useState(
    imageName.replace(/[^a-zA-Z0-9-_]/g, "-").toLowerCase()
  )
  const [cpu, setCpu] = useState("256")
  const [memory, setMemory] = useState("512")
  const [containerPort, setContainerPort] = useState("")
  const [region, setRegion] = useState("us-east-1")

  // Load clusters when dialog opens
  useEffect(() => {
    if (open && clusters.length === 0) {
      loadClusters()
    }
  }, [open])

  const loadClusters = async () => {
    setLoadingClusters(true)
    try {
      const response = await fetch(`/api/ecs/status?action=clusters&region=${region}`)
      const data = await response.json()

      if (data.success && data.clusters) {
        setClusters(data.clusters)
        if (data.clusters.length > 0) {
          setCluster(data.clusters[0].name)
        }
      }
    } catch (error) {
      console.error("Failed to load clusters:", error)
    } finally {
      setLoadingClusters(false)
    }
  }

  const handleDeploy = async () => {
    setLoading(true)
    setResult(null)

    try {
      const response = await fetch("/api/ecs/deploy", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          cluster,
          serviceName: deployType === "service" ? serviceName : undefined,
          taskFamily,
          imageUri,
          cpu,
          memory,
          containerPort: containerPort ? parseInt(containerPort) : undefined,
          region,
          assignPublicIp: true,
        }),
      })

      const data = await response.json()

      if (data.success) {
        setResult({
          success: true,
          message: data.message || "Deployment started successfully",
          taskDefinitionArn: data.taskDefinitionArn,
        })
      } else {
        setResult({
          success: false,
          message: data.error || "Failed to deploy",
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
        <Button variant="default" size="sm">
          <Rocket className="mr-2 h-4 w-4" />
          Deploy to ECS
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-[600px]">
        <DialogHeader>
          <DialogTitle>Deploy to Amazon ECS</DialogTitle>
          <DialogDescription>
            Deploy your optimized image to Amazon Elastic Container Service
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-4 max-h-[60vh] overflow-y-auto">
          <div className="space-y-2">
            <Label htmlFor="imageUri">Image URI</Label>
            <Input id="imageUri" value={imageUri} disabled className="font-mono text-xs" />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="region">AWS Region</Label>
              <Select value={region} onValueChange={(val) => { setRegion(val); setClusters([]); }} disabled={loading}>
                <SelectTrigger id="region">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="us-east-1">US East (N. Virginia)</SelectItem>
                  <SelectItem value="us-east-2">US East (Ohio)</SelectItem>
                  <SelectItem value="us-west-2">US West (Oregon)</SelectItem>
                  <SelectItem value="eu-west-1">EU (Ireland)</SelectItem>
                  <SelectItem value="ap-southeast-1">Asia Pacific (Singapore)</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label htmlFor="cluster">ECS Cluster</Label>
              <div className="flex gap-2">
                <Select value={cluster} onValueChange={setCluster} disabled={loading || loadingClusters}>
                  <SelectTrigger id="cluster" className="flex-1">
                    <SelectValue placeholder="Select cluster" />
                  </SelectTrigger>
                  <SelectContent>
                    {clusters.map((c) => (
                      <SelectItem key={c.name} value={c.name}>
                        <div className="flex items-center gap-2">
                          <Server className="h-3 w-3" />
                          {c.name}
                        </div>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={loadClusters}
                  disabled={loadingClusters}
                >
                  {loadingClusters ? <Loader2 className="h-4 w-4 animate-spin" /> : "↻"}
                </Button>
              </div>
            </div>
          </div>

          <Tabs value={deployType} onValueChange={(val) => setDeployType(val as "service" | "task")}>
            <TabsList className="grid w-full grid-cols-2">
              <TabsTrigger value="task">Standalone Task</TabsTrigger>
              <TabsTrigger value="service">ECS Service</TabsTrigger>
            </TabsList>

            <TabsContent value="task" className="space-y-4">
              <p className="text-sm text-muted-foreground">
                Run a one-time task (good for testing)
              </p>
            </TabsContent>

            <TabsContent value="service" className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="serviceName">Service Name</Label>
                <Input
                  id="serviceName"
                  value={serviceName}
                  onChange={(e) => setServiceName(e.target.value)}
                  placeholder="my-service"
                  disabled={loading}
                />
              </div>
            </TabsContent>
          </Tabs>

          <div className="space-y-2">
            <Label htmlFor="taskFamily">Task Family Name</Label>
            <Input
              id="taskFamily"
              value={taskFamily}
              onChange={(e) => setTaskFamily(e.target.value)}
              placeholder="my-task"
              disabled={loading}
            />
          </div>

          <div className="grid grid-cols-3 gap-4">
            <div className="space-y-2">
              <Label htmlFor="cpu">CPU</Label>
              <Select value={cpu} onValueChange={setCpu} disabled={loading}>
                <SelectTrigger id="cpu">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="256">256 (.25 vCPU)</SelectItem>
                  <SelectItem value="512">512 (.5 vCPU)</SelectItem>
                  <SelectItem value="1024">1024 (1 vCPU)</SelectItem>
                  <SelectItem value="2048">2048 (2 vCPU)</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label htmlFor="memory">Memory</Label>
              <Select value={memory} onValueChange={setMemory} disabled={loading}>
                <SelectTrigger id="memory">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="512">512 MB</SelectItem>
                  <SelectItem value="1024">1 GB</SelectItem>
                  <SelectItem value="2048">2 GB</SelectItem>
                  <SelectItem value="4096">4 GB</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label htmlFor="port">Port (Optional)</Label>
              <Input
                id="port"
                type="number"
                value={containerPort}
                onChange={(e) => setContainerPort(e.target.value)}
                placeholder="80"
                disabled={loading}
              />
            </div>
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
                  {result.taskDefinitionArn && (
                    <p className="text-xs mt-2 font-mono break-all">{result.taskDefinitionArn}</p>
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
          <Button onClick={handleDeploy} disabled={loading || result?.success || !cluster}>
            {loading ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Deploying...
              </>
            ) : (
              <>
                <Rocket className="mr-2 h-4 w-4" />
                Deploy
              </>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
