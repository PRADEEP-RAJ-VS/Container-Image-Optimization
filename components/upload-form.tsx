"use client"

import type React from "react"

import { useState, useRef } from "react"
import { Upload, X, Package } from "lucide-react"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"

interface UploadFormProps {
  onUpload: (file: File | string) => void
  isLoading?: boolean
}

export default function UploadForm({ onUpload, isLoading = false }: UploadFormProps) {
  const [mode, setMode] = useState<"file" | "image">("file")
  const [isDragActive, setIsDragActive] = useState(false)
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [imageName, setImageName] = useState("")
  const fileInputRef = useRef<HTMLInputElement>(null)

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragActive(e.type === "dragenter" || e.type === "dragover")
  }

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragActive(false)

    const files = e.dataTransfer.files
    if (files && files[0]) {
      handleFile(files[0])
    }
  }

  const handleFile = (file: File) => {
    if (file.type === "application/x-tar" || file.name.endsWith(".tar")) {
      setSelectedFile(file)
    } else {
      alert("Please upload a .tar file")
    }
  }

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      handleFile(e.target.files[0])
    }
  }

  const handleSubmit = () => {
    if (mode === "file" && selectedFile) {
      onUpload(selectedFile)
    } else if (mode === "image" && imageName.trim()) {
      onUpload(imageName.trim())
    }
  }

  const handleClear = () => {
    setSelectedFile(null)
    if (fileInputRef.current) {
      fileInputRef.current.value = ""
    }
  }

  const handleClearImage = () => {
    setImageName("")
  }

  return (
    <div className="space-y-4">
      <div className="flex gap-2 bg-slate-900/50 border border-slate-700 rounded-lg p-1">
        <button
          onClick={() => {
            setMode("file")
            handleClear()
            handleClearImage()
          }}
          className={cn(
            "flex-1 py-2 px-3 rounded transition-colors text-sm font-medium flex items-center justify-center gap-2",
            mode === "file" ? "bg-blue-600 text-white" : "text-slate-400 hover:text-slate-300",
          )}
        >
          <Upload className="w-4 h-4" />
          Upload .tar
        </button>
        <button
          onClick={() => {
            setMode("image")
            handleClear()
            handleClearImage()
          }}
          className={cn(
            "flex-1 py-2 px-3 rounded transition-colors text-sm font-medium flex items-center justify-center gap-2",
            mode === "image" ? "bg-blue-600 text-white" : "text-slate-400 hover:text-slate-300",
          )}
        >
          <Package className="w-4 h-4" />
          Docker Hub
        </button>
      </div>

      {/* File Upload Mode */}
      {mode === "file" && (
        <>
          <div
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
            className={cn(
              "border-2 border-dashed rounded-lg p-6 text-center cursor-pointer transition-all",
              isDragActive
                ? "border-blue-400 bg-blue-500/10"
                : "border-slate-600 bg-slate-900/50 hover:border-slate-500",
            )}
            onClick={() => fileInputRef.current?.click()}
          >
            <Upload className="w-8 h-8 mx-auto mb-2 text-slate-400" />
            <p className="text-sm font-medium text-slate-300">Drop your .tar file here</p>
            <p className="text-xs text-slate-500 mt-1">or click to select</p>
          </div>

          <input ref={fileInputRef} type="file" accept=".tar" onChange={handleChange} className="hidden" />

          {selectedFile && (
            <div className="bg-slate-900/50 border border-slate-700 rounded-lg p-3 flex items-center justify-between">
              <div className="flex-1">
                <p className="text-sm font-medium text-slate-300 truncate">{selectedFile.name}</p>
                <p className="text-xs text-slate-500">{(selectedFile.size / 1024 / 1024).toFixed(2)} MB</p>
              </div>
              <button
                onClick={handleClear}
                disabled={isLoading}
                className="p-1 hover:bg-slate-800 rounded transition-colors disabled:opacity-50"
              >
                <X className="w-4 h-4 text-slate-400" />
              </button>
            </div>
          )}
        </>
      )}

      {/* Docker Hub Image Name Mode */}
      {mode === "image" && (
        <>
          <div className="space-y-2">
            <label className="block text-sm font-medium text-slate-300">Docker Hub Image Name</label>
            <input
              type="text"
              value={imageName}
              onChange={(e) => setImageName(e.target.value)}
              onKeyPress={(e) => e.key === "Enter" && handleSubmit()}
              placeholder="e.g. python:3.9, nginx:latest, node:18-alpine"
              className="w-full px-4 py-2 bg-slate-900/50 border border-slate-700 rounded-lg text-slate-300 placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-colors"
              disabled={isLoading}
            />
            <p className="text-xs text-slate-500">Include the tag (e.g., :latest, :3.9) or use 'latest' by default</p>
          </div>

          {imageName && (
            <div className="bg-slate-900/50 border border-slate-700 rounded-lg p-3 flex items-center justify-between">
              <div className="flex-1">
                <p className="text-sm font-medium text-slate-300 truncate">{imageName}</p>
                <p className="text-xs text-slate-500">Docker Hub Image</p>
              </div>
              <button
                onClick={handleClearImage}
                disabled={isLoading}
                className="p-1 hover:bg-slate-800 rounded transition-colors disabled:opacity-50"
              >
                <X className="w-4 h-4 text-slate-400" />
              </button>
            </div>
          )}
        </>
      )}

      <Button
        onClick={handleSubmit}
        disabled={(mode === "file" && !selectedFile) || (mode === "image" && !imageName.trim()) || isLoading}
        className="w-full bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700"
      >
        {isLoading ? "Analyzing..." : mode === "file" ? "Analyze Image" : "Scan from Docker Hub"}
      </Button>
    </div>
  )
}
