/** @type {import('next').NextConfig} */
const nextConfig = {
  typescript: {
    ignoreBuildErrors: true,
  },
  images: {
    unoptimized: true,
  },
  async rewrites() {
    const backendBaseUrl = process.env.BACKEND_API_BASE_URL?.replace(/\/$/, "")

    if (!backendBaseUrl) {
      return []
    }

    // Forward all API routes to an external backend when configured.
    return {
      beforeFiles: [
        {
          source: "/api/:path*",
          destination: `${backendBaseUrl}/api/:path*`,
        },
      ],
    }
  },
}

export default nextConfig
