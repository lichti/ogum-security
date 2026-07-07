import type { NextConfig } from 'next'

const nextConfig: NextConfig = {
  reactStrictMode: true,
  transpilePackages: ['@xyflow/react', '@xyflow/system'],
}

export default nextConfig
