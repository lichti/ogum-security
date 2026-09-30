/** @type {import('next').NextConfig} */
const nextConfig = {
  // US-13.12: build standalone para a imagem de produção (docker/frontend.Dockerfile)
  output: "standalone",
}

export default nextConfig
