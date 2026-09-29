# US-13.12 — build standalone do Next.js, imagem de produção (nada de
# `npm run dev`); o perfil dev do docker-compose sobrecarrega o command.

# ── Stage 1: build ───────────────────────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci

COPY . .
ENV NEXT_TELEMETRY_DISABLED=1
# output: "standalone" no next.config.mjs — emite server.js + mínimos node_modules
RUN npm run build

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM node:20-alpine

RUN npm install -g npm@11

WORKDIR /app

ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1

# Usuário não-root do próprio node image
USER node

COPY --from=builder --chown=node:node /app/.next/standalone ./
COPY --from=builder --chown=node:node /app/.next/static ./.next/static
COPY --from=builder --chown=node:node /app/public ./public

EXPOSE 3000

CMD ["node", "server.js"]
