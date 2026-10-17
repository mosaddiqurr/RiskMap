FROM node:24-alpine AS dependencies
WORKDIR /app
COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --foreground-scripts --fetch-timeout=30000 --fetch-retries=1

FROM node:24-alpine AS builder
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY --from=dependencies /app/node_modules ./node_modules
COPY . .
ARG NEXT_PUBLIC_API_BASE_URL=""
ENV NEXT_PUBLIC_API_BASE_URL=$NEXT_PUBLIC_API_BASE_URL
RUN npm run build

FROM node:24-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV HOSTNAME=0.0.0.0 PORT=3000
RUN addgroup --system --gid 1001 nodejs && adduser --system --uid 1001 riskmap
COPY --from=builder --chown=riskmap:nodejs /app/.next/standalone ./
COPY --from=builder --chown=riskmap:nodejs /app/.next/static ./.next/static
COPY --from=builder --chown=riskmap:nodejs /app/public ./public
COPY --from=builder --chown=riskmap:nodejs /app/scripts/healthcheck.mjs ./scripts/healthcheck.mjs
USER riskmap
EXPOSE 3000
HEALTHCHECK --interval=20s --timeout=5s --start-period=20s --retries=3 CMD node scripts/healthcheck.mjs
CMD ["node", "server.js"]
