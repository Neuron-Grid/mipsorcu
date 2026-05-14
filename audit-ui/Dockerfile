FROM oven/bun:1.3.14-alpine AS builder

WORKDIR /work

COPY package.json bun.lock ./
RUN bun install --frozen-lockfile

COPY . .

ARG VITE_MIPSORCU_SUPABASE_URL=http://127.0.0.1:54321
ARG VITE_MIPSORCU_SUPABASE_PUBLISHABLE_KEY=local-dev-publishable-key
ARG VITE_MIPSORCU_AUDIT_API_BASE_URL=http://127.0.0.1:3000

ENV VITE_MIPSORCU_SUPABASE_URL=${VITE_MIPSORCU_SUPABASE_URL}
ENV VITE_MIPSORCU_SUPABASE_PUBLISHABLE_KEY=${VITE_MIPSORCU_SUPABASE_PUBLISHABLE_KEY}
ENV VITE_MIPSORCU_AUDIT_API_BASE_URL=${VITE_MIPSORCU_AUDIT_API_BASE_URL}

RUN bun run check && bun run test:guards && bun run build

FROM nginxinc/nginx-unprivileged:1.29-alpine AS runtime

COPY --from=builder /work/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 8080
