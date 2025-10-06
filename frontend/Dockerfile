# syntax=docker/dockerfile:1

FROM node:24-alpine

WORKDIR /app

EXPOSE 3000

ENV NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000

CMD ["sh", "-c", "if [ ! -d node_modules ]; then npm ci; fi; npm run dev"]