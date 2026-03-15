FROM node:22-alpine
RUN apk add --no-cache curl
WORKDIR /app
COPY package.json server.js ./
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1
CMD ["node", "server.js"]
