FROM node:20-alpine AS deps

WORKDIR /app

COPY package*.json ./

RUN npm ci --frozen-lockfile --ignore-scripts --omit=dev


FROM node:20-alpine AS production

WORKDIR /app

ENV NODE_ENV=production

COPY --from=deps --chown=node:node /app/node_modules ./node_modules
COPY --chown=node:node package.json ./

COPY --chown=node:node . .

USER node

EXPOSE 3000

CMD ["node", "server.js"]