FROM node:20-slim AS build
WORKDIR /web
COPY frontend/package.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build

FROM node:20-slim
WORKDIR /web
COPY --from=build /web/dist ./dist
COPY --from=build /web/package.json /web/vite.config.js ./
RUN npm install --omit=dev && npm install -g vite@5.4.0 || true
EXPOSE 5173
CMD ["npx", "vite", "preview", "--host", "0.0.0.0", "--port", "5173"]
