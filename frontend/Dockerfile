FROM node:20-slim AS build
WORKDIR /web
COPY package.json package-lock.json ./
RUN npm ci
COPY ./ ./
ARG VITE_API_BASE=""
ARG VITE_API_KEY=""
ENV VITE_API_BASE=$VITE_API_BASE VITE_API_KEY=$VITE_API_KEY
RUN npm run build

FROM node:20-slim
WORKDIR /web
COPY --from=build /web/dist ./dist
COPY --from=build /web/package.json /web/vite.config.js ./
RUN npm install -g vite@5.4.0
EXPOSE 5173
CMD ["vite", "preview", "--host", "0.0.0.0", "--port", "5173"]
