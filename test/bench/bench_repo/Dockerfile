# Многоступенчатая сборка: компиляторы остаются в build-stage
FROM redos/redos:7.3 AS build
RUN dnf install -y gcc make nodejs npm && dnf clean all
WORKDIR /src
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM redos/redos:7.3
RUN dnf install -y nodejs && dnf clean all \
    && useradd --system --uid 10001 --create-home appuser
WORKDIR /app
COPY --from=build /src/dist ./dist
COPY --from=build /src/node_modules ./node_modules

USER appuser
EXPOSE 8080
HEALTHCHECK CMD ["node", "dist/healthcheck.js"]
CMD ["node", "dist/main.js"]
