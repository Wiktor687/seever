# Etap 1: Build + instalacja zależności
FROM node:24-alpine AS builder

WORKDIR /app

# Kopiuj tylko package*.json – to pozwala skorzystać z cache
COPY package*.json ./

# Instaluj tylko produkcyjne zależności
RUN npm install --production && npm cache clean --force && \
    find node_modules -type d -name "test" -o -name "__tests__" | xargs rm -rf && \
    find node_modules -type f -name "*.md" -o -name "*.ts" | xargs rm -f

# Skopiuj resztę plików aplikacji
COPY server.js ./

# Etap 2: Czysty, lekki obraz
FROM node:24-alpine

WORKDIR /app

# Skopiuj tylko zbudowaną aplikację + node_modules z buildera
COPY --from=builder /app /app

# Ustaw port
EXPOSE 3000

# Uruchom aplikację
CMD [ "npm", "start" ]