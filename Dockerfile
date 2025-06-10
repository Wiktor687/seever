# Użyj oficjalnego obrazu Node.js
FROM node:24-alpine

# Ustaw katalog roboczy
WORKDIR /usr/src/app

# Skopiuj pliki
COPY package*.json ./
RUN npm install
COPY server.js ./

# Ustaw port
EXPOSE 3000

# Uruchom aplikację
CMD [ "npm", "start" ]