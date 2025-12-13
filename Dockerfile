FROM node:18-alpine

WORKDIR /app

# Install scanning tools
RUN apk add --no-cache nmap nmap-nping arp-scan iputils

# Copy package files and install dependencies
COPY package*.json ./
RUN npm install

# Copy the rest of the application
COPY src ./src
COPY static ./static
COPY data ./data
COPY tsconfig.json ./

# Install tsx globally
RUN npm install -g tsx

EXPOSE 4000

# Run the app with tsx
CMD ["tsx", "src/main.ts"]
