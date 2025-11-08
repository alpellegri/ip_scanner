# R43: Makefile per build e docker

.PHONY: all run clean docker docker-run docker-compose

all: run

run:
	npm install
	# Run with tsx for ESM and TS support
	sudo npx tsx src/main.ts

clean:
	rm -rf node_modules dist

docker:
	docker build -t ip_scanner .

docker-run:
	docker run --rm -it --network host --cap-add=NET_RAW -v $(PWD)/data:/app/data ip_scanner

# Avvia i servizi tramite docker-compose
docker-compose:
	docker compose up --build

# Tag Docker image for GitHub Container Registry
docker-tag:
	docker tag ip_scanner ghcr.io/alpellegri/ip_scanner:latest

# Push Docker image to GitHub Container Registry
docker-push: docker-tag
	docker push ghcr.io/alpellegri/ip_scanner:latest
