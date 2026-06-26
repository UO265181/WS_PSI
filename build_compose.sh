docker compose down
docker builder prune
docker build -t ws-psi .
docker compose up