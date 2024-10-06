docker run \
    -e "SERVER_ENDPOINT=localhost:8014"   \
    -e "ACCESS_KEY=${ACCESS_KEY}" -e "SECRET_KEY=${SECRET_KEY}" \
    --network host \
    minio/mint:latest
