#!/bin/bash

echo "Starting ElectionGuard Frontend..."
echo "================================="

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "Error: Docker is not running. Please start Docker and try again."
    exit 1
fi

# Check if Docker Compose is available
if ! command -v docker-compose > /dev/null 2>&1; then
    echo "Error: Docker Compose is not installed."
    exit 1
fi

echo "Building and starting the frontend container..."
docker-compose up --build

echo ""
echo "Frontend should be available at: http://localhost:3000"
echo "Press Ctrl+C to stop the container."
