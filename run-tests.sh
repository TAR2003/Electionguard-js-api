#!/bin/bash

# ElectionGuard JavaScript API Test Runner
# This script starts the API and runs comprehensive tests

echo "🗳️  ElectionGuard JavaScript API Test Runner"
echo "=============================================="

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js 18+ first."
    exit 1
fi

# Check if npm is installed
if ! command -v npm &> /dev/null; then
    echo "❌ npm is not installed. Please install npm first."
    exit 1
fi

# Install dependencies if node_modules doesn't exist
if [ ! -d "node_modules" ]; then
    echo "📦 Installing dependencies..."
    npm install
    if [ $? -ne 0 ]; then
        echo "❌ Failed to install dependencies"
        exit 1
    fi
fi

# Create necessary directories
mkdir -p logs
mkdir -p test-results
mkdir -p data

echo "🚀 Starting ElectionGuard API..."

# Start the API in the background
npm start &
API_PID=$!

# Function to cleanup on exit
cleanup() {
    echo "🛑 Stopping API server..."
    kill $API_PID 2>/dev/null
    wait $API_PID 2>/dev/null
    echo "✅ Cleanup complete"
    exit $1
}

# Set up trap for cleanup
trap 'cleanup $?' EXIT

# Wait for API to start
echo "⏳ Waiting for API to start..."
sleep 5

# Check if API is running
if ! kill -0 $API_PID 2>/dev/null; then
    echo "❌ Failed to start API server"
    exit 1
fi

# Test if API is responding
echo "🏥 Testing API health..."
if curl -f -s http://localhost:3000/health > /dev/null; then
    echo "✅ API is healthy and ready"
else
    echo "⚠️  API might not be ready yet, waiting 5 more seconds..."
    sleep 5
    if curl -f -s http://localhost:3000/health > /dev/null; then
        echo "✅ API is healthy and ready"
    else
        echo "❌ API health check failed"
        exit 1
    fi
fi

# Run the comprehensive test suite
echo "🧪 Running comprehensive API tests..."
node test-api.js

TEST_EXIT_CODE=$?

if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo ""
    echo "🎉 All tests passed! ElectionGuard JavaScript API is working correctly."
    echo "📊 Test results have been saved to the test-results/ directory."
    echo "🔍 API logs can be found in the logs/ directory."
else
    echo ""
    echo "❌ Some tests failed. Please check the output above for details."
    echo "📊 Test results have been saved to the test-results/ directory."
fi

# Keep the API running for a bit to allow manual testing if needed
echo ""
echo "🌐 API is still running at http://localhost:3000"
echo "📚 API documentation: http://localhost:3000"
echo "💡 Press Ctrl+C to stop the API server"
echo ""

# Wait for user interrupt or let it run for 60 seconds
sleep 60 || true

exit $TEST_EXIT_CODE
