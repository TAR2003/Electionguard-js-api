# ElectionGuard JavaScript API Test Runner (PowerShell)
# This script starts the API and runs comprehensive tests

Write-Host "🗳️  ElectionGuard JavaScript API Test Runner" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan

# Check if Node.js is installed
try {
    $nodeVersion = node --version
    Write-Host "✅ Node.js version: $nodeVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ Node.js is not installed. Please install Node.js 18+ first." -ForegroundColor Red
    exit 1
}

# Check if npm is installed
try {
    $npmVersion = npm --version
    Write-Host "✅ npm version: $npmVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ npm is not installed. Please install npm first." -ForegroundColor Red
    exit 1
}

# Install dependencies if node_modules doesn't exist
if (-not (Test-Path "node_modules")) {
    Write-Host "📦 Installing dependencies..." -ForegroundColor Yellow
    npm install
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Failed to install dependencies" -ForegroundColor Red
        exit 1
    }
}

# Create necessary directories
New-Item -ItemType Directory -Force -Path "logs" | Out-Null
New-Item -ItemType Directory -Force -Path "test-results" | Out-Null
New-Item -ItemType Directory -Force -Path "data" | Out-Null

Write-Host "🚀 Starting ElectionGuard API..." -ForegroundColor Yellow

# Start the API in the background
$apiProcess = Start-Process -FilePath "npm" -ArgumentList "start" -PassThru -WindowStyle Hidden

# Function to cleanup on exit
function Cleanup {
    param($ExitCode)
    Write-Host "🛑 Stopping API server..." -ForegroundColor Yellow
    try {
        Stop-Process -Id $apiProcess.Id -Force -ErrorAction SilentlyContinue
        Write-Host "✅ Cleanup complete" -ForegroundColor Green
    } catch {
        Write-Host "⚠️  Process may have already stopped" -ForegroundColor Yellow
    }
    exit $ExitCode
}

# Register cleanup for Ctrl+C
$null = Register-EngineEvent PowerShell.Exiting -Action { Cleanup 0 }

# Wait for API to start
Write-Host "⏳ Waiting for API to start..." -ForegroundColor Yellow
Start-Sleep -Seconds 5

# Check if API process is still running
if ($apiProcess.HasExited) {
    Write-Host "❌ Failed to start API server" -ForegroundColor Red
    exit 1
}

# Test if API is responding
Write-Host "🏥 Testing API health..." -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod -Uri "http://localhost:3000/health" -Method Get -TimeoutSec 10
    if ($response.status -eq "OK") {
        Write-Host "✅ API is healthy and ready" -ForegroundColor Green
    } else {
        throw "API returned unexpected status"
    }
} catch {
    Write-Host "⚠️  API might not be ready yet, waiting 5 more seconds..." -ForegroundColor Yellow
    Start-Sleep -Seconds 5
    try {
        $response = Invoke-RestMethod -Uri "http://localhost:3000/health" -Method Get -TimeoutSec 10
        if ($response.status -eq "OK") {
            Write-Host "✅ API is healthy and ready" -ForegroundColor Green
        } else {
            throw "API returned unexpected status"
        }
    } catch {
        Write-Host "❌ API health check failed: $_" -ForegroundColor Red
        Cleanup 1
    }
}

# Run the comprehensive test suite
Write-Host "🧪 Running comprehensive API tests..." -ForegroundColor Yellow
$testProcess = Start-Process -FilePath "node" -ArgumentList "test-api.js" -Wait -PassThru -NoNewWindow

$testExitCode = $testProcess.ExitCode

if ($testExitCode -eq 0) {
    Write-Host "" 
    Write-Host "🎉 All tests passed! ElectionGuard JavaScript API is working correctly." -ForegroundColor Green
    Write-Host "📊 Test results have been saved to the test-results/ directory." -ForegroundColor Cyan
    Write-Host "🔍 API logs can be found in the logs/ directory." -ForegroundColor Cyan
} else {
    Write-Host ""
    Write-Host "❌ Some tests failed. Please check the output above for details." -ForegroundColor Red
    Write-Host "📊 Test results have been saved to the test-results/ directory." -ForegroundColor Cyan
}

# Keep the API running for a bit to allow manual testing if needed
Write-Host ""
Write-Host "🌐 API is still running at http://localhost:3000" -ForegroundColor Cyan
Write-Host "📚 You can now test the API manually or run additional tests" -ForegroundColor Cyan
Write-Host "💡 Press Ctrl+C to stop the API server" -ForegroundColor Yellow
Write-Host ""

# Wait for user interrupt or let it run for 60 seconds
try {
    Start-Sleep -Seconds 60
} catch {
    # User pressed Ctrl+C
}

Cleanup $testExitCode
