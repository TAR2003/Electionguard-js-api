# ElectionGuard JavaScript API

A complete JavaScript implementation of the ElectionGuard cryptographic voting protocol with post-quantum security features.

## 🚀 Quick Start

### Prerequisites
- Node.js 18+ or Docker
- Docker Compose (optional)

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd Electionguard-javascript-api
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

### Running the API

#### Method 1: Direct Node.js
```bash
# Development mode
npm run dev

# Production mode
npm start
```

#### Method 2: Docker Compose (Recommended)
```bash
# Development environment
npm run docker:compose:dev

# Full production environment with Redis, PostgreSQL, monitoring
npm run docker:compose
```

#### Method 3: Docker only
```bash
# Build the image
npm run docker:build

# Run the container
npm run docker:run
```

The API will be available at: `http://localhost:3000`

## 🧪 Testing

### Run the comprehensive API test suite
```bash
# Start the API first
npm run dev

# In another terminal, run the tests
npm run test:api
```

### Run unit tests
```bash
npm test
```

### Run tests with coverage
```bash
npm run test:coverage
```

## 📚 API Endpoints

All endpoints match the Python ElectionGuard API:

### Guardian Management
- `POST /setup_guardians` - Setup guardian key ceremony
- `GET /health` - API health check

### Ballot Operations  
- `POST /create_encrypted_ballot` - Encrypt plaintext ballot
- `POST /create_encrypted_tally` - Create homomorphic tally

### Decryption Operations
- `POST /create_partial_decryption` - Generate partial decryption shares
- `POST /create_compensated_decryption` - Handle missing guardians
- `POST /combine_decryption_shares` - Combine shares for final results

### Generic Crypto Operations
- `POST /api/encrypt` - Generic data encryption
- `POST /api/decrypt` - Generic data decryption

## 🔧 Configuration

### Environment Variables
```bash
NODE_ENV=development
PORT=3000
API_KEY=your-secure-api-key
CORS_ORIGINS=http://localhost:3000
RATE_LIMIT_WINDOW=15
RATE_LIMIT_MAX=100
LOG_LEVEL=info
```

### Docker Compose Services

#### Development (`docker-compose.dev.yml`)
- **electionguard-api**: Main API service

#### Production (`docker-compose.yml`)
- **electionguard-api**: Main API service
- **redis**: Session management and caching
- **postgres**: Persistent data storage
- **nginx**: Reverse proxy and load balancer
- **prometheus**: Monitoring and metrics
- **grafana**: Monitoring dashboard

## 🔐 Security Features

### Post-Quantum Cryptography
- ML-KEM-1024 equivalent implementation
- Quantum-resistant encryption algorithms
- Future-proof cryptographic security

### Threshold Cryptography
- Shamir Secret Sharing
- Guardian key distribution
- Quorum-based decryption
- Missing guardian compensation

### Zero-Knowledge Proofs
- Disjunctive Chaum-Pedersen proofs
- Constant sum proofs
- Range proofs for vote validation
- Schnorr proofs for key authenticity

### End-to-End Verifiability
- Cryptographic audit trail
- Public verification without revealing votes
- Homomorphic tallying
- Individual ballot verification

## 📊 Test Suite Features

The `test-api.js` file provides comprehensive testing:

### Test Coverage
- ✅ Health check and API availability
- ✅ Guardian key ceremony setup
- ✅ Ballot encryption with zero-knowledge proofs
- ✅ Homomorphic tally creation
- ✅ Partial decryption share generation
- ✅ Threshold decryption and vote counting
- ✅ Generic encrypt/decrypt operations
- ✅ Election result validation

### Test Data
- Sample election manifest with contests and candidates
- Multiple test ballots with different vote patterns
- Expected result validation
- Performance metrics and timing

### Test Output
- Detailed test logs with timestamps
- Performance metrics for each operation
- JSON test results saved to `./test-results/`
- Pass/fail status for all operations

## 🏗️ Architecture

### Core Modules (`electionguard/`)
- **group.js**: Mathematical group operations
- **elgamal.js**: ElGamal encryption scheme
- **ballot.js**: Ballot data structures
- **manifest.js**: Election descriptions
- **guardian.js**: Key ceremony management
- **encrypt.js**: Ballot encryption with proofs
- **decryption.js**: Threshold decryption
- **tally.js**: Homomorphic tallying

### Services (`services/`)
- **setup_guardians.js**: Guardian ceremony orchestration
- **create_encrypted_ballot.js**: Ballot encryption service
- **create_encrypted_tally.js**: Tally creation service
- **create_partial_decryption.js**: Decryption share service
- **create_compensated_decryption_shares.js**: Missing guardian handling
- **combine_decryption_shares.js**: Final decryption service

## 🔍 Monitoring & Observability

When using the full Docker Compose setup:

- **Grafana Dashboard**: `http://localhost:3001` (admin/admin)
- **Prometheus Metrics**: `http://localhost:9090`
- **API Health**: `http://localhost:3000/health`

## 🐛 Troubleshooting

### Common Issues

1. **Port already in use**
   ```bash
   # Check what's using port 3000
   lsof -i :3000
   # Or use a different port
   PORT=3001 npm start
   ```

2. **Docker permissions on Windows**
   ```bash
   # Run Docker Desktop as administrator
   # Or use WSL2 backend
   ```

3. **Test failures**
   ```bash
   # Ensure API is running first
   npm run dev
   # Wait for "Server running on port 3000"
   # Then run tests in another terminal
   npm run test:api
   ```

### Debug Mode
```bash
LOG_LEVEL=debug npm run dev
```

## 📄 License

This project implements the ElectionGuard cryptographic protocol. Please refer to the original ElectionGuard license terms.

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

---

For more information about ElectionGuard, visit: https://www.electionguard.vote/
