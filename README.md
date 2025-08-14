# ElectionGuard Frontend

This is a frontend-only implementation of ElectionGuard ballot encryption using React, Vite, and Pyodide to run Python code directly in the browser.

## Features

- **Frontend-Only Architecture**: No backend server required
- **Python in Browser**: Uses Pyodide to run ElectionGuard Python code in the browser
- **Interactive Interface**: Simple form to input JSON parameters and create encrypted ballots
- **Docker Support**: Easy deployment using Docker Compose

## Quick Start

### Using Docker Compose (Recommended)

1. Make sure Docker and Docker Compose are installed on your system
2. Navigate to the project root directory
3. Run the following command:

```bash
docker-compose up --build
```

4. Open your browser and go to `http://localhost:3000`

### Manual Setup

If you prefer to run without Docker:

1. Navigate to the frontend directory:
```bash
cd frontend
```

2. Install dependencies:
```bash
npm install
```

3. Start the development server:
```bash
npm run dev
```

4. Open your browser and go to `http://localhost:3000`

## Usage

1. **Load Sample Data**: Click the "Load Sample Data" button to populate the JSON input with example parameters
2. **Edit Parameters**: Modify the JSON parameters as needed:
   - `party_names`: Array of political party names
   - `candidate_names`: Array of candidate names
   - `candidate_name`: Name of the candidate to vote for (must be in candidate_names array)
   - `ballot_id`: Unique identifier for the ballot
   - `joint_public_key`: Public key for encryption (as string)
   - `commitment_hash`: Commitment hash (as string)
   - `number_of_guardians`: Number of election guardians
   - `quorum`: Minimum number of guardians required
3. **Create Encrypted Ballot**: Click the "Create Encrypted Ballot" button to process the parameters
4. **View Results**: The encrypted ballot and hash will be displayed below

## Sample JSON Input

```json
{
  "party_names": ["Democratic", "Republican", "Independent"],
  "candidate_names": ["Alice Johnson", "Bob Smith", "Carol Davis"],
  "candidate_name": "Alice Johnson",
  "ballot_id": "ballot-001",
  "joint_public_key": "12345678901234567890",
  "commitment_hash": "98765432109876543210",
  "number_of_guardians": 3,
  "quorum": 2
}
```

## Architecture

- **Frontend**: React + Vite for the user interface
- **Python Runtime**: Pyodide runs Python code directly in the browser
- **ElectionGuard Logic**: Simplified version of ElectionGuard functions optimized for browser execution
- **No Backend**: All processing happens client-side

## Development

### File Structure

```
frontend/
├── src/
│   ├── App.jsx              # Main React component
│   ├── main.jsx             # React entry point
│   ├── index.css            # Styles
│   └── python/
│       └── electionguard_service.py  # Python service code
├── public/                  # Static assets
├── Dockerfile              # Container configuration
├── package.json            # Node.js dependencies
├── vite.config.js          # Vite configuration
└── index.html              # HTML template
```

### Key Components

1. **App.jsx**: Main React component that handles the UI and Pyodide integration
2. **electionguard_service.py**: Simplified Python implementation of ElectionGuard functions
3. **Pyodide Integration**: Loads Python environment and executes ballot encryption logic

## Notes

- **First Load**: The initial page load may take some time as Pyodide downloads and initializes the Python runtime
- **Simplified Encryption**: This implementation uses simplified encryption for demonstration purposes
- **Browser Compatibility**: Requires a modern browser with WebAssembly support
- **Security**: This is a demonstration implementation; production use would require additional security considerations

## Troubleshooting

- **Slow Loading**: The first load can be slow due to Pyodide initialization. This is normal.
- **CORS Errors**: Make sure your browser supports the required CORS policies for Pyodide
- **JSON Errors**: Validate your JSON input using the browser's developer tools if you encounter parsing errors

## Production Considerations

For production deployment:

1. Use the production Dockerfile with built assets
2. Implement proper error handling and logging
3. Add input validation and sanitization
4. Consider using a CDN for static assets
5. Implement proper security headers

## Support

This is a demonstration implementation. For production ElectionGuard applications, refer to the official ElectionGuard documentation and repositories.
