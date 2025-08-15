import React, { useState, useEffect } from 'react';
import Editor from '@monaco-editor/react';

function ServiceComponent({ serviceName, serviceConfig, pyodide }) {
  const [jsonInput, setJsonInput] = useState('');
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [processing, setProcessing] = useState(false);

  useEffect(() => {
    // Load sample data when component mounts
    setJsonInput(JSON.stringify(serviceConfig.sampleRequest, null, 2));
  }, [serviceConfig.sampleRequest]);

  const processRequest = async () => {
    if (!pyodide) {
      setError('Python environment not initialized');
      return;
    }

    setProcessing(true);
    setError(null);
    setResult(null);

    try {
      // Validate JSON
      JSON.parse(jsonInput);
      
      console.log(`Processing ${serviceName} with input:`, jsonInput);
      
      // Set the JSON input as a Python variable to avoid escaping issues
      pyodide.globals.set('json_input', jsonInput);
      
      // Call the appropriate Python function based on service
      const functionName = `process_${serviceName.replace(/-/g, '_')}_request`;
      
      const pythonResult = pyodide.runPython(`
result = ${functionName}(json_input) if '${functionName}' in globals() else process_generic_request(json_input, '${serviceName}')
result
      `);
      
      console.log(`${serviceName} result:`, pythonResult);
      
      const parsedResult = JSON.parse(pythonResult);
      setResult(parsedResult);
      
      if (parsedResult.status === 'error') {
        setError(parsedResult.error);
      }
      
    } catch (err) {
      console.error(`Error processing ${serviceName}:`, err);
      setError(`Error processing request: ${err.message}`);
    } finally {
      setProcessing(false);
    }
  };

  const loadSampleData = () => {
    setJsonInput(JSON.stringify(serviceConfig.sampleRequest, null, 2));
    setError(null);
    setResult(null);
  };

  return (
    <div className="service-container">
      <div className="service-header">
        <h2>{serviceConfig.name}</h2>
        <p className="service-description">{serviceConfig.description}</p>
      </div>
      
      <div className="form-group">
        <label htmlFor={`json-input-${serviceName}`}>JSON Parameters:</label>
        <div className="editor-container">
          <Editor
            height="300px"
            defaultLanguage="json"
            value={jsonInput}
            onChange={(value) => setJsonInput(value || '')}
            options={{
              minimap: { enabled: false },
              scrollBeyondLastLine: false,
              fontSize: 14,
              wordWrap: 'on',
              formatOnPaste: true,
              formatOnType: true
            }}
          />
        </div>
      </div>
      
      <div className="button-group">
        <button onClick={loadSampleData} className="secondary-button">
          Load Sample Data
        </button>
        <button 
          onClick={processRequest} 
          disabled={processing || !pyodide}
          className="primary-button"
        >
          {processing ? 'Processing...' : `Process ${serviceConfig.name}`}
        </button>
      </div>

      {error && (
        <div className="error">
          <h3>Error:</h3>
          <p>{error}</p>
        </div>
      )}

      {result && result.status === 'success' && (
        <div className="success">
          <h3>Request Processed Successfully!</h3>
          {result.hash && <p><strong>Hash:</strong> {result.hash}</p>}
          {result.ballot_hash && <p><strong>Ballot Hash:</strong> {result.ballot_hash}</p>}
        </div>
      )}

      {result && (
        <div className="result-container">
          <h3>Result:</h3>
          <div className="result-editor">
            <Editor
              height="400px"
              defaultLanguage="json"
              value={JSON.stringify(result, null, 2)}
              options={{
                readOnly: true,
                minimap: { enabled: false },
                scrollBeyondLastLine: false,
                fontSize: 14,
                wordWrap: 'on'
              }}
            />
          </div>
        </div>
      )}
    </div>
  );
}

export default ServiceComponent;
