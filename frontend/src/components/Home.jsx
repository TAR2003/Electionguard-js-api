import React from 'react';
import { Link } from 'react-router-dom';
import { SERVICES } from '../data/services';

function Home() {
  return (
    <div className="home-container">
      <div className="hero-section">
        <h2>ElectionGuard Frontend Demo</h2>
        <p>
          This frontend demonstrates all ElectionGuard services running in the browser using Pyodide. 
          Each service processes cryptographic operations for secure elections without requiring a backend server.
        </p>
      </div>

      <div className="services-grid">
        {Object.entries(SERVICES).map(([serviceKey, service]) => (
          <div key={serviceKey} className="service-card">
            <h3>{service.name}</h3>
            <p className="service-description">{service.description}</p>
            <Link to={service.route} className="service-link">
              Try {service.shortName} →
            </Link>
          </div>
        ))}
      </div>

      <div className="tech-info">
        <h3>Technology Stack</h3>
        <ul>
          <li><strong>Pyodide:</strong> Python running in the browser via WebAssembly</li>
          <li><strong>ElectionGuard:</strong> End-to-end verifiable election library</li>
          <li><strong>React:</strong> Modern UI framework with routing</li>
          <li><strong>Vite:</strong> Fast build tool with development server</li>
          <li><strong>Docker:</strong> Containerized deployment</li>
        </ul>
      </div>
    </div>
  );
}

export default Home;
