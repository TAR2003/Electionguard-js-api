import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { SERVICES } from '../data/services';

function Navigation() {
  const location = useLocation();

  return (
    <nav className="navigation">
      <div className="nav-container">
        <Link to="/" className="nav-logo">
          <h1>ElectionGuard Frontend</h1>
        </Link>
        
        <div className="nav-links">
          <Link 
            to="/" 
            className={location.pathname === '/' ? 'nav-link active' : 'nav-link'}
          >
            Home
          </Link>
          
          {Object.entries(SERVICES).map(([serviceKey, service]) => (
            <Link 
              key={serviceKey}
              to={service.route}
              className={location.pathname === service.route ? 'nav-link active' : 'nav-link'}
            >
              {service.shortName}
            </Link>
          ))}
        </div>
      </div>
    </nav>
  );
}

export default Navigation;
