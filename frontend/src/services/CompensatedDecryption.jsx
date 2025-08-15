import React from 'react';
import ServiceComponent from '../components/ServiceComponent';
import { SERVICES } from '../data/services';

function CompensatedDecryption({ pyodide }) {
  return <ServiceComponent 
    serviceName="compensatedDecryption"
    serviceConfig={SERVICES.compensatedDecryption}
    pyodide={pyodide}
  />;
}

export default CompensatedDecryption;
