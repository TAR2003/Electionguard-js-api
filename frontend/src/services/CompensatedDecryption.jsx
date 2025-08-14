import React from 'react';
import ServiceComponent from '../components/ServiceComponent';
import { SERVICES } from '../data/services';

function CompensatedDecryption({ pyodide }) {
  return <ServiceComponent 
    serviceName="compensated-decryption"
    serviceConfig={SERVICES.compensatedDecryption}
    pyodide={pyodide}
  />;
}

export default CompensatedDecryption;
