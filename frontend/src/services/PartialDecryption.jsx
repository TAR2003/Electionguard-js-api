import React from 'react';
import ServiceComponent from '../components/ServiceComponent';
import { SERVICES } from '../data/services';

function PartialDecryption({ pyodide }) {
  return <ServiceComponent 
    serviceName="partialDecryption"
    serviceConfig={SERVICES.partialDecryption}
    pyodide={pyodide}
  />;
}

export default PartialDecryption;
