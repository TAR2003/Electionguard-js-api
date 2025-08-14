import React from 'react';
import ServiceComponent from '../components/ServiceComponent';
import { SERVICES } from '../data/services';

function PartialDecryption({ pyodide }) {
  return <ServiceComponent 
    serviceName="partial-decryption"
    serviceConfig={SERVICES.partialDecryption}
    pyodide={pyodide}
  />;
}

export default PartialDecryption;
