import React from 'react';
import ServiceComponent from '../components/ServiceComponent';
import { SERVICES } from '../data/services';

function CreateCompensatedDecryption({ pyodide }) {
  return <ServiceComponent 
    serviceName="create-compensated-decryption"
    serviceConfig={SERVICES.createCompensatedDecryption}
    pyodide={pyodide}
  />;
}

export default CreateCompensatedDecryption;
