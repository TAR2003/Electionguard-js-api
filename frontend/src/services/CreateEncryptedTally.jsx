import React from 'react';
import ServiceComponent from '../components/ServiceComponent';
import { SERVICES } from '../data/services';

function CreateEncryptedTally({ pyodide }) {
  return <ServiceComponent 
    serviceName="createEncryptedTally"
    serviceConfig={SERVICES.createEncryptedTally}
    pyodide={pyodide}
  />;
}

export default CreateEncryptedTally;
