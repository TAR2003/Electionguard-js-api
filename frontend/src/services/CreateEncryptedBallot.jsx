import React from 'react';
import ServiceComponent from '../components/ServiceComponent';
import { SERVICES } from '../data/services';

function CreateEncryptedBallot({ pyodide }) {
  return <ServiceComponent 
    serviceName="createEncryptedBallot"
    serviceConfig={SERVICES.createEncryptedBallot}
    pyodide={pyodide}
  />;
}

export default CreateEncryptedBallot;
