import React from 'react';
import ServiceComponent from '../components/ServiceComponent';
import { SERVICES } from '../data/services';

function CreateEncryptedBallot({ pyodide }) {
  return <ServiceComponent 
    serviceName="create-encrypted-ballot"
    serviceConfig={SERVICES.createEncryptedBallot}
    pyodide={pyodide}
  />;
}

export default CreateEncryptedBallot;
