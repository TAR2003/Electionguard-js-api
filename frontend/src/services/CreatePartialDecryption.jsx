import React from 'react';
import ServiceComponent from '../components/ServiceComponent';
import { SERVICES } from '../data/services';

function CreatePartialDecryption({ pyodide }) {
  return <ServiceComponent 
    serviceName="create-partial-decryption"
    serviceConfig={SERVICES.createPartialDecryption}
    pyodide={pyodide}
  />;
}

export default CreatePartialDecryption;
