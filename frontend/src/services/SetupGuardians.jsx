import React from 'react';
import ServiceComponent from '../components/ServiceComponent';
import { SERVICES } from '../data/services';

function SetupGuardians({ pyodide }) {
  return <ServiceComponent 
    serviceName="setupGuardians"
    serviceConfig={SERVICES.setupGuardians}
    pyodide={pyodide}
  />;
}

export default SetupGuardians;
