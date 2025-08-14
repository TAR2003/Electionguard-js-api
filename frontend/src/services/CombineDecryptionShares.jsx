import React from 'react';
import ServiceComponent from '../components/ServiceComponent';
import { SERVICES } from '../data/services';

function CombineDecryptionShares({ pyodide }) {
  return <ServiceComponent 
    serviceName="combine-decryption-shares"
    serviceConfig={SERVICES.combineDecryptionShares}
    pyodide={pyodide}
  />;
}

export default CombineDecryptionShares;
