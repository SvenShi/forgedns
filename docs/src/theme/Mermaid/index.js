import React from 'react';
import BrowserOnly from '@docusaurus/BrowserOnly';
import Mermaid from '@theme-original/Mermaid';

function MermaidFallback({value}) {
  return <pre>{value}</pre>;
}

export default function MermaidWrapper(props) {
  return (
    <BrowserOnly fallback={<MermaidFallback value={props.value} />}>
      {() => <Mermaid {...props} />}
    </BrowserOnly>
  );
}
