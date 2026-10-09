// Cytoscape extensions that ship without type declarations. Each default export is the
// registration function passed to `cytoscape.use()`; the APIs they add to `Core` are
// declared in `cytoscape-core-extensions.d.ts`.

declare module 'cytoscape-fcose' {
  const register: import('cytoscape').Ext;
  export default register;
}

declare module 'cytoscape-klay' {
  const register: import('cytoscape').Ext;
  export default register;
}

declare module 'cytoscape-expand-collapse' {
  const register: import('cytoscape').Ext;
  export default register;
}

declare module 'cytoscape-context-menus' {
  const register: import('cytoscape').Ext;
  export default register;
}
