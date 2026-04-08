export function formatSarif(report: any): any {
  return {
    version: '2.1.0',
    runs: [{ tool: { driver: { name: 'ProdCycle Compliance Scanner' } }, results: [] }]
  };
}
