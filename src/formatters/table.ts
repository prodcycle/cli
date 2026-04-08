export function formatTable(report: any): string {
  // Simplistic table formatter
  if (!report) return 'No report data';
  return `Scan Results: ${report.summary?.passed || 0} passed, ${report.summary?.failed || 0} failed.`;
}
