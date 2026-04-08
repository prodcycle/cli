export function formatPrompt(report: any): string {
  if (!report) return '';
  return 'Please fix the compliance issues found in this repository.';
}
