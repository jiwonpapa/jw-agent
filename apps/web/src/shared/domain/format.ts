const dateTimeFormatter = new Intl.DateTimeFormat("ko-KR", {
  dateStyle: "medium",
  timeStyle: "medium",
});

const numberFormatter = new Intl.NumberFormat("ko-KR", {
  maximumFractionDigits: 1,
});

const bytesFormatter = new Intl.NumberFormat("ko-KR", {
  style: "unit",
  unit: "gigabyte",
  maximumFractionDigits: 1,
});

export function formatDateTime(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? "알 수 없음" : dateTimeFormatter.format(date);
}

export function formatBytes(value: number): string {
  return bytesFormatter.format(value / 1_073_741_824);
}

export function formatPercent(available: number, total: number): string {
  if (total <= 0) return "알 수 없음";
  const used = Math.max(0, total - available);
  return `${numberFormatter.format((used / total) * 100)}% 사용`;
}

export function formatDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return "알 수 없음";
  const days = Math.floor(seconds / 86_400);
  const hours = Math.floor((seconds % 86_400) / 3_600);
  if (days > 0) return `${numberFormatter.format(days)}일 ${numberFormatter.format(hours)}시간`;
  return `${numberFormatter.format(hours)}시간`;
}
