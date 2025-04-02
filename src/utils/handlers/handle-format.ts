const timeUnits = [
    { divisor: 31536000, unit: 'year' },
    { divisor: 2592000, unit: 'month' }, // Assuming 30-day months
    { divisor: 86400, unit: 'day' },
    { divisor: 3600, unit: 'hour' },
    { divisor: 60, unit: 'minute' },
    { divisor: 1, unit: 'second' }
];

export function millisecondsToStrAI(milliseconds: number) {
    let seconds = Math.floor(milliseconds / 1000);
    const parts = [];
    for (const { divisor, unit } of timeUnits) {
        const value = Math.floor(seconds / divisor);
        if (value > 0) {
            parts.push(`${value} ${unit}${value > 1 ? 's' : ''}`);
            seconds %= divisor;
        }
    }
    return parts.length > 0 ? parts.join(' ') : 'less than a second';
}
