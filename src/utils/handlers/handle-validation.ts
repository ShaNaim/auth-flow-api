export function isValueInObject<T extends Record<string, unknown>>(key: string, target: T): boolean {
    return Object.values(target).includes(key);
}
