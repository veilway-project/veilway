export type Rgb = {r: number, g: number, b: number};

export const BLACK: Rgb = {r: 0, g: 0, b: 0};
export const WHITE: Rgb = {r: 255, g: 255, b: 255};

// The only colour syntax a theme may use. Anything else (names, rgb(), var(), 3 or 8 digits) is refused.
export function parseHex(input: unknown): Rgb | null {
	if (typeof input !== "string" || !/^#[0-9a-fA-F]{6}$/.test(input)) return null;
	return {r: parseInt(input.slice(1, 3), 16), g: parseInt(input.slice(3, 5), 16), b: parseInt(input.slice(5, 7), 16)};
}

export function toHex(c: Rgb): string {
	return "#" + [c.r, c.g, c.b].map(v => Math.round(Math.min(255, Math.max(0, v))).toString(16).padStart(2, "0")).join("");
}

export function luminance(c: Rgb): number {
	const [r, g, b] = [c.r, c.g, c.b].map(v => (v / 255 <= 0.04045 ? v / 255 / 12.92 : ((v / 255 + 0.055) / 1.055) ** 2.4)) as [number, number, number];
	return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

export function contrast(a: Rgb, b: Rgb): number {
	const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number];
	return (hi + 0.05) / (lo + 0.05);
}

// Straight sRGB mix, the same result as CSS color-mix(in srgb, b t%, a) for opaque colours.
export function mix(a: Rgb, b: Rgb, t: number): Rgb {
	return {r: a.r + (b.r - a.r) * t, g: a.g + (b.g - a.g) * t, b: a.b + (b.b - a.b) * t};
}

// The CSS saturate() filter as backdrop-filter applies it: every channel moves away from the pixel's luma by the factor s, on the encoded values.
export function saturate(c: Rgb, s: number): Rgb {
	const luma = 0.213 * c.r + 0.715 * c.g + 0.072 * c.b;
	return {r: Math.min(255, Math.max(0, luma + (c.r - luma) * s)), g: Math.min(255, Math.max(0, luma + (c.g - luma) * s)), b: Math.min(255, Math.max(0, luma + (c.b - luma) * s))};
}
