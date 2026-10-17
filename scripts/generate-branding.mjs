import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import sharp from "sharp";

// Run with `node scripts/generate-branding.mjs` after updating the supplied artwork.
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const source = await readFile(path.join(root, "assets", "logo.png"));
const metadata = await sharp(source).metadata();
if (metadata.width !== 1254 || metadata.height !== 1254) {
  throw new Error("Update the symbol crop for the dimensions of the new RiskMap artwork.");
}

// The supplied logo's map ends at row 903; its wordmark starts at row 904.
// Keep the original artwork intact and omit tiny lettering from the compact icons.
const cropped = await sharp(source)
  .extract({ left: 0, top: 0, width: metadata.width, height: 904 })
  .png()
  .toBuffer();
const symbol = await sharp(cropped).trim().png().toBuffer();
const pngOptions = { compressionLevel: 9, adaptiveFiltering: true };
await sharp(symbol)
  .resize({ width: 176 })
  .png(pngOptions)
  .toFile(path.join(root, "assets", "riskmap-mark.png"));

async function icon(size, background = { r: 0, g: 0, b: 0, alpha: 0 }) {
  const padding = Math.round(size * 0.08);
  const image = sharp(symbol)
    .resize(size - padding * 2, size - padding * 2, {
      fit: "contain",
      background
    })
    .extend({ top: padding, bottom: padding, left: padding, right: padding, background });
  if (background.alpha === 1) image.flatten({ background });
  return image.png(pngOptions).toBuffer();
}

const faviconSizes = [16, 32, 48];
const faviconImages = [];
for (const size of faviconSizes) faviconImages.push(await icon(size));

// PNG-backed ICO entries support legacy favicon discovery at /favicon.ico.
const directory = Buffer.alloc(6 + faviconSizes.length * 16);
directory.writeUInt16LE(1, 2);
directory.writeUInt16LE(faviconSizes.length, 4);
let offset = directory.length;
for (let index = 0; index < faviconSizes.length; index++) {
  const entry = 6 + index * 16;
  directory[entry] = faviconSizes[index];
  directory[entry + 1] = faviconSizes[index];
  directory.writeUInt16LE(1, entry + 4);
  directory.writeUInt16LE(32, entry + 6);
  directory.writeUInt32LE(faviconImages[index].length, entry + 8);
  directory.writeUInt32LE(offset, entry + 12);
  offset += faviconImages[index].length;
}
await writeFile(
  path.join(root, "public", "favicon.ico"),
  Buffer.concat([directory, ...faviconImages])
);
await writeFile(path.join(root, "public", "favicon-32x32.png"), faviconImages[1]);

const scalableIcon = await icon(256);
await writeFile(
  path.join(root, "public", "favicon.svg"),
  `<svg xmlns="http://www.w3.org/2000/svg" width="256" height="256" viewBox="0 0 256 256"><image width="256" height="256" href="data:image/png;base64,${scalableIcon.toString("base64")}"/></svg>\n`
);
await writeFile(
  path.join(root, "public", "apple-touch-icon.png"),
  await icon(180, { r: 255, g: 255, b: 255, alpha: 1 })
);
await writeFile(
  path.join(root, "assets", "branding.json"),
  `${JSON.stringify({ version: createHash("sha256").update(source).digest("hex").slice(0, 12) }, null, 2)}\n`
);
console.log("Generated RiskMap header artwork, SVG/PNG/ICO favicons and Apple touch icon.");
