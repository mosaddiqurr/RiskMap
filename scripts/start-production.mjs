import { cpSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const args = process.argv.slice(2);
function option(name, fallback) {
  const index = args.indexOf(name);
  if (index < 0) return fallback;
  if (!args[index + 1]) throw new Error(`Missing ${name} value.`);
  return args[index + 1];
}
const port = Number(option("--port", process.env.PORT || "3000"));
if (!Number.isInteger(port) || port < 1 || port > 65535)
  throw new Error("Invalid server port.");
process.env.PORT = String(port);
process.env.HOSTNAME = option("--hostname", "0.0.0.0");
process.env.NODE_ENV = "production";
const standalone = path.join(root, ".next", "standalone");
const server = path.join(standalone, "server.js");
if (!existsSync(server)) throw new Error("Run npm run build before production startup.");
cpSync(path.join(root, "public"), path.join(standalone, "public"), { recursive: true });
cpSync(path.join(root, ".next", "static"), path.join(standalone, ".next", "static"), {
  recursive: true
});
await import(pathToFileURL(server).href);
