import bcrypt from "bcryptjs";
import { createHmac, randomBytes } from "node:crypto";
import { cookies } from "next/headers";
import { prisma } from "@/lib/db";
import { env, secureCookies } from "@/lib/env";

export const SESSION_COOKIE = env.SESSION_COOKIE_NAME;

export function hashSessionToken(token: string) {
  return createHmac("sha256", env.SESSION_SECRET).update(token).digest("hex");
}

export async function hashPassword(password: string) {
  return bcrypt.hash(password, 12);
}

export async function verifyPassword(password: string, passwordHash: string) {
  return bcrypt.compare(password, passwordHash);
}

export async function createSession(userId: string) {
  const token = randomBytes(32).toString("base64url");
  const expiresAt = new Date(Date.now() + env.SESSION_TTL_HOURS * 60 * 60 * 1000);
  await prisma.session.create({
    data: { userId, tokenHash: hashSessionToken(token), expiresAt }
  });
  return { token, expiresAt };
}

export async function getUserFromSessionToken(token: string | undefined) {
  if (!token) return null;
  const session = await prisma.session.findUnique({
    where: { tokenHash: hashSessionToken(token) },
    include: { user: true }
  });
  if (!session || session.expiresAt <= new Date() || session.user.deletedAt) {
    if (session)
      await prisma.session.delete({ where: { id: session.id } }).catch(() => undefined);
    return null;
  }
  return session.user;
}

export async function getCurrentUser() {
  const store = await cookies();
  return getUserFromSessionToken(store.get(SESSION_COOKIE)?.value);
}

export async function deleteSession(token: string | undefined) {
  if (!token) return;
  await prisma.session.deleteMany({ where: { tokenHash: hashSessionToken(token) } });
}

export function sessionCookieOptions(expiresAt?: Date) {
  return {
    httpOnly: true,
    sameSite: "lax" as const,
    secure: secureCookies,
    path: "/",
    expires: expiresAt
  };
}
