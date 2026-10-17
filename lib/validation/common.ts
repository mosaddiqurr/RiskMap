import { z } from "zod";

export const domainSchema = z
  .string()
  .trim()
  .toLowerCase()
  .max(253)
  .refine((value) => !value.includes("://"), "Enter a domain without http:// or https://")
  .refine(
    (value) =>
      /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(
        value
      ) || /^[a-z0-9-]+\.test$/i.test(value),
    "Enter a valid root domain"
  );

export const passwordSchema = z
  .string()
  .min(10, "Password must be at least 10 characters")
  .max(128)
  .regex(/[A-Z]/, "Include an uppercase letter")
  .regex(/[a-z]/, "Include a lowercase letter")
  .regex(/[0-9]/, "Include a number")
  .regex(/[^A-Za-z0-9]/, "Include a symbol");

export const idSchema = z.string().cuid();
