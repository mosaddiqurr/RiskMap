import * as React from "react";
import { cn } from "@/lib/utils";

export type ButtonProps = React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "secondary" | "ghost" | "danger";
  size?: "sm" | "md" | "lg";
};

const variants = {
  primary: "button-primary",
  secondary: "button-secondary",
  ghost: "button-ghost",
  danger: "button-danger"
};
const sizes = { sm: "h-8 px-3 text-xs", md: "h-10 px-4 text-sm", lg: "h-11 px-5 text-sm" };

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { className, variant = "primary", size = "md", type = "button", ...props },
  ref
) {
  return (
    <button
      ref={ref}
      type={type}
      className={cn(
        "ui-button inline-flex shrink-0 items-center justify-center gap-2 rounded-lg font-semibold transition disabled:cursor-not-allowed",
        variants[variant],
        sizes[size],
        className
      )}
      {...props}
    />
  );
});

export function buttonClass(
  variant: ButtonProps["variant"] = "primary",
  size: ButtonProps["size"] = "md"
) {
  return cn(
    "ui-button inline-flex shrink-0 items-center justify-center gap-2 rounded-lg font-semibold transition",
    variants[variant ?? "primary"],
    sizes[size ?? "md"]
  );
}
