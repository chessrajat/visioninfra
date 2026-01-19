import * as React from "react";

import { cn } from "@/lib/utils";

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "secondary" | "ghost";
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = "primary", ...props }, ref) => (
    <button
      ref={ref}
      className={cn(
        "inline-flex items-center justify-center rounded-full px-5 py-2 text-sm font-semibold transition",
        variant === "primary" &&
          "bg-gradient-to-r from-sky-500 to-purple-500 text-white shadow-lg shadow-sky-200/40 hover:from-sky-400 hover:to-purple-400",
        variant === "secondary" &&
          "bg-white/80 text-slate-900 ring-1 ring-slate-200 hover:bg-white",
        variant === "ghost" &&
          "bg-transparent text-slate-600 hover:text-slate-900",
        className,
      )}
      {...props}
    />
  ),
);
Button.displayName = "Button";

export { Button };
