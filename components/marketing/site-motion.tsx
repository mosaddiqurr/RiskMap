"use client";

import { useEffect, useRef } from "react";
import { usePathname } from "next/navigation";

/** Ambient signals communicate connected exposure. No animation work enters React state. */
export function SignalField() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    const context = canvas?.getContext("2d");
    if (!canvas || !context) return;
    let frame = 0;
    let width = 0;
    let height = 0;
    let visible = true;
    let lastFrame = 0;
    const points = Array.from({ length: 54 }, (_, i) => ({
      x: ((i * 163 + 41) % 997) / 997,
      y: ((i * 283 + 19) % 991) / 991,
      phase: i * 1.7
    }));

    function draw(time: number) {
      if (!context || !canvas) return;
      context.clearRect(0, 0, width, height);
      const t = time * 0.000055;
      const positions = points.map((p) => ({
        x: p.x * width + Math.sin(t + p.phase) * 22,
        y: p.y * height + Math.cos(t * 0.7 + p.phase) * 19
      }));
      for (let i = 0; i < positions.length; i++) {
        const p = positions[i]!;
        for (let j = i + 1; j < positions.length; j++) {
          const q = positions[j]!;
          const distance = Math.hypot(p.x - q.x, p.y - q.y);
          if (distance > 170) continue;
          context.strokeStyle = `rgba(84, 135, 220, ${(1 - distance / 170) * 0.2})`;
          context.beginPath();
          context.moveTo(p.x, p.y);
          context.lineTo(q.x, q.y);
          context.stroke();
        }
        context.fillStyle = "rgba(115, 167, 255, .46)";
        context.beginPath();
        context.arc(p.x, p.y, i % 7 === 0 ? 2 : 1, 0, Math.PI * 2);
        context.fill();
      }
    }

    function tick(time: number) {
      // Limit the purely decorative layer to 30fps and suspend it off screen.
      if (time - lastFrame > 32) {
        draw(time);
        lastFrame = time;
      }
      if (visible && !document.hidden) frame = requestAnimationFrame(tick);
    }
    function restart() {
      cancelAnimationFrame(frame);
      draw(0);
      if (visible && !document.hidden) frame = requestAnimationFrame(tick);
    }
    const resize = new ResizeObserver(() => {
      const box = canvas.getBoundingClientRect();
      width = box.width;
      height = box.height;
      const ratio = Math.min(window.devicePixelRatio || 1, 1.5);
      canvas.width = Math.round(width * ratio);
      canvas.height = Math.round(height * ratio);
      context.setTransform(ratio, 0, 0, ratio, 0, 0);
      restart();
    });
    const intersection = new IntersectionObserver(([entry]) => {
      visible = Boolean(entry?.isIntersecting);
      restart();
    });
    resize.observe(canvas);
    intersection.observe(canvas);
    document.addEventListener("visibilitychange", restart);
    return () => {
      cancelAnimationFrame(frame);
      resize.disconnect();
      intersection.disconnect();
      document.removeEventListener("visibilitychange", restart);
    };
  }, []);

  return <canvas ref={canvasRef} className="signal-field" aria-hidden="true" />;
}

export function PageMotion() {
  const pathname = usePathname();

  useEffect(() => {
    const elements = document.querySelectorAll<HTMLElement>("[data-ambient]");
    const visibility = new Map<Element, boolean>();
    const update = () =>
      elements.forEach((element) =>
        element.style.setProperty(
          "--ambient-play-state",
          !document.hidden && visibility.get(element) ? "running" : "paused"
        )
      );
    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => visibility.set(entry.target, entry.isIntersecting));
      update();
    });
    elements.forEach((element) => observer.observe(element));
    document.addEventListener("visibilitychange", update);
    return () => {
      observer.disconnect();
      document.removeEventListener("visibilitychange", update);
      elements.forEach((element) => element.style.removeProperty("--ambient-play-state"));
    };
  }, [pathname]);

  useEffect(() => {
    const elements = document.querySelectorAll<HTMLElement>("[data-reveal]");
    const animations = new Set<Animation>();
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) return;
          const element = entry.target as HTMLElement;
          const animation = element.animate(
            [
              { opacity: 0, transform: "translateY(24px)" },
              { opacity: 1, transform: "translateY(0)" }
            ],
            {
              duration: 700,
              delay: Number(element.dataset.delay || 0),
              easing: "cubic-bezier(.16,1,.3,1)",
              fill: "backwards"
            }
          );
          animations.add(animation);
          animation.onfinish = () => animations.delete(animation);
          observer.unobserve(element);
        });
      },
      { threshold: 0.12 }
    );
    elements.forEach((element) => observer.observe(element));
    return () => {
      observer.disconnect();
      animations.forEach((animation) => animation.cancel());
    };
  }, [pathname]);

  return null;
}
