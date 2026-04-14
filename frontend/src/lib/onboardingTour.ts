/**
 * driver.js onboarding tour for first-time users.
 * Steps: 1. Meta-Address (Your ID), 2. Receive (Ghost Addresses), 3. Vault (Portfolio).
 */

import { driver } from "driver.js";
import "driver.js/dist/driver.css";

const TOUR_STORAGE_KEY = "opaque-tour-done";

export function hasCompletedOnboardingTour(): boolean {
  return typeof window !== "undefined" && !!localStorage.getItem(TOUR_STORAGE_KEY);
}

export function runOnboardingTour(force?: boolean): void {
  if (!force && hasCompletedOnboardingTour()) return;

  const d = driver({
    showProgress: true,
    steps: [
      {
        element: "[data-tour=\"meta\"]",
        popover: {
          title: "Your ID",
          description: "Your stealth meta-address (Your ID) is in Profile. Open this menu to find it and share it for receiving private payments.",
          side: "bottom",
          align: "end",
        },
      },
      {
        element: "[data-tour=\"receive\"]",
        popover: {
          title: "Generating Ghost Addresses",
          description: "Use Receive to generate one-time ghost addresses. Each payment gets a unique address; no one can link them.",
          side: "top",
          align: "center",
        },
      },
      {
        element: "[data-tour=\"vault\"]",
        popover: {
          title: "The Vault",
          description: "Your SOL appears here. Click to see which stealth addresses hold it and withdraw.",
          side: "top",
          align: "start",
        },
      },
    ],
    onDestroyStarted: () => {
      if (typeof window !== "undefined") {
        localStorage.setItem(TOUR_STORAGE_KEY, "1");
      }
      d.destroy();
    },
  });

  d.drive();
}
