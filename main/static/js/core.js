"use strict";

const getStoredTheme = () => localStorage.getItem("theme");
const setStoredTheme = (theme) => localStorage.setItem("theme", theme);

const getPreferredTheme = () => {
  const storedTheme = getStoredTheme();
  if (storedTheme) {
    return storedTheme;
  }

  return window.matchMedia("(prefers-color-scheme: dark)").matches
    ? "dark"
    : "light";
};

const setTheme = (theme) => {
  document.documentElement.setAttribute("data-bs-theme", theme);
};

setTheme(getPreferredTheme());

const showActiveTheme = (theme) => {
  const themeToggles = document.querySelectorAll("[data-bs-theme-toggle]");

  themeToggles.forEach((toggle) => {
    toggle.classList.toggle(
      "active",
      toggle.getAttribute("data-bs-theme-toggle") === theme,
    );
  });
};

window
  .matchMedia("(prefers-color-scheme: dark)")
  .addEventListener("change", () => {
    const storedTheme = getStoredTheme();
    if (storedTheme !== "light" && storedTheme !== "dark") {
      setTheme(getPreferredTheme());
      showActiveTheme(getPreferredTheme());
    }
  });

window.addEventListener("DOMContentLoaded", () => {
  showActiveTheme(getPreferredTheme());

  const themeToggles = document.querySelectorAll("[data-bs-theme-toggle]");
  themeToggles.forEach((toggle) => {
    toggle.addEventListener("click", () => {
      const theme = toggle.getAttribute("data-bs-theme-toggle");
      setStoredTheme(theme);
      setTheme(theme);
      showActiveTheme(theme);
      window.location.reload(); // TODO: Find a way to rerender charts to delete that horrible thing.
    });
  });
});
