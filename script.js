// Footer year
document.getElementById("year")?.textContent = new Date().getFullYear();

/**
 * Simple horizontal "carousel":
 * - Left/Right buttons scroll the track by one card width.
 * - Dots update based on nearest card.
 */
const track = document.querySelector("[data-carousel-track]");
const btnPrev = document.querySelector("[data-carousel-prev]");
const btnNext = document.querySelector("[data-carousel-next]");
const dotsWrap = document.querySelector("[data-carousel-dots]");

if (track && dotsWrap) {
  const cards = Array.from(track.querySelectorAll(".project-card"));

  // Build dots
  const dots = cards.map((_, i) => {
    const d = document.createElement("span");
    d.className = "dot" + (i === 0 ? " active" : "");
    d.setAttribute("role", "button");
    d.setAttribute("tabindex", "0");
    d.setAttribute("aria-label", `Go to project ${i + 1}`);
    d.addEventListener("click", () => scrollToIndex(i));
    d.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") scrollToIndex(i);
    });
    dotsWrap.appendChild(d);
    return d;
  });

  const cardStep = () => {
    const first = cards[0];
    if (!first) return 320;
    // card width + gap (12px in CSS)
    return first.getBoundingClientRect().width + 12;
  };

  function scrollToIndex(i) {
    const x = i * cardStep();
    track.scrollTo({ left: x, behavior: "smooth" });
  }

  function setActiveDot() {
    const left = track.scrollLeft;
    const idx = Math.round(left / cardStep());
    dots.forEach((d, i) => d.classList.toggle("active", i === idx));
  }

  btnPrev?.addEventListener("click", () => {
    track.scrollBy({ left: -cardStep(), behavior: "smooth" });
  });

  btnNext?.addEventListener("click", () => {
    track.scrollBy({ left: cardStep(), behavior: "smooth" });
  });

  track.addEventListener("scroll", () => {
    // Throttle-ish without overthinking:
    window.requestAnimationFrame(setActiveDot);
  });

  // Also allow arrow keys when focused on track
  track.addEventListener("keydown", (e) => {
    if (e.key === "ArrowLeft") btnPrev?.click();
    if (e.key === "ArrowRight") btnNext?.click();
  });
}
