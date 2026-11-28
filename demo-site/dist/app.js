"use strict";

const actions = [...document.querySelectorAll("[data-scenario]")];
const status = document.querySelector("#status");
const detail = document.querySelector("#detail");
const reference = document.querySelector("#reference");
const marker = document.querySelector("#marker");
const copy = document.querySelector("#copy");

for (const button of actions) {
  button.addEventListener("click", async () => {
    for (const action of actions) action.disabled = true;
    delete status.dataset.error;
    status.textContent = "Generating test records…";
    detail.hidden = reference.hidden = copy.hidden = true;
    copy.textContent = "Copy reference";
    try {
      const response = await fetch("/scenarios/" + button.dataset.scenario, {method: "POST"});
      const result = await response.json();
      if (!response.ok) throw new Error(result.message);
      status.textContent = `${result.label} simulation complete.`;
      detail.textContent = `Docker recorded ${result.count} synthetic events. Search this reference in Evidence explorer.`;
      marker.textContent = result.marker;
      detail.hidden = reference.hidden = copy.hidden = false;
    } catch (error) {
      status.dataset.error = "true";
      status.textContent = error.message || "Unable to run the simulation. Try again.";
    } finally {
      for (const action of actions) action.disabled = false;
    }
  });
}

copy.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(marker.textContent);
    copy.textContent = "Copied";
  } catch {
    const selection = window.getSelection();
    const range = document.createRange();
    range.selectNodeContents(marker);
    selection.removeAllRanges();
    selection.addRange(range);
    copy.textContent = "Selected for copying";
  }
});
