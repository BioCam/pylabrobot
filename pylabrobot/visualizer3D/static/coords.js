/**
 * The coordinate tool: reads a point off a resource against a chosen reference and lists it.
 *
 * It knows nothing about the scene beyond what it is handed, so the geometry stays in one place.
 *
 * @param {{getWorld: () => any, referencePoint: Function, escapeHtml: (s: string) => string}} deps
 * @returns {{coordinateLabel: (i: number) => string, recordMeasurement: (i: number) => void,
 *            populateWrtDropdown: () => void}}
 */
import { select as selectEl } from "./dom.js";

export function initCoords({ getWorld, referencePoint, escapeHtml }) {
  const refValue = (id) => selectEl(id).value;
  const measurementsEl = document.getElementById("coords-measurements");
  const hintEl = document.getElementById("coords-measurements-hint");

  function coordinateFor(index) {
    const point = referencePoint(index, refValue("coords-x-ref"), refValue("coords-y-ref"), refValue("coords-z-ref"));
    const wrtName = refValue("coords-wrt-ref");
    if (wrtName !== "root") {
      const wrtIndex = getWorld().indexOfName.get(wrtName);
      if (wrtIndex !== undefined) {
        point.sub(
          referencePoint(wrtIndex, refValue("coords-wrt-x-ref"), refValue("coords-wrt-y-ref"), refValue("coords-wrt-z-ref"))
        );
      }
    }
    return point;
  }

  function coordinateLabel(index) {
    const p = coordinateFor(index);
    const wrtName = refValue("coords-wrt-ref");
    const wrt = wrtName === "root" ? "abs" : `wrt ${wrtName}`;
    return `${getWorld().names[index]}\n${wrt}: (${p.x.toFixed(1)}, ${p.y.toFixed(1)}, ${p.z.toFixed(1)}) mm`;
  }

  function recordMeasurement(index) {
    const p = coordinateFor(index);
    hintEl.remove();

    const initials = (...ids) => ids.map((id) => (refValue(id) || "?")[0]).join(", ");
    const wrtName = refValue("coords-wrt-ref");

    const row = document.createElement("div");
    row.className = "measurement-row";
    row.innerHTML =
      `<div class="m-content">` +
      `<div class="m-name">${escapeHtml(getWorld().names[index])} ` +
      `(${initials("coords-x-ref", "coords-y-ref", "coords-z-ref")})</div>` +
      `<div class="m-wrt">wrt ${escapeHtml(wrtName)} ` +
      `(${initials("coords-wrt-x-ref", "coords-wrt-y-ref", "coords-wrt-z-ref")})</div>` +
      `<div class="m-val">(${p.x.toFixed(1)}, ${p.y.toFixed(1)}, ${p.z.toFixed(1)})</div>` +
      `</div><button class="m-remove" title="Remove">&times;</button>`;
    row.querySelector(".m-remove").addEventListener("click", () => row.remove());
    measurementsEl.appendChild(row);
    measurementsEl.scrollTop = measurementsEl.scrollHeight;
  }

  function populateWrtDropdown() {
    const select = selectEl("coords-wrt-ref");
    const current = select.value;
    select.innerHTML = '<option value="root">(abs)</option>';
    // Everything above the leaves: a well is rarely the thing another thing is measured against,
    // and listing 1,400 of them makes the dropdown unusable.
    for (let i = 0; i < getWorld().names.length; i++) {
      if (getWorld().childrenOf[i].length === 0) continue;
      const option = document.createElement("option");
      option.value = getWorld().names[i];
      option.textContent = getWorld().names[i];
      select.appendChild(option);
    }
    select.value = current && [...select.options].some((o) => o.value === current) ? current : "root";
  }

  return { coordinateLabel, recordMeasurement, populateWrtDropdown };
}
