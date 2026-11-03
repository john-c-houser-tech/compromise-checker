# The web interface's look (2026-11-03)

John: the interface worked but looked like a hobby project, and should look like a NouriLoop LLC
product. Two directions were drawn on a canvas (Claude design artifact CecZ3KjjGDxh6sonN3rQLA). He
chose **B, "Lighthouse"**: a top bar, a headline band, a dense server list, findings with coloured
severity headers.

## Decided (John, 2026-11-03)

- **NouriLoop identity:** the Coil mark and favicon, NouriLoop green (`#2f6b4f`, `#7cc3a0` in dark) for the
  brand and the controls, its warm off-white page (`#fbfaf7`). The top bar is NouriLoop green in both
  themes.
- **Colour still means worry and nothing else** for red, orange, amber, teal and violet. "No strong signs"
  moves from green to teal, so green is only ever the brand.
- **A light/dark switch** in the top bar. It starts from the browser's setting and remembers a choice in a
  cookie. It's a plain form: pages still run no script, and the content security policy is unchanged.
- **Light mode:** the headline band a darker sage tint (`#dde8e0`) than the page; severity headers on
  findings and the status badges in the server list are solid colour with white text. **Dark mode:** they
  stay tinted.
- **Headlines never end in a period,** even when they're full sentences.
- **The top bar's items share one text line,** all the same height.

## Pull requests

- **L.1 Foundation.** The palette in both themes, the switch, the Coil and favicon, the top bar, buttons
  (main, quiet, danger) and fields that work in both themes. This fixes dark mode's main buttons, which were
  nearly the colour of the page. Sign-in security moves from the menu to the round initial at the right.
- **L.2 Servers.** The headline band with the answer and the counts, the server list with solid badges and
  meters, filters as pills.
- **L.3 One server and its evidence.** The headline band with the scale from unlikely to very likely, the
  action buttons, findings with severity headers, the side column.
- **L.4 Everything else.** Sign-in, setup, Manage, threats, checks, activity, two-factor, empty states with
  NouriLoop's drawings, and fresh screenshots for the README.

Each goes to dev with an agent review, then Copilot. I.4 (#126) also changes the base template, so whichever
merges second carries the other's change to it.
