# Shelldeck design system

The rules the interface follows. The tokens live at the top of
`shelldeck/static/style.css`; this file says why they are what they are.
The direction is a warm, quiet terminal tool: closer to Warp and Termius
than to a SaaS dashboard.

## Principles

1. **The terminal is the product.** Chrome is dim and thin so the panes
   carry the screen. Terminal backgrounds match the chrome, so a pane has
   no frame around it.
2. **Colour means state, never decoration.** There is no brand colour. Off-white
   (dark theme) or ink (light theme) is the only emphasis. Green, amber and red
   appear only for connected, caution and error.
3. **Hairlines, not shadows.** Surfaces are separated by 1px lines and a step in
   background. Only dialogs and toasts cast a shadow, because they float.
4. **Dense by default.** One line per host, 28px pane headers, 36px tab bar.
   A screen should hold a fleet, not nine rows.
5. **Every state is visible.** Focus rings on everything focusable, the pane
   that receives typing is bright, broadcast is amber on every pane it reaches.

## Colour

| Token | Dark | Light | Use |
|---|---|---|---|
| `--bg` | `#171513` | `#f3f0ea` | page, terminal background |
| `--panel` | `#1e1b19` | `#fbfaf7` | sidebar, tab bar, dialogs |
| `--raised` | `#282421` | `#ebe7df` | hover, selected, code |
| `--line` | `#3d3733` | `#ddd7cc` | hairlines between surfaces |
| `--ctl` | `#746b62` | `#8f8579` | input and control borders (3:1 or better) |
| `--fg` | `#f2efe9` | `#24201d` | text, primary button fill |
| `--fg-2` | `#c9c0ad` | `#57504a` | secondary text, labels |
| `--fg-3` | `#968d82` | `#6e665e` | hints, addresses, counts (4.5:1 or better) |
| `--ok` / `--warn` / `--danger` | green / amber / red | darker equivalents | state only |

Every text colour is at least 4.5:1 against every surface it sits on, in
both themes. Check new pairs before adding them.

## Type

- UI: `--sans` (Inter when installed, otherwise the system sans).
- Code, addresses, sizes, fingerprints: `--mono`.
- Five sizes only: `--t-xs` 11, `--t-sm` 12, `--t-md` 13 (body), `--t-lg` 15
  (dialog titles), `--t-xl` 20 (unlock screen). Weights 400, 500, 600.
- Sentence case for every label and button. No uppercase tracking.

## Shape and space

- Radius: `--r-sm` 4px for controls, `--r` 6px for dialogs and panels.
  Nothing rounder.
- Spacing on a 4px grid: 4, 8, 12, 16, 20.
- Icons: 16px line icons at 1.75 stroke, no emoji.

## Components

- **Primary button:** filled `--accent` with `--accent-fg` text. One per dialog.
- **Secondary button:** `--raised` fill, hairline border.
- **Inputs:** `--field` fill, `--ctl` border, `--fg-2` border on hover, focus ring.
- **Tabs:** text tabs with a 2px underline for the active one; amber underline
  when broadcasting.
- **Broadcast:** amber 2px rule across the top of each pane, tinted pane header,
  "Broadcasting" in the tab bar. Never red: red is for errors.
- **Dialogs:** `--panel`, hairline border, 6px radius, plain dimmed backdrop.
- **Toasts:** hairline card; the icon colour carries ok/error.

## Constraints

- No web fonts or CDNs: the app makes no outbound requests.
- Plain CSS, no build step. Element ids and class names are used by
  `app.js` and `test_ui.py`; restyle them, do not rename them.
- `prefers-reduced-motion` turns animation off.
