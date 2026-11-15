# Shelldeck design system

The rules the interface follows. The tokens live at the top of
`shelldeck/static/style.css`; this file says why they are what they are.
The direction is a cool, quiet terminal tool: closer to Warp and Termius
than to a SaaS dashboard.

## Principles

1. **The terminal is the product.** Chrome is dim and thin so the panes
   carry the screen. Terminal backgrounds match the chrome, so a pane has
   no frame around it.
2. **Colour means state, never decoration.** Off-white (dark theme) or ink
   (light theme) is the emphasis. One teal *signal* marks where you are: focus
   ring, active tab, the pane with the keyboard. Green, amber and red appear
   only for connected, caution and error.
3. **Hairlines, not shadows.** Surfaces are separated by 1px lines and a step in
   background. Only dialogs and toasts cast a shadow, because they float.
4. **Dense by default.** One line per host (about 24px), 26px pane headers, 34px tab bar.
   Jump hosts move into the row's tooltip behind a single arrow.
   A screen should hold a fleet, not nine rows.
5. **Every state is visible.** Focus rings on everything focusable, the pane
   that receives typing is bright, broadcast is amber on every pane it reaches.

## Colour

| Token | Dark | Light | Use |
|---|---|---|---|
| `--bg` | `#111316` | `#eef1f4` | page, terminal background |
| `--panel` | `#15181c` | `#fafbfc` | sidebar, tab bar, dialogs |
| `--raised` | `#1d2126` | `#e3e7ec` | hover, selected, code |
| `--line` | `#2a2f36` | `#d6dce3` | hairlines between surfaces |
| `--ctl` | `#5f6873` | `#858f9b` | input and control borders (3:1 or better) |
| `--fg` | `#e7eaee` | `#15191e` | text, primary button fill |
| `--fg-2` | `#b4bcc7` | `#3f4752` | secondary text, labels |
| `--fg-3` | `#8a93a0` | `#5a6370` | hints, addresses, counts (4.5:1 or better) |
| `--signal` | `#6fc2c9` | `#19707a` | focus, active tab, focused pane |
| `--ok` / `--warn` / `--danger` | green / amber / red | darker equivalents | state only |

The table is Graphite (dark) and Paper (light). Seven themes ship, each a
short block in `style.css` that sets only the base colours above; fields,
weak tints, focus ring and terminal background are derived from them.

| Theme | Tone | Signal |
|---|---|---|
| Graphite (`dark`, default) | cool charcoal | teal |
| Midnight | deep navy | periwinkle |
| Ember | warm charcoal | coral |
| Moss | green-grey | mint |
| Void | true black, high contrast | cyan |
| Paper (`light`) | cool light | dark teal |
| Sand | warm light | sienna |

Each theme has a matching terminal palette in `app.js` (`TERM_THEMES`), with
the same background as the chrome. The sun/moon button swaps between the last
dark and the last light theme used.

Every text colour is at least 4.5:1 against every surface it sits on, in
both themes. Check new pairs before adding them.

## Type

- UI: `--sans` (Inter when installed, otherwise the system sans).
- Code, addresses, sizes, fingerprints: `--mono`.
- Five sizes only: `--t-xs` 11, `--t-sm` 12, `--t-md` 13 (body), `--t-lg` 15
  (dialog titles), `--t-xl` 20 (unlock screen). Weights 400, 500, 600.
- The light theme steps every size up by 1px (2px for the largest) and host
  names to 600: dark text on a light ground reads thinner and smaller.
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

## Motion

Short (120-160ms), eased, and only where state changes: dialogs rise in,
tabs and the caret transition, toasts slide up. Nothing animates on its own,
and nothing animates on a re-render (the tree and panes re-render often, so
they would flicker). `prefers-reduced-motion` turns all of it off.

## Constraints

- No web fonts or CDNs: the app makes no outbound requests.
- Plain CSS, no build step. Element ids and class names are used by
  `app.js` and `test_ui.py`; restyle them, do not rename them.
- `prefers-reduced-motion` turns animation off.
