# Accessibility testing: approach and findings

This document covers the accessibility review carried out on VaultShare, the
issues found, the fixes applied, and what's knowingly still incomplete.

## Testing approach

Three methods were used, in order:

1. **Automated contrast check.** Every text/background color pair defined in
   `style.css` was checked against WCAG 2.1's contrast formula (relative
   luminance ratio) using a small script, rather than eyeballing it. This
   catches objective failures quickly but says nothing about structure,
   navigation, or screen reader behaviour - it's a first pass, not the whole
   review.
2. **Keyboard-only navigation.** Every page was walked through using only
   Tab, Shift+Tab, Enter, and Space - no mouse. This surfaces missing focus
   indicators, illogical tab order, and interactive elements that can't be
   reached or activated without a pointer.
3. **Manual structural review.** Reading through each template's markup for:
   labels correctly associated with form inputs (`<label for>` matching
   input `id`), meaningful `alt` text vs. decorative images, heading
   hierarchy, and whether dynamic content (errors, success messages) would
   be announced to a screen reader at all.

No dedicated screen reader software (NVDA/JAWS/VoiceOver) was used for a full
read-through in this pass; the structural review above targets the same
underlying requirements (labels, landmarks, live regions, alt text) that a
screen reader session would surface, but a real assistive-technology pass is
listed as a known gap below rather than something this report claims to have
done.

## Findings and fixes

| # | Finding | Severity | Fix applied |
|---|---|---|---|
| 1 | `--muted-2` gray text (`#6C6C67`) measured **3.75:1** contrast against the dark background at the sizes it's used (nav labels, table headers, file metadata - all under 14px) - below the 4.5:1 WCAG AA threshold for normal text. | Medium | Replaced with `#868686`, which clears 4.5:1+ against both background shades used in the app. Verified with the same contrast script, not just visually. |
| 2 | No "skip to main content" link. A keyboard user had to tab through the entire sidebar (7-10 links) on every single page before reaching the actual content. | Medium | Added a skip link as the first focusable element on every page, visually hidden until focused, jumping to a `tabindex="-1"` target on `<main>`. |
| 3 | Error and success messages (`.error-box` / `.success-box`) were plain `<div>`s with no ARIA role. A screen reader user would not be told a validation error appeared unless they happened to navigate directly onto it. | High | Added `role="alert"` to error messages and `role="status"` to success messages across all forms (login, register, MFA, profile, upload, share, settings, billing). `alert`/`status` are both live regions, so assistive tech announces them immediately when they appear. |
| 4 | Profile picture `<img>` tags used `alt=""` (i.e. explicitly marked as decorative), but an avatar is meaningful content - it identifies a specific person, and is the primary visual element in search results and on profile pages. | Medium | Changed to descriptive alt text (`"<name>'s profile picture"`) everywhere an avatar is rendered. |
| 5 | The avatar color picker conveyed each option through color swatches alone, with no text name. A screen reader would announce six unlabelled radio buttons with no way to tell them apart. | Medium | Added `aria-label` with the color's name (Gold, Green, Blue, etc.) to each radio input, and grouped them with `role="radiogroup"` + `aria-labelledby`. |
| 6 | Active navigation state was conveyed only via a background color/left-border change (`.active` class) - a screen reader gives no indication of which page you're currently on. | Low | Added `aria-current="page"` alongside the existing visual `.active` class on the current nav link. |
| 7 | Several templates referenced a `var(--accent)` CSS variable that doesn't exist in the design system (leftover from an earlier color scheme), causing those links to silently fall back to the browser default blue instead of the intended styling - inconsistent, and on a dark background, likely to have its own contrast problems against `--ink`. | Low (correctness, adjacent to accessibility) | Replaced with `var(--brass)`, the variable actually defined and already contrast-checked in finding #1's audit. |
| 8 | `lang="en"` and a `<title>` are present on every page (checked, not a finding) - noted here as a pass, since these are common baseline failures elsewhere. | — | No fix needed. |
| 9 | Form labels are consistently associated via `<label for="id">` matching the input's `id` throughout the app (checked, not a finding). | — | No fix needed. |

## Known remaining gaps

Being direct about what this pass did **not** cover, rather than implying a
completeness it doesn't have:

- **No screen reader software was actually run.** The fixes above target the
  requirements a screen reader session would test (labels, live regions,
  landmarks, alt text), but an actual NVDA/VoiceOver pass could still surface
  issues this review missed - particularly around reading order in more
  complex layouts like the recycle bin's two-table page.
- **Confirmation dialogs use the browser's native `confirm()`.** This is
  keyboard- and screen-reader-accessible by default (it's a native OS/browser
  UI element), but it can't be restyled, and some organizations' accessibility
  policies specifically require custom, in-page confirmation UI instead of
  native dialogs. Not changed in this pass.
- **No automated tooling (axe-core, Lighthouse) was run.** The contrast check
  here is hand-rolled and only covers color contrast - it doesn't catch
  things like missing landmark regions, duplicate IDs, or invalid ARIA usage
  the way a real axe-core scan would. Running one is a natural next step.
- **Avatar images use `object-fit: cover` with no long-description
  alternative.** Fine for a small profile thumbnail, but worth flagging if
  avatars are ever used somewhere the visual detail actually matters.
- **Reduced-motion support is partial.** `prefers-reduced-motion: reduce`
  disables CSS transitions/animations globally, but doesn't address anything
  JS-driven (there is none currently, so this is fine today, but would need
  revisiting if animated JS interactions are added later).

## How this was verified, not just claimed

The contrast fix (finding #1) was checked with a small Node script computing
WCAG 2.1 relative luminance and contrast ratios for every color pair actually
used in `style.css`, before and after the change - the before/after numbers
in the findings table above are real script output, not estimates.