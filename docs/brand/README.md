# SyncPlus Brand Kit

Public identity for GitHub and Facebook. These files match the desktop Brand
Mark. They are assets and rules only: this kit does not create a live Facebook
page, GitHub organization, or advertising account.

Review the plan. Confirm what changes. Uncertainty preserves the source.

## Promise

Use this sentence exactly. Do not substitute a slogan that implies silent
deletion, a completed drain, or unattended removal:

> Review the plan. Confirm what changes. Uncertainty preserves the source.

## Colours

| Role | Hex | Use |
| --- | --- | --- |
| Copper | `#E08A3C` | Primary accent, outbound arrow, Dark Appearance wordmark |
| Steel | `#8AA0B8` | Companion accent, inbound arrow |
| Warm ink | `#141210` | Dark Appearance canvas and mark plate |
| Warm paper | `#F7F0E4` | Light Appearance canvas and mark plate |
| Light copper | `#B65E1C` | Outbound arrow on paper |
| Light steel | `#3E5874` | Inbound arrow on paper |

## Contents

- `mark/` — Brand Mark from `packaging/icons/` (dark ink, light paper, monochrome)
- `wordmark/` — “SyncPlus” in a geometric sans, copper or ink by appearance
- `lockup/` — horizontal mark + wordmark for Dark Appearance, Light Appearance, and monochrome
- `github/avatar.png` — 512×512 repository avatar
- `github/social-preview-1280x640.png` — Open Graph preview
- `facebook/profile.png` — 512×512 profile source
- `facebook/cover-1640x924.png` — cover source
- `facebook/post-1200x630.png` — post image

Rebuild committed rasters after editing sources:

```sh
./packaging/brand/render-kit.sh
```

## Clear space

Keep empty space equal to **1/8 of the mark height** on every side of the mark
and of the horizontal lockup. In the 64-unit mark that is 8 units — the same
inset used around the protected loop. Do not place type, rules, or other
graphics inside that margin. The lockup viewBoxes already include this clear
space.

## Minimum size

- Brand Mark: **24 CSS pixels** (16 px only for the monochrome/symbolic mark)
- Wordmark: **80 CSS pixels** wide
- Horizontal lockup: **120 CSS pixels** wide
- GitHub avatar / Facebook profile: ship the 512 px sources; do not scale the
  mark below 24 px in a layout

## Allowed backgrounds

- Warm ink `#141210` for Dark Appearance
- Warm paper `#F7F0E4` for Light Appearance
- The matching elevated ink or stone surfaces from the desktop appearances
- Transparent, when the mark keeps its own ink or paper plate

Light Appearance is not a white sheet. Do not treat pure white as the only
light option, and do not treat pure black as Dark Appearance.

## Forbidden treatments

- Recolour to pink or teal
- Neon glow, scanlines, or drop shadows that look neon
- Slogans that imply silent deletion (“sync and forget”, “auto-delete”,
  “in rhythm”, or any claim that a drain completed when Source Not Empty is
  possible)
- A menu icon, window icon, or social avatar that is not this Brand Mark
- Placing the mark on pure white as the only light treatment
- Rotating, outlining, or stretching the arrows out of the protected loop

## Appearances

Dark Appearance lockups sit on warm ink with a copper wordmark. Light
Appearance lockups sit on warm paper with an ink wordmark. Monochrome
variants use `currentColor` for constrained or single-ink reproduction.

## Secrets

Do not embed credentials, key material, or user file bytes in kit artwork,
sidecars, or previews.
