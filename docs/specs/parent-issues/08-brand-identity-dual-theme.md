# Brand identity, dual theme, and public assets

GitHub: [#117](https://github.com/darrenedward/SyncPlus/issues/117)

## Problem Statement

SyncPlus now has a complete safety workflow, but its public face does not match that product. The live desktop chrome uses neon mint and magenta on near-black. The packaged icon uses a different seafoam-and-gold mark. Light appearance is treated as a bright fallback rather than a designed theme. There is no shared brand kit for GitHub, Facebook, the desktop icon, or the window mark.

People who prefer Dark Appearance and people who prefer Light Appearance both deserve a finished, respectful theme. Light must not mean white. Dark must not mean a cyberpunk HUD. Magenta does not belong on a tool that reviews overwrites and removals. Teal is not the brand direction.

Until identity, theme, and public assets are one system, SyncPlus looks like two different products and undersells the care of its Sync Run, Execution Confirmation, and Recovery Review.

## Solution

Adopt one visual identity and apply it everywhere a person meets SyncPlus: the desktop app in Dark Appearance and Light Appearance, the application icon, and a public Brand Kit for GitHub and Facebook.

The identity is **copper and steel on warm ink or warm paper**. Copper is the primary accent (forward, Peer A, selected, primary action). Steel is the companion accent (return, Peer B, secondary). Warm ink is the dark canvas. Warm paper is the light canvas. Danger red and warning gold are reserved for real warnings and destructive state. They are not decoration.

Both appearances are first-class. They share the same layout, type roles, spacing, components, and illustration language. Only surface, ink, and accent calibration change. The existing theme preference (System, Light, Dark) continues to select the appearance; System follows the desktop.

Replace the current logo. The mark is two protected arrows in a loop: copper outbound, steel inbound, on a rounded square. No pink. No teal. No neon mint. The window icon, desktop icon, and Brand Kit lockups are the same mark.

Keep the safety model unchanged. Colour never authorizes an action, never replaces a label, and never bypasses Execution Confirmation, precheck, or Recovery Review.

## User Stories

1. As a dark-mode user, I want a warm, quiet Dark Appearance, so that I can review a long plan without neon glare.
2. As a light-mode user, I want a designed Light Appearance on warm paper and stone, so that my theme is not a white sheet with dark-mode leftovers.
3. As a user who follows the desktop theme, I want System to pick Dark Appearance or Light Appearance from the OS, so that SyncPlus matches the rest of my session.
4. As a returning user, I want my theme preference remembered, so that I do not reset appearance every launch.
5. As a user switching appearance, I want every screen to update immediately, so that Overview, Profiles, the wizard, Sync workspace, Run Reports, Recovery Review, Help, Settings, and dialogs stay one product.
6. As a light-mode user, I want cards, fields, borders, and shadows designed for cream and stone, so that hierarchy is as clear as it is in Dark Appearance.
7. As a dark-mode user, I want surfaces that are warm ink rather than pure black, so that the app feels like an instrument and not a terminal skin.
8. As a user, I want copper as the only primary accent, so that selected navigation, primary buttons, and Peer A share one meaning.
9. As a user, I want steel for Peer B and reverse direction, so that two peers are distinct without magenta.
10. As a user, I want magenta, neon mint, and teal gone from chrome, icons, focus rings, Help dots, and the logo, so that the product no longer looks like a HUD kit.
11. As a user, I want danger red only when something is blocked, failed, destructive, or in Recovery Review, so that red remains a real signal.
12. As a user, I want warning gold only for Path Risk Warning, pending review, and similar caution, so that incomplete wizard steps are not painted as warnings.
13. As a colour-blind user, I want labels, icons, and text in addition to colour, so that Peer A, Peer B, success, warning, and danger remain understandable.
14. As a keyboard user, I want a visible focus ring in the primary accent, so that focus is obvious without a magenta halo.
15. As a new user on first launch, I want the empty Overview to explain the product calmly and offer one primary action, so that I can create a Sync Profile without marketing noise.
16. As a returning user with a Sync Profile, I want Overview to show the active profile, last Sync Run, anything in Recovery Review, and the next safe action, so that home is operational rather than a landing page.
17. As a user, I want Settings reachable from the sidebar, so that appearance and Simple Mode or Advanced Mode are not hidden behind a text link.
18. As a user, I want sidebar navigation to use one selected accent, so that each destination does not get its own rainbow colour.
19. As a user, I want Recovery Review to appear as a badge or alert when a run needs it, so that a red shield is not a permanent tourist destination.
20. As a user, I want Exit to be a quiet control, so that quitting is not louder than Synchronise or Execution Confirmation.
21. As a user creating a Sync Profile, I want the wizard stepper to mark current, complete, and upcoming without warning colours on upcoming steps, so that “not yet” does not feel like a fault.
22. As a user in Sync workspace, I want analyze, plan, and confirmation as the main work, so that profile editing and historical Run Reports do not compete on the same scroll.
23. As a user editing a Sync Profile, I want that work on Profiles, so that configuration and execution stay distinct.
24. As a user reading Help, I want topics grouped by subject, not colour-coded like a risk legend, so that I do not infer danger from a decorative dot.
25. As a user, I want type used as an instrument: eyebrow, title, body, caption, so that 46px hero lines and all-caps banners do not shout over the plan.
26. As a Simple Mode user, I want the new identity without extra chrome, so that the safe default path stays the quietest path.
27. As an Advanced Mode user, I want the same identity on scheduling and diagnostics, so that Advanced Mode looks like more controls, not a different skin.
28. As a user confirming a destructive run, I want Execution Confirmation to stay the visual event, so that brand colour never softens or hides removal consequences.
29. As a user in Conflict Review, I want Peer A copper and Peer B steel with text labels, so that Keep Peer A and Keep Peer B stay readable.
30. As a user, I want the application icon in the desktop menu to match the window icon, so that launching SyncPlus does not show two marks.
31. As a user, I want the new mark to read as protected two-way motion, so that the logo explains sync without pink or teal.
32. As a packager, I want one SVG source plus the sized raster icons the desktop entry needs, so that install, menu, and window stay consistent.
33. As a GitHub visitor, I want the repository avatar and social preview to use the same mark and dual-appearance kit, so that the project looks like the app.
34. As a GitHub visitor, I want the README to use the wordmark or lockup without neon screenshots that contradict the identity.
35. As someone sharing SyncPlus on Facebook, I want a profile image, cover, and post image in the Brand Kit, so that I do not invent a third logo.
36. As a maintainer, I want the Brand Kit to document clear space, minimum size, allowed backgrounds, and forbidden treatments, so that later assets stay on-identity.
37. As a maintainer, I want Light Appearance and Dark Appearance lockups in the Brand Kit, so that social images can sit on paper or ink without a white box.
38. As a reviewer, I want screenshots of the same screens in both appearances, so that Light Appearance is reviewed with the same care as Dark Appearance.
39. As a user on a small 960px window, I want the identity to hold without crushed steppers or overflowing hero type, so that the minimum window remains usable.
40. As a user, I want status badges to use text plus colour, so that Completed, Blocked, and Recovery Review are not colour-only.
41. As a user, I want primary buttons in copper with readable on-accent ink, so that the next safe action is the clearest control.
42. As a user, I want secondary buttons to be quiet stone or elevated ink, so that Dry run, Validate, and Cancel do not compete with confirm.
43. As a user facing a Path Risk Warning, I want warning gold and plain language, so that advisory caution is distinct from blocked or destructive state.
44. As a user, I want illustrations and the brand mark to share copper and steel, so that the empty Overview and the icon feel related.
45. As a user, I want no glow, scanline, or neon gradient stripe, so that the chrome stays calm.
46. As a translator of the product into public posts, I want a one-line brand promise that matches the safety copy, so that Facebook and GitHub do not invent a slogan that implies silent deletion.
47. As a maintainer, I want the Brand Kit in the repository, so that agents and humans generate later assets from the same source.
48. As a safety-conscious user, I want the new look to change no confirmation, authorization, or fail-closed rule, so that beauty cannot weaken Verified Removal or Completion Reconciliation.

## Implementation Decisions

- Keep synchronization policy, ThemePreference persistence, and all safety-critical logic in the GUI-free core. The core continues to store System, Light, or Dark. It does not store hex colours, fonts, or logo geometry.
- Own the visual system in the desktop GUI as one Brand Theme token set with two complete appearances. Every surface, text, border, accent, danger, warning, and focus colour comes from tokens. Screens do not invent one-off colours.
- Treat Dark Appearance and Light Appearance as peers. Light Appearance uses warm paper, cream cards, and stone elevated surfaces. It must not use a white canvas, and it must not be a brightness-inverted Dark Appearance. Dark Appearance uses warm ink surfaces, not pure black and not neon-on-OLED.
- Use this token direction (calibrate only if a contrast check fails; do not drift back into teal, mint, or magenta):

  Dark Appearance
  - Canvas `#141210`, surface `#1C1916`, elevated `#26221D`, field `#12100E`
  - Text `#F3EDE4`, muted `#B5A99A`, border `#6F6458`
  - Copper accent `#E08A3C`, on-accent `#1A1208`, copper soft `#3A2414`
  - Steel `#8AA0B8`, steel soft `#243040`
  - Danger `#D35A5A`, danger soft `#3A1C1C`
  - Warning `#E0B24A`, warning soft `#3A3014`

  Light Appearance
  - Canvas `#EFE6D8`, surface `#F7F0E4`, elevated `#E7DCCB`, field `#FFF8EE`
  - Text `#1C1712`, muted `#6B5E50`, border `#C4B6A4`
  - Copper accent `#B65E1C`, on-accent `#FFF8EE`, copper soft `#F3D7BE`
  - Steel `#3E5874`, steel soft `#D5DEE8`
  - Danger `#B42332`, danger soft `#F7D7DA`
  - Warning `#8A5A12`, warning soft `#F3E6C4`

- Forbid these hues in chrome, icons, focus, Help markers, illustrations, and the logo: magenta and hot pink (including `#FF0099`), neon mint (including `#00FF85`), and teal or seafoam (including `#79D2C3` and cyan-green relatives). Existing packaged artwork that uses those hues is replaced, not kept as a variant.
- Map colour to meaning and nothing else. Copper: primary action, selected nav, Peer A, forward sync. Steel: Peer B, reverse, companion chrome. Danger: blocked, failed, destructive, Recovery Review that needs attention. Warning: advisory caution. Incomplete, idle, and informational states use muted text and quiet surfaces.
- Replace rainbow navigation. Unselected sidebar items share muted ink. The selected item uses copper soft fill and copper stroke. Recovery Review is not a permanent peer item; it surfaces as a badge or notice when a Run Report requires it. Settings sits in the sidebar. Exit is a quiet control; the strong quit copy stays in the active-run quit dialog.
- Replace the procedural neon window glyph and the seafoam packaged mark with one Brand Mark: a rounded square, copper outbound arrow, steel inbound arrow, protected loop, no pink, no teal. Dark mark sits on warm ink. Light mark sits on warm paper or is a full-colour mark on transparent. Monochrome versions exist for constrained backgrounds.
- Stop generating the window icon from ad-hoc pixel painting. Load the Brand Mark asset used by the desktop entry.
- Introduce a repository Brand Kit for public identity: mark, wordmark, horizontal lockup, monochrome, Dark Appearance and Light Appearance versions, desktop icon sizes, GitHub avatar and 1280×640 social preview, Facebook profile, cover (1640×924 source), and 1200×630 post image. Document clear space, minimum size, allowed backgrounds, and forbidden treatments (recolour to pink or teal, drop shadows that look neon, placing the mark on pure white as the only light option, adding slogans that imply silent delete).
- Public brand promise for kit and README, not as in-app hero type: “Review the plan. Confirm what changes. Uncertainty preserves the source.” Do not use “in rhythm,” neon taglines, or language that implies a completed drain when Source Not Empty is possible.
- Apply the identity to layout, not only paint. Empty Overview may keep a calm first-run explanation. Populated Overview becomes operational. Sync workspace concentrates Fresh Analysis, plan review, and Execution Confirmation. Profile fields stay with Profiles. Run Reports stay with Reports. Help remains a dedicated page without colour-as-legend.
- Use four type roles: eyebrow, title, body, caption. Titles stay in a tool range, not marketing display sizes. All-caps banners are not a substitute for hierarchy. The desktop app may keep the bundled GUI font for v1; the Brand Kit may specify a public wordmark treatment that remains legible at icon and cover sizes.
- Primary controls stay about 40px tall. Focus rings use copper or steel contrast against the surface, never magenta. Colour is never the only state indicator.
- Update the domain glossary when this lands so Dark Appearance, Light Appearance, Brand Mark, and Brand Kit are canonical terms. Appearance must not be described as “just white” or “just dark.”
- Do not add a new settings store, a third theme, a user-supplied colour picker, or arbitrary chrome CSS. Named appearances only.
- Do not change Safe Delete, Destination Cleanup, Mirror resolutions, authorization, or fail-closed rules to fit the look.

## Testing Decisions

- Test external behaviour and identity contracts, not private drawing calls. A good test asks: which appearance is active, whether a required token role exists, whether a forbidden hue is present, whether a required public asset exists at the documented size, and whether safety copy and confirmation still appear.
- Highest seam: the desktop Brand Theme tokens. Assert both appearances expose the full role set; Light Appearance canvas is not white; Dark Appearance canvas is not black; copper, steel, danger, and warning are distinct; forbidden magenta, neon mint, and teal values are absent from token roles.
- Theme preference seam: System, Light, and Dark still persist through application settings and configuration export/import. Switching Light and Dark swaps the token set for the whole window. Existing settings tests remain the prior art.
- Contrast seam: body text on canvas and surface, muted text on surface, on-accent text on copper buttons, and danger text on danger-soft surfaces meet at least 4.5:1 in both appearances. Fail the appearance if calibration is required and not done.
- Navigation seam: Settings is reachable from the main chrome; Recovery Review is not a permanent equally-weighted destination when no run needs it; selected nav does not rely on a unique hue per item.
- Icon seam: the packaged application icon, window icon, and Brand Mark are the same design family; none contain magenta or teal.
- Brand Kit seam: required GitHub and Facebook assets exist with documented dimensions; kit documentation states forbidden treatments; assets contain no secrets or file contents.
- Safety regression: Execution Confirmation, Path Risk Warning, destructive labels, and Recovery Review copy still appear; UI chrome cannot bypass core blockers. Prior art is the existing GUI workflow tests and core contract tests.
- Review evidence: the same representative screens are captured in Dark Appearance and Light Appearance (empty Overview, populated Overview, wizard, plan review, Execution Confirmation, Help). A Light Appearance that was not screenshotted is not done.
- Do not treat a single dark screenshot as proof that Light Appearance was designed.

## Out of Scope

- Any change to the core run workflow, Verified Removal, Completion Reconciliation, SSH policy, scheduling authorization, or SQLite safety gates.
- A user-editable theme editor, extra accent pickers, or community theme files.
- New packaged fonts if they complicate the Debian package; Brand Kit typography may exist as guidance without shipping a new font in v1.
- Creating or operating live Facebook pages, GitHub organizations, or advertising accounts. This spec delivers the assets and rules, not the social presence.
- Marketing websites, animated launch videos, or store listings beyond the Linux desktop icon and the listed public images.
- SSH-to-SSH, rsync daemon URLs, merge editors, or other deferred product work.
- Rewriting Help article substance except where identity (colour legend, neon language) would contradict this spec.

## Further Notes

This is a parent for visual identity after the v1 safety parents. Child work should split by dependency: Brand Theme tokens and appearances first, Brand Mark and desktop icon next, application of tokens to chrome and navigation, then public Brand Kit assets.

Dark Appearance is not the “real” product and Light Appearance is not a courtesy. Both are the product. If a later change is only finished in one appearance, it is not finished.

The safety copy already says the right thing: nothing changes until the user confirms, and uncertainty preserves the source. The identity should look like that sentence.
