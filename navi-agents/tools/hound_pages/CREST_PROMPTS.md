# Crest prompts — making a crest for a hound

Paste the shared style plus a subject block into ChatGPT, one
hound per chat (or one per message), then save the result as a square PNG named for the
hound's id (for example `sla.png`) in `web/assets/crests/`. Then run
`python3 tools/hound_pages.py` to rebuild the one-pagers with the new crest.

Each prompt is the **shared style** block plus that hound's **subject** block. The style
block matches the existing crests (Charon, Hellhound, Anubis …): keep it word for word so
the new crests sit in the same set.

## Shared style (paste first, every time)

> Create a square 1024×1024 crest emblem in a dark, mystical-tech style. Pure black
> background. Monochrome palette of glowing violet and indigo (around #5457cc and #6d70e6)
> with soft purple light bloom; no other colours. A circular frame made of thin runic
> glyphs and fine circuit-board traces surrounds the central figure, with three or four
> small glowing icon medallions set into the ring (top, left, right, bottom). In the centre,
> a detailed, dramatically lit anthropomorphic hound (a dog-headed figure or a dog), shown
> from the chest up or in a three-quarter pose, with fine fur and cloth detail. Below the
> circle, a heavy bold block-letter title with a subtle violet glow, then one thinner line
> of small capitals for the discipline, then a very small tagline in spaced capitals, then
> a tiny paw-print mark. Crisp, high contrast, symmetrical composition, readable at 256 px.
> No real company logos, no real people, no real brand marks, no extra text beyond what
> the subject block specifies. Spell every word exactly as given.

## Subjects

Every hound has a crest now. To add one for a new hound, write a subject block in the
same shape as below (title, discipline line, tagline, the scene, four ring medallions) and
paste it after the shared style.

> Title: **HARRIER**. Discipline line: **SOFTWARE EXPLORER**. Tagline: **RUNS DOWN EVERY INSTALL**.
> A lean, muscular Harrier pack hound in full stride, ears flying, racing along a glowing trail
> of small software-package boxes; a few of the boxes ahead are marked with a bright warning
> glyph (a lightning-bolt shield). Ring medallions: a package box, a magnifying glass, a
> lightning bolt, a version-tag label.

The generated images (webp) are kept in `tools/hound_pages/crest_sources/`; the app uses
384×384 PNGs made from them.

## Notes

- `mcpcmp` has no codename in the app. These prompts and its one-pager use **Pointer** as a
  proposal; it is not yet in the manifest or the hub's codename list.
- The existing crests use the agent's codename plus "HOUND" for mythological names
  (CHARON HOUND) and the breed alone for breeds (HELLHOUND). The titles above follow that.
