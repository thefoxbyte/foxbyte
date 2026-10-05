// SPDX-License-Identifier: AGPL-3.0-or-later

package gen

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
	"os"
	"path/filepath"
)

// The logo, derived rather than hand-cut.
//
// It has been replaced three times. Each time the job was the same: trim the
// artwork, scale it to the handful of sizes the app and the README use, key the
// background out, and remember to update every place that hard-codes a size or
// a colour. Doing that by hand is how a favicon ends up a version behind the
// mark beside it.
//
// So brand.json names the four source files and the two colours, and everything
// below is generated from them. `make brand` writes them; `make brand-check`
// and TestGeneratedFilesAreInStep fail when they are stale, which is the part
// that makes the next change safe: forgetting to regenerate is a red build
// rather than a logo that is subtly wrong in one place.
//
// No image dependency. Downscaling a logo wants an area average, which is
// twenty lines and exactly the right filter for the job — every output here is
// a reduction, never an enlargement.

// Logo is brand.json's `logo` block.
type Logo struct {
	SourceDir         string `json:"source_dir"`
	MarkDark          string `json:"mark_dark"`
	MarkLight         string `json:"mark_light"`
	LockupDark        string `json:"lockup_dark"`
	LockupLight       string `json:"lockup_light"`
	KeyTolerance      int    `json:"key_tolerance"`
	KeyFeather        int    `json:"key_feather"`
	Plate             string `json:"plate"`
	AccentWarm        string `json:"accent_warm"`
	AccentCoolOnDark  string `json:"accent_cool_on_dark"`
	AccentCoolOnLight string `json:"accent_cool_on_light"`
}

// The sizes each output is used at. Kept here rather than in brand.json
// because they follow from where the image is shown, not from the artwork: the
// app never draws the mark above 30px, a tab icon is a tab icon, and iOS asks
// for 180. New artwork does not change any of them.
const (
	appMarkPx    = 128 // 30px at 3x, with room
	faviconPx    = 48
	touchIconPx  = 180
	docsMarkPx   = 512
	docsLockupPx = 720 // the README renders it at 420
)

// logoFiles are every asset derived from the artwork.
func logoFiles(root string, l Logo) (map[string][]byte, error) {
	if l.SourceDir == "" {
		return nil, nil // no logo block: nothing to generate
	}
	load := func(name string) (*image.NRGBA, error) {
		p := filepath.Join(root, l.SourceDir, name)
		f, err := os.Open(p)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		src, err := png.Decode(f)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		return keyOut(src, l.KeyTolerance, l.KeyFeather), nil
	}

	markDark, err := load(l.MarkDark)
	if err != nil {
		return nil, err
	}
	markLight, err := load(l.MarkLight)
	if err != nil {
		return nil, err
	}
	lockupDark, err := load(l.LockupDark)
	if err != nil {
		return nil, err
	}
	lockupLight, err := load(l.LockupLight)
	if err != nil {
		return nil, err
	}

	plate, err := parseHex(l.Plate)
	if err != nil {
		return nil, fmt.Errorf("logo.plate: %w", err)
	}

	// A tab icon and an iOS icon get the brand's own ground rather than
	// whatever the browser or the OS would put behind them: iOS ignores a touch
	// icon's alpha and composites on black, and a tab bar may be either colour.
	sq := square(markDark)
	out := map[string][]byte{}
	add := func(rel string, im image.Image) error {
		b, err := encode(im)
		if err != nil {
			return err
		}
		out[rel] = b
		return nil
	}

	out[filepath.Join("web", "src", "brand.gen.css")] = []byte(cssFile(l))

	for rel, im := range map[string]image.Image{
		filepath.Join("web", "public", "mark-dark.png"):  fit(square(markDark), appMarkPx),
		filepath.Join("web", "public", "mark-light.png"): fit(square(markLight), appMarkPx),
		filepath.Join("web", "public", "favicon.png"):    onPlate(fit(sq, faviconPx*5/6), faviconPx, plate),
		filepath.Join("web", "public", "apple-touch-icon.png"): onPlate(
			fit(sq, touchIconPx*5/6), touchIconPx, plate),
		filepath.Join("docs", "brand", "foxbyte-mark.png"):       fit(sq, docsMarkPx),
		filepath.Join("docs", "brand", "foxbyte-mark-light.png"): fit(square(markLight), docsMarkPx),
		filepath.Join("docs", "brand", "foxbyte-logo.png"):       fit(lockupLight, docsLockupPx),
		filepath.Join("docs", "brand", "foxbyte-logo-dark.png"):  fit(lockupDark, docsLockupPx),
	} {
		if err := add(rel, im); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// keyOut turns the artwork's flat background transparent, then trims to what is
// left. The background is whatever the corner pixel is: every source so far has
// arrived as the mark on a solid field. Distance is summed per channel rather
// than Euclidean — it is cheaper and, on a flat field, indistinguishable.
//
// Pixels within tolerance vanish, pixels past tolerance+feather are solid, and
// the ramp between is what keeps the edges smooth instead of jagged.
func keyOut(src image.Image, tolerance, feather int) *image.NRGBA {
	b := src.Bounds()
	dst := image.NewNRGBA(b)
	br, bg, bb, _ := src.At(b.Min.X, b.Min.Y).RGBA()
	bgR, bgG, bgB := int(br>>8), int(bg>>8), int(bb>>8)
	if feather <= 0 {
		feather = 1
	}
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			r16, g16, b16, _ := src.At(x, y).RGBA()
			r, g, bl := int(r16>>8), int(g16>>8), int(b16>>8)
			d := abs(r-bgR) + abs(g-bgG) + abs(bl-bgB)
			var a int
			switch {
			case d <= tolerance:
				a = 0
			case d >= tolerance+feather:
				a = 255
			default:
				a = 255 * (d - tolerance) / feather
			}
			dst.SetNRGBA(x, y, color.NRGBA{uint8(r), uint8(g), uint8(bl), uint8(a)})
		}
	}
	return trim(dst)
}

// trim crops to the pixels that are not fully transparent, so every size below
// is a scale of the artwork itself rather than of the whitespace around it.
func trim(im *image.NRGBA) *image.NRGBA {
	b := im.Bounds()
	minX, minY, maxX, maxY := b.Max.X, b.Max.Y, b.Min.X, b.Min.Y
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			if im.NRGBAAt(x, y).A == 0 {
				continue
			}
			if x < minX {
				minX = x
			}
			if y < minY {
				minY = y
			}
			if x >= maxX {
				maxX = x + 1
			}
			if y >= maxY {
				maxY = y + 1
			}
		}
	}
	if minX >= maxX || minY >= maxY {
		return im
	}
	out := image.NewNRGBA(image.Rect(0, 0, maxX-minX, maxY-minY))
	draw.Draw(out, out.Bounds(), im, image.Pt(minX, minY), draw.Src)
	return out
}

// square pads to a square with transparency, centred, so every size derived
// from it is the same artwork at a different scale and nothing shifts between
// a 48px tab icon and a 512px one.
func square(im *image.NRGBA) *image.NRGBA {
	w, h := im.Bounds().Dx(), im.Bounds().Dy()
	side := max(w, h)
	out := image.NewNRGBA(image.Rect(0, 0, side, side))
	draw.Draw(out, image.Rect((side-w)/2, (side-h)/2, (side-w)/2+w, (side-h)/2+h), im, image.Point{}, draw.Src)
	return out
}

// fit scales to a width, keeping the aspect ratio, by averaging the source
// pixels that fall under each destination pixel. That is the right filter for a
// reduction and it needs no dependency; alpha is averaged with the colour, and
// colour is weighted by alpha so a transparent pixel cannot drag the edge
// toward black.
func fit(im *image.NRGBA, width int) *image.NRGBA {
	sw, sh := im.Bounds().Dx(), im.Bounds().Dy()
	if sw <= width {
		return im
	}
	height := int(math.Round(float64(sh) * float64(width) / float64(sw)))
	if height < 1 {
		height = 1
	}
	out := image.NewNRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		y0, y1 := y*sh/height, (y+1)*sh/height
		if y1 <= y0 {
			y1 = y0 + 1
		}
		for x := 0; x < width; x++ {
			x0, x1 := x*sw/width, (x+1)*sw/width
			if x1 <= x0 {
				x1 = x0 + 1
			}
			var sr, sg, sb, sa, n float64
			for yy := y0; yy < y1; yy++ {
				for xx := x0; xx < x1; xx++ {
					c := im.NRGBAAt(xx, yy)
					a := float64(c.A)
					sr += float64(c.R) * a
					sg += float64(c.G) * a
					sb += float64(c.B) * a
					sa += a
					n++
				}
			}
			if sa == 0 {
				out.SetNRGBA(x, y, color.NRGBA{})
				continue
			}
			out.SetNRGBA(x, y, color.NRGBA{
				R: uint8(math.Round(sr / sa)),
				G: uint8(math.Round(sg / sa)),
				B: uint8(math.Round(sb / sa)),
				A: uint8(math.Round(sa / n)),
			})
		}
	}
	return out
}

// onPlate centres an image on an opaque square of the brand's ground.
func onPlate(im *image.NRGBA, side int, plate color.NRGBA) *image.NRGBA {
	out := image.NewNRGBA(image.Rect(0, 0, side, side))
	draw.Draw(out, out.Bounds(), &image.Uniform{plate}, image.Point{}, draw.Src)
	w, h := im.Bounds().Dx(), im.Bounds().Dy()
	r := image.Rect((side-w)/2, (side-h)/2, (side-w)/2+w, (side-h)/2+h)
	draw.Draw(out, r, im, image.Point{}, draw.Over)
	return out
}

// encode writes a PNG. Deterministic for the same pixels, which is what lets
// `make brand-check` compare bytes and mean it.
func encode(im image.Image) ([]byte, error) {
	var buf bytes.Buffer
	enc := png.Encoder{CompressionLevel: png.BestCompression}
	if err := enc.Encode(&buf, im); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func parseHex(s string) (color.NRGBA, error) {
	b, err := hex.DecodeString(trimHash(s))
	if err != nil || len(b) != 3 {
		return color.NRGBA{}, fmt.Errorf("want #rrggbb, got %q", s)
	}
	return color.NRGBA{b[0], b[1], b[2], 255}, nil
}

func trimHash(s string) string {
	if len(s) > 0 && s[0] == '#' {
		return s[1:]
	}
	return s
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// cssFile is the stylesheet's half of the logo: the two colours the artwork is
// drawn in. A fully generated file rather than a marked block, because
// replaceBlock writes `#` comments for the installers and CSS does not have
// those — and because a whole file cannot be edited by hand without the next
// `make brand` noticing.
func cssFile(l Logo) string {
	return fmt.Sprintf(`/* SPDX-License-Identifier: AGPL-3.0-or-later */

/* Generated from brand.json by cmd/brandgen. DO NOT EDIT.
   The logo's own ink, so the wordmark's accented letter is drawn in the
   colours beside it rather than a hex someone matched by eye and then forgot
   to change.

   The cool half swaps with the page, exactly as the mark does: white on a dark
   one, navy on a light one. A single cool colour would disappear into one of
   the two backgrounds, and on the dark theme that is what it did. */

:root {
  --mark-a: %s;
  --mark-b: %s;
  --grad-mark: linear-gradient(100deg, var(--mark-a), var(--mark-b));
}

[data-theme='light'] {
  --mark-b: %s;
}
`, l.AccentWarm, l.AccentCoolOnDark, l.AccentCoolOnLight)
}
