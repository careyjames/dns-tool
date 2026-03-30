package handlers

import (
	"image"
	"image/color"
	"image/color/palette"
	"testing"
)

func TestRasterizeSVGToRGBA_EmptyPath(t *testing.T) {
	saved := rsvgBinPath
	rsvgBinPath = ""
	defer func() { rsvgBinPath = saved }()

	_, err := rasterizeSVGToRGBA([]byte("<svg></svg>"))
	if err == nil {
		t.Fatal("expected error when rsvgBinPath is empty")
	}
	if got := err.Error(); got != "rsvg-convert: not found in PATH" {
		t.Errorf("unexpected error message: %s", got)
	}
}

func TestRasterizeSVGToRGBA_InvalidBinary(t *testing.T) {
	saved := rsvgBinPath
	rsvgBinPath = "/nonexistent/rsvg-convert"
	defer func() { rsvgBinPath = saved }()

	_, err := rasterizeSVGToRGBA([]byte("<svg></svg>"))
	if err == nil {
		t.Fatal("expected error with nonexistent binary path")
	}
}

func TestAssembleGIF(t *testing.T) {
	frames := make([]*image.NRGBA, 2)
	for i := range frames {
		img := image.NewNRGBA(image.Rect(0, 0, 10, 10))
		for y := 0; y < 10; y++ {
			for x := 0; x < 10; x++ {
				img.SetNRGBA(x, y, color.NRGBA{R: 100, G: 150, B: 200, A: 255})
			}
		}
		frames[i] = img
	}

	data, err := assembleGIF(frames)
	if err != nil {
		t.Fatalf("assembleGIF failed: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("assembleGIF returned empty data")
	}
	if data[0] != 'G' || data[1] != 'I' || data[2] != 'F' {
		t.Error("output does not start with GIF magic bytes")
	}
}

func TestAssembleAPNG(t *testing.T) {
	frames := make([]*image.NRGBA, 2)
	for i := range frames {
		img := image.NewNRGBA(image.Rect(0, 0, 10, 10))
		for y := 0; y < 10; y++ {
			for x := 0; x < 10; x++ {
				img.SetNRGBA(x, y, color.NRGBA{R: 50, G: 100, B: 150, A: 255})
			}
		}
		frames[i] = img
	}

	data, err := assembleAPNG(frames)
	if err != nil {
		t.Fatalf("assembleAPNG failed: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("assembleAPNG returned empty data")
	}
	if data[0] != 0x89 || data[1] != 'P' || data[2] != 'N' || data[3] != 'G' {
		t.Error("output does not start with PNG magic bytes")
	}
}

func TestGifPalette(t *testing.T) {
	p := gifPalette()
	if len(p) == 0 {
		t.Fatal("gifPalette returned empty palette")
	}
	if len(p) > 256 {
		t.Errorf("gifPalette has %d entries, max 256", len(p))
	}
	baseLen := len(palette.WebSafe)
	if len(p) < baseLen {
		t.Errorf("gifPalette has %d entries, expected at least %d (WebSafe)", len(p), baseLen)
	}
}

func TestRenderFramesConcurrentRGBA_EmptyRsvg(t *testing.T) {
	saved := rsvgBinPath
	rsvgBinPath = ""
	defer func() { rsvgBinPath = saved }()

	_, err := renderFramesConcurrentRGBA("<svg></svg>", 2, func(idx int, tt float64, svgStr string) string {
		return svgStr
	})
	if err == nil {
		t.Fatal("expected error when rsvgBinPath is empty")
	}
}

func TestAnimCacheConstants(t *testing.T) {
	if animFrameCount != 12 {
		t.Errorf("animFrameCount = %d, want 12", animFrameCount)
	}
	if animFrameDelayGIF != 10 {
		t.Errorf("animFrameDelayGIF = %d, want 10", animFrameDelayGIF)
	}
	if animMaxCacheItems != 200 {
		t.Errorf("animMaxCacheItems = %d, want 200", animMaxCacheItems)
	}
	if animCacheMaxAge != 3600 {
		t.Errorf("animCacheMaxAge = %d, want 3600", animCacheMaxAge)
	}
	if animRasterWidth != 720 {
		t.Errorf("animRasterWidth = %d, want 720", animRasterWidth)
	}
}
