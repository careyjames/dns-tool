// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
        "bytes"
        "crypto/sha256"
        "fmt"
        "image"
        "image/color"
        "image/color/palette"
        "image/draw"
        "image/gif"
        "image/png"
        "log/slog"
        "math"
        "net/http"
        "os/exec"
        "regexp"
        "strings"
        "sync"
        "time"

        "github.com/gin-gonic/gin"
        "github.com/kettek/apng"
)

const (
        animFrameCount    = 12
        animFrameDelayGIF = 10
        animMaxCacheItems = 200
        animCacheMaxAge   = 3600
        animRasterWidth   = 720
)

type animCacheEntry struct {
        data       []byte
        createdAt  time.Time
        lastAccess time.Time
        etag       string
}

var (
        animCache    = make(map[string]*animCacheEntry)
        animCacheMu  sync.RWMutex
        rsvgBinPath  string
)

func init() {
        if p, err := exec.LookPath("rsvg-convert"); err == nil {
                rsvgBinPath = p
        }
}

func (h *BadgeHandler) BadgeAnimated(c *gin.Context) {
        domain, results, scanTime, scanID, postureHash, ok := h.resolveAnalysis(c)
        if !ok {
                return
        }
        if results == nil {
                c.Data(http.StatusOK, contentTypeSVG, badgeSVG(labelDNSTool, "no data", colorGrey))
                return
        }

        style := c.DefaultQuery("style", "detailed")
        if style != "detailed" && style != "covert" {
                c.JSON(http.StatusBadRequest, gin.H{"error": "style must be 'detailed' or 'covert'"})
                return
        }

        format := c.DefaultQuery("format", "apng")
        if format != "apng" && format != "gif" {
                c.JSON(http.StatusBadRequest, gin.H{"error": "format must be 'apng' or 'gif'"})
                return
        }

        cacheKey := fmt.Sprintf("anim:%s:%s:%d:%s", format, style, scanID, postureHash)

        if served := serveAnimFromCache(c, cacheKey, format); served {
                return
        }

        var svgGen func(string, map[string]any, time.Time, int32, string, string) []byte
        switch style {
        case "covert":
                svgGen = badgeSVGCovert
        default:
                svgGen = badgeSVGDetailed
        }

        baseSVG := svgGen(domain, results, scanTime, scanID, postureHash, h.Config.BaseURL)

        frames, err := renderAnimatedFramesRGBA(baseSVG, animFrameCount, style)
        if err != nil {
                slog.Error("BadgeAnimated: render frames failed", "error", err, "domain", domain)
                c.JSON(http.StatusInternalServerError, gin.H{"error": "animation rendering failed"})
                return
        }

        var outData []byte
        switch format {
        case "gif":
                outData, err = assembleGIF(frames)
        default:
                outData, err = assembleAPNG(frames)
        }
        if err != nil {
                slog.Error("BadgeAnimated: assemble failed", "error", err, "domain", domain, "format", format)
                c.JSON(http.StatusInternalServerError, gin.H{"error": "animation assembly failed"})
                return
        }

        etag := storeAnimInCache(cacheKey, outData)

        ext := "png"
        if format == "gif" {
                ext = "gif"
        }
        ct := animContentType(format)
        c.Header("Content-Type", ct)
        c.Header("Cache-Control", fmt.Sprintf("public, max-age=%d", animCacheMaxAge))
        c.Header("ETag", etag)
        c.Header("Content-Disposition", fmt.Sprintf(`inline; filename="%s-dns-topology.%s"`, domain, ext))
        c.Data(http.StatusOK, ct, outData)
}

func serveAnimFromCache(c *gin.Context, cacheKey, format string) bool {
        animCacheMu.RLock()
        entry, cached := animCache[cacheKey]
        if !cached || time.Since(entry.createdAt) >= time.Duration(animCacheMaxAge)*time.Second {
                animCacheMu.RUnlock()
                return false
        }
        entry.lastAccess = time.Now()
        animCacheMu.RUnlock()

        if match := c.GetHeader("If-None-Match"); match == entry.etag {
                c.Status(http.StatusNotModified)
                return true
        }
        ct := animContentType(format)
        c.Header("Content-Type", ct)
        c.Header("Cache-Control", fmt.Sprintf("public, max-age=%d", animCacheMaxAge))
        c.Header("ETag", entry.etag)
        c.Data(http.StatusOK, ct, entry.data)
        return true
}

func storeAnimInCache(cacheKey string, outData []byte) string {
        hash := sha256.Sum256(outData)
        etag := fmt.Sprintf(`"%x"`, hash[:8])

        now := time.Now()
        animCacheMu.Lock()
        if len(animCache) >= animMaxCacheItems {
                evictLRUAnimEntry()
        }
        animCache[cacheKey] = &animCacheEntry{
                data:       outData,
                createdAt:  now,
                lastAccess: now,
                etag:       etag,
        }
        animCacheMu.Unlock()
        return etag
}

func evictLRUAnimEntry() {
        var lruKey string
        var lruTime time.Time
        for k, v := range animCache {
                if lruKey == "" || v.lastAccess.Before(lruTime) {
                        lruKey = k
                        lruTime = v.lastAccess
                }
        }
        if lruKey != "" {
                delete(animCache, lruKey)
        }
}

func animContentType(format string) string {
        if format == "gif" {
                return "image/gif"
        }
        return "image/png"
}

var reAnimateMotionBlock = regexp.MustCompile(
        `<circle\s+r="[\d.]+"\s+fill="([^"]+)"\s+opacity="([^"]+)"><animateMotion\s+dur="([^"]+)"\s+repeatCount="indefinite"\s+path="M([^"]+)"/></circle>`,
)

func renderAnimatedFramesRGBA(baseSVG []byte, frameCount int, style string) ([]*image.NRGBA, error) {
        svgStr := string(baseSVG)

        if style == "covert" {
                return renderCovertFramesRGBA(svgStr, frameCount)
        }
        return renderDetailedFramesRGBA(svgStr, frameCount)
}

func renderDetailedFramesRGBA(svgStr string, frameCount int) ([]*image.NRGBA, error) {
        svgStr = strings.Replace(svgStr,
                `animation: topodata 1.2s linear infinite`,
                `stroke-dashoffset: 0`,
                -1)
        svgStr = strings.Replace(svgStr,
                `@keyframes topodata { to { stroke-dashoffset: -7; } }`,
                "", 1)

        type motionDot struct {
                fillColor string
                opacity   string
                dur       float64
                x1, y1    float64
                x2, y2    float64
        }

        var dots []motionDot
        matches := reAnimateMotionBlock.FindAllStringSubmatch(svgStr, -1)
        for _, m := range matches {
                d := motionDot{
                        fillColor: m[1],
                        opacity:   m[2],
                }
                durStr := m[3]
                if strings.HasSuffix(durStr, "s") {
                        fmt.Sscanf(durStr[:len(durStr)-1], "%f", &d.dur)
                }
                coords := m[4]
                parts := strings.SplitN(coords, " L", 2)
                if len(parts) == 2 {
                        fmt.Sscanf(parts[0], "%f,%f", &d.x1, &d.y1)
                        fmt.Sscanf(parts[1], "%f,%f", &d.x2, &d.y2)
                }
                dots = append(dots, d)
        }

        cleanSVG := reAnimateMotionBlock.ReplaceAllString(svgStr, "")

        return renderFramesConcurrentRGBA(cleanSVG, frameCount, func(idx int, t float64, frameSVG string) string {
                dashOffset := -7.0 * t
                frameSVG = strings.Replace(frameSVG,
                        `stroke-dashoffset: 0`,
                        fmt.Sprintf(`stroke-dashoffset: %.2f`, dashOffset),
                        -1)

                var dotSVG strings.Builder
                for _, d := range dots {
                        if d.dur <= 0 {
                                d.dur = 1.2
                        }
                        dotT := math.Mod(t*1.2/d.dur, 1.0)
                        cx := d.x1 + (d.x2-d.x1)*dotT
                        cy := d.y1 + (d.y2-d.y1)*dotT
                        dotSVG.WriteString(fmt.Sprintf(
                                `<circle cx="%.1f" cy="%.1f" r="2.5" fill="%s" opacity="%s"/>`,
                                cx, cy, d.fillColor, d.opacity,
                        ))
                }

                frameSVG = strings.Replace(frameSVG, "</svg>",
                        dotSVG.String()+"</svg>", 1)
                return frameSVG
        })
}

var (
        reCursorClass = regexp.MustCompile(`\.cursor\s*\{[^}]*\}`)
        reCursorHide  = regexp.MustCompile(`\.cursor-hide\s*\{[^}]*\}`)
        reBlinkKF     = regexp.MustCompile(`@keyframes\s+blink\s*\{[^}]*\}`)
        reTypeInKF    = regexp.MustCompile(`@keyframes\s+typeIn\s*\{[^}]*\}`)
        reFadeInKF    = regexp.MustCompile(`@keyframes\s+fadeIn\s*\{[^}]*\}`)
)

func renderCovertFramesRGBA(svgStr string, frameCount int) ([]*image.NRGBA, error) {
        cleanSVG := reBlinkKF.ReplaceAllString(svgStr, "")
        cleanSVG = reTypeInKF.ReplaceAllString(cleanSVG, "")
        cleanSVG = reFadeInKF.ReplaceAllString(cleanSVG, "")
        cleanSVG = reCursorClass.ReplaceAllString(cleanSVG, `.cursor { opacity: 1; }`)
        cleanSVG = reCursorHide.ReplaceAllString(cleanSVG, `.cursor-hide { opacity: 0; }`)

        return renderFramesConcurrentRGBA(cleanSVG, frameCount, func(idx int, t float64, frameSVG string) string {
                cursorOn := (idx/3)%2 == 0
                if !cursorOn {
                        frameSVG = strings.Replace(frameSVG, `.cursor { opacity: 1; }`, `.cursor { opacity: 0; }`, 1)
                }
                return frameSVG
        })
}

func renderFramesConcurrentRGBA(baseSVG string, frameCount int, frameModifier func(int, float64, string) string) ([]*image.NRGBA, error) {
        frames := make([]*image.NRGBA, frameCount)
        errs := make([]error, frameCount)
        var wg sync.WaitGroup
        sem := make(chan struct{}, 3)

        for i := 0; i < frameCount; i++ {
                wg.Add(1)
                go func(idx int) {
                        defer wg.Done()
                        sem <- struct{}{}
                        defer func() { <-sem }()

                        t := float64(idx) / float64(frameCount)
                        frameSVG := frameModifier(idx, t, baseSVG)

                        img, err := rasterizeSVGToRGBA([]byte(frameSVG))
                        if err != nil {
                                errs[idx] = fmt.Errorf("frame %d: %w", idx, err)
                                return
                        }
                        frames[idx] = img
                }(i)
        }

        wg.Wait()
        for _, err := range errs {
                if err != nil {
                        return nil, err
                }
        }
        return frames, nil
}

func rasterizeSVGToRGBA(svgData []byte) (*image.NRGBA, error) {
        if rsvgBinPath == "" {
                return nil, fmt.Errorf("rsvg-convert: not found in PATH")
        }
        cmd := exec.Command(rsvgBinPath, //nolint:gosec // resolved at init via LookPath
                fmt.Sprintf("--width=%d", animRasterWidth),
                "--keep-aspect-ratio",
                "--format=png",
        )
        cmd.Stdin = bytes.NewReader(svgData)
        var out bytes.Buffer
        cmd.Stdout = &out
        var stderr bytes.Buffer
        cmd.Stderr = &stderr

        if err := cmd.Run(); err != nil {
                return nil, fmt.Errorf("rsvg-convert: %w: %s", err, stderr.String())
        }

        img, err := png.Decode(&out)
        if err != nil {
                return nil, fmt.Errorf("png decode: %w", err)
        }

        bounds := img.Bounds()
        nrgba := image.NewNRGBA(bounds)
        draw.Draw(nrgba, bounds, img, image.Point{}, draw.Src)
        return nrgba, nil
}

func assembleAPNG(frames []*image.NRGBA) ([]byte, error) {
        a := apng.APNG{
                Frames: make([]apng.Frame, len(frames)),
        }

        delayNum := uint16(100)
        delayDen := uint16(1000)

        for i, frame := range frames {
                a.Frames[i] = apng.Frame{
                        Image:            frame,
                        DelayNumerator:   delayNum,
                        DelayDenominator: delayDen,
                        DisposeOp:        apng.DISPOSE_OP_BACKGROUND,
                        BlendOp:          apng.BLEND_OP_SOURCE,
                }
        }

        var buf bytes.Buffer
        if err := apng.Encode(&buf, a); err != nil {
                return nil, fmt.Errorf("apng encode: %w", err)
        }
        return buf.Bytes(), nil
}

func assembleGIF(frames []*image.NRGBA) ([]byte, error) {
        g := &gif.GIF{
                LoopCount: 0,
        }
        pal := gifPalette()
        for _, frame := range frames {
                bounds := frame.Bounds()
                palettedImg := image.NewPaletted(bounds, pal)
                draw.FloydSteinberg.Draw(palettedImg, bounds, frame, image.Point{})
                g.Image = append(g.Image, palettedImg)
                g.Delay = append(g.Delay, animFrameDelayGIF)
        }
        var buf bytes.Buffer
        if err := gif.EncodeAll(&buf, g); err != nil {
                return nil, err
        }
        return buf.Bytes(), nil
}

func gifPalette() color.Palette {
        base := palette.WebSafe

        extras := []color.Color{
                color.RGBA{22, 27, 34, 255},
                color.RGBA{13, 17, 23, 255},
                color.RGBA{33, 38, 45, 255},
                color.RGBA{48, 54, 61, 255},
                color.RGBA{139, 148, 158, 255},
                color.RGBA{230, 237, 243, 255},
                color.RGBA{63, 185, 80, 255},
                color.RGBA{210, 153, 34, 255},
                color.RGBA{248, 81, 73, 255},
                color.RGBA{88, 231, 144, 255},
                color.RGBA{199, 196, 0, 255},
                color.RGBA{180, 60, 41, 255},
                color.RGBA{92, 107, 192, 255},
                color.RGBA{224, 224, 224, 255},
                color.RGBA{25, 135, 84, 255},
                color.RGBA{255, 193, 7, 255},
                color.RGBA{220, 53, 69, 255},
                color.RGBA{255, 107, 107, 255},
        }

        p := make(color.Palette, 0, len(base)+len(extras))
        p = append(p, base...)
        p = append(p, extras...)

        if len(p) > 256 {
                p = p[:256]
        }
        return p
}
