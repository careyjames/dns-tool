// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
	"net/http"

	"dnstool/go-server/internal/config"

	"github.com/gin-gonic/gin"
)

const (
	cvssSpecURL = "https://www.first.org/cvss/v3-1/specification-document"
	firstTLPv2  = "FIRST TLP v2.0"
	firstTLPURL = "https://www.first.org/tlp/"
	cvssNotes   = "Score range specified by FIRST CVSS v3.1. Color derived from NVD implementation convention."
	cvssSource  = "Ranges: FIRST CVSS v3.1 | Colors: NVD convention"
)

type BrandColor struct {
	Name      string
	Token     string
	Value     string
	Category  string
	Notes     string
	Source    string
	SourceURL string
}

type BrandColorsHandler struct {
	Config *config.Config
}

func NewBrandColorsHandler(cfg *config.Config) *BrandColorsHandler {
	return &BrandColorsHandler{Config: cfg}
}

func (h *BrandColorsHandler) BrandColors(c *gin.Context) {
	nonce, _ := c.Get("csp_nonce")
	data := gin.H{
		keyAppVersion:      h.Config.AppVersion,
		keyMaintenanceNote: h.Config.MaintenanceNote,
		keyBetaPages:       h.Config.BetaPages,
		keyCspNonce:        nonce,
		keyActivePage:      "brand-colors",
		"BrandPalette":    getBrandPalette(),
		"StatusColors":    getStatusColors(),
		"SurfaceColors":   getSurfaceColors(),
		"TLPColors":       getTLPColors(),
		"CVSSColors":      getCVSSColors(),
	}
	mergeAuthData(c, h.Config, data)
	c.HTML(http.StatusOK, "brand_colors.html", data)
}

func getBrandPalette() []BrandColor {
	return []BrandColor{
		{
			Name:  "Background Primary",
			Token: "--bg-primary",
			Value: "#0d1117",
			Notes: "Main application background. GitHub-dark aligned.",
		},
		{
			Name:  "Background Secondary",
			Token: "--bg-secondary",
			Value: "#161b22",
			Notes: "Elevated surfaces, code blocks.",
		},
		{
			Name:  "Background Tertiary",
			Token: "--bg-tertiary",
			Value: "#21262d",
			Notes: "Cards, modals, elevated containers.",
		},
		{
			Name:  "Background Elevated",
			Token: "--bg-elevated",
			Value: "#30363d",
			Notes: "Highest elevation surfaces.",
		},
		{
			Name:  "Text Primary",
			Token: "--text-primary",
			Value: "rgba(230,237,243,0.9)",
			Notes: "Off-white for reduced eye strain. ~#e6edf3 at 90%.",
		},
		{
			Name:  "Text Secondary",
			Token: "--text-secondary",
			Value: "rgba(139,148,158,0.9)",
			Notes: "Muted/secondary text.",
		},
		{
			Name:  "Border Default",
			Token: "--border-default",
			Value: "#30363d",
			Notes: "Standard borders.",
		},
		{
			Name:  "Border Muted",
			Token: "--border-muted",
			Value: "#21262d",
			Notes: "Subtle dividers.",
		},
		{
			Name:  "Info Blue",
			Token: "--status-info",
			Value: "#58a6ff",
			Notes: "Primary accent. Links, buttons, informational badges.",
		},
	}
}

func getStatusColors() []BrandColor {
	return []BrandColor{
		{
			Name:  "Success",
			Token: "--status-success",
			Value: "#3fb950",
			Notes: "Verified, safe, pass indicators. 20% desaturated for professionalism.",
		},
		{
			Name:  "Warning",
			Token: "--status-warning",
			Value: "#e3b341",
			Notes: "Caution, review needed. Optimized amber for WCAG AA contrast on dark backgrounds.",
		},
		{
			Name:  "Danger",
			Token: "--status-danger",
			Value: "#f85149",
			Notes: "Critical, fail, error indicators. 20% desaturated for professionalism.",
		},
		{
			Name:  "Info",
			Token: "--status-info",
			Value: "#58a6ff",
			Notes: "Informational, neutral-positive states.",
		},
		{
			Name:  "Neutral",
			Token: "--status-neutral",
			Value: "#8b949e",
			Notes: "Inactive, secondary, not-applicable states.",
		},
	}
}

func getSurfaceColors() []BrandColor {
	return []BrandColor{
		{
			Name:  "Success Surface",
			Token: "--status-success-bg",
			Value: "rgba(63,185,80,0.15)",
			Notes: "Background tint for success states.",
		},
		{
			Name:  "Warning Surface",
			Token: "--status-warning-bg",
			Value: "rgba(227,179,65,0.15)",
			Notes: "Background tint for warning states.",
		},
		{
			Name:  "Danger Surface",
			Token: "--status-danger-bg",
			Value: "rgba(248,81,73,0.15)",
			Notes: "Background tint for danger states.",
		},
		{
			Name:  "Info Surface",
			Token: "--status-info-bg",
			Value: "rgba(88,166,255,0.15)",
			Notes: "Background tint for info states.",
		},
	}
}

func getTLPColors() []BrandColor {
	return []BrandColor{
		{
			Name:      "TLP:RED",
			Token:     ".tlp-badge-red",
			Value:     "#FF2B2B",
			Notes:     "For named recipients only. No further disclosure.",
			Source:    firstTLPv2,
			SourceURL: firstTLPURL,
		},
		{
			Name:      "TLP:AMBER",
			Token:     ".tlp-badge-amber",
			Value:     "#FFC000",
			Notes:     "Limited disclosure within organization and clients. Default classification for DNS Tool reports.",
			Source:    firstTLPv2,
			SourceURL: firstTLPURL,
		},
		{
			Name:      "TLP:AMBER+STRICT",
			Token:     ".tlp-badge-amber-strict",
			Value:     "#FFC000",
			Notes:     "Limited to organization only, no client sharing.",
			Source:    firstTLPv2,
			SourceURL: firstTLPURL,
		},
		{
			Name:      "TLP:GREEN",
			Token:     ".tlp-badge-green",
			Value:     "#33A532",
			Notes:     "Community-wide sharing permitted.",
			Source:    firstTLPv2,
			SourceURL: firstTLPURL,
		},
		{
			Name:      "TLP:CLEAR",
			Token:     ".tlp-badge-clear",
			Value:     "#FFFFFF",
			Notes:     "Unlimited disclosure. White text on dark background, bordered on light.",
			Source:    firstTLPv2,
			SourceURL: firstTLPURL,
		},
	}
}

func getCVSSColors() []BrandColor {
	return []BrandColor{
		{
			Name:      "Critical (9.0–10.0)",
			Token:     ".u-severity-critical",
			Value:     "#cc0000",
			Notes:     cvssNotes,
			Source:    cvssSource,
			SourceURL: cvssSpecURL,
		},
		{
			Name:      "High (7.0–8.9)",
			Token:     ".u-severity-high",
			Value:     "#df3d03",
			Notes:     cvssNotes,
			Source:    cvssSource,
			SourceURL: cvssSpecURL,
		},
		{
			Name:      "Medium (4.0–6.9)",
			Token:     ".u-severity-medium",
			Value:     "#f9a009",
			Notes:     cvssNotes,
			Source:    cvssSource,
			SourceURL: cvssSpecURL,
		},
		{
			Name:      "Low (0.1–3.9)",
			Token:     ".u-severity-low",
			Value:     "#ffcb0d",
			Notes:     cvssNotes,
			Source:    cvssSource,
			SourceURL: cvssSpecURL,
		},
		{
			Name:      "None (0.0)",
			Token:     ".u-severity-none",
			Value:     "#53aa33",
			Notes:     cvssNotes,
			Source:    cvssSource,
			SourceURL: cvssSpecURL,
		},
	}
}
