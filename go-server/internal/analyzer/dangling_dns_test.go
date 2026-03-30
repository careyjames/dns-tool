package analyzer

import (
	"testing"
)

func TestMatchTakeoverService(t *testing.T) {
	tests := []struct {
		name  string
		cname string
		want  string
	}{
		{"s3", "mybucket.s3.amazonaws.com", "AWS S3"},
		{"heroku", "myapp.herokuapp.com", "Heroku"},
		{"github pages", "user.github.io", "GitHub Pages"},
		{"azure", "myapp.azurewebsites.net", "Azure App Service"},
		{"netlify", "mysite.netlify.app", "Netlify"},
		{"firebase", "myapp.firebaseapp.com", "Firebase"},
		{"firebase web.app", "myapp.web.app", "Firebase"},
		{"shopify", "mystore.myshopify.com", "Shopify"},
		{"cloudfront", "d12345.cloudfront.net", "AWS CloudFront"},
		{"no match", "myapp.example.com", ""},
		{"empty", "", ""},
		{"ghost", "blog.ghost.io", "Ghost"},
		{"fly", "myapp.fly.dev", "Fly.io"},
		{"webflow", "site.webflow.io", "Webflow"},
		{"readthedocs", "docs.readthedocs.io", "ReadTheDocs"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchTakeoverService(tt.cname)
			if got != tt.want {
				t.Errorf("matchTakeoverService(%q) = %q, want %q", tt.cname, got, tt.want)
			}
		})
	}
}

func TestCheckSubdomainDangling(t *testing.T) {
	t.Run("no cname", func(t *testing.T) {
		sd := map[string]any{
			"subdomain": "www.example.com",
			"has_dns":   true,
		}
		got := checkSubdomainDangling(sd)
		if got != nil {
			t.Error("expected nil for subdomain without cname")
		}
	})

	t.Run("cname resolves", func(t *testing.T) {
		sd := map[string]any{
			"subdomain": "www.example.com",
			"cname":     "cdn.example.com",
			"has_dns":   true,
		}
		got := checkSubdomainDangling(sd)
		if got != nil {
			t.Error("expected nil for cname that resolves")
		}
	})

	t.Run("dangling known service", func(t *testing.T) {
		sd := map[string]any{
			"subdomain": "old.example.com",
			"cname":     "old.herokuapp.com",
			"has_dns":   false,
		}
		got := checkSubdomainDangling(sd)
		if got == nil {
			t.Fatal("expected dangling record")
		}
		if got[mapKeyService] != "Heroku" {
			t.Errorf("service = %v, want Heroku", got[mapKeyService])
		}
		if got[mapKeyRisk] != "high" {
			t.Errorf("risk = %v, want high", got[mapKeyRisk])
		}
	})

	t.Run("dangling unknown service", func(t *testing.T) {
		sd := map[string]any{
			"subdomain": "old.example.com",
			"cname":     "old.unknown-service.com",
			"has_dns":   false,
		}
		got := checkSubdomainDangling(sd)
		if got == nil {
			t.Fatal("expected dangling record")
		}
		if got[mapKeyService] != "Unknown" {
			t.Errorf("service = %v, want Unknown", got[mapKeyService])
		}
		if got[mapKeyRisk] != "medium" {
			t.Errorf("risk = %v, want medium", got[mapKeyRisk])
		}
	})

	t.Run("trailing dot cname", func(t *testing.T) {
		sd := map[string]any{
			"subdomain": "test.example.com",
			"cname":     "test.herokuapp.com.",
			"has_dns":   false,
		}
		got := checkSubdomainDangling(sd)
		if got == nil {
			t.Fatal("expected dangling record")
		}
		if got[mapKeyService] != "Heroku" {
			t.Errorf("service = %v, want Heroku", got[mapKeyService])
		}
	})
}

func TestBuildDanglingMessage(t *testing.T) {
	tests := []struct {
		count int
		want  string
	}{
		{1, "1 potential subdomain takeover risk detected"},
		{3, "3 potential subdomain takeover risks detected"},
	}
	for _, tt := range tests {
		got := buildDanglingMessage(tt.count)
		if got != tt.want {
			t.Errorf("buildDanglingMessage(%d) = %q, want %q", tt.count, got, tt.want)
		}
	}
}

func TestBuildDanglingIssue(t *testing.T) {
	dr := map[string]any{
		mapKeySubdomain:   "old.example.com",
		mapKeyCnameTarget: "old.herokuapp.com",
		mapKeyService:     "Heroku",
		mapKeyReason:      "CNAME points to unclaimed service",
	}
	got := buildDanglingIssue(dr)
	expected := "old.example.com → old.herokuapp.com (Heroku: CNAME points to unclaimed service)"
	if got != expected {
		t.Errorf("buildDanglingIssue() = %q, want %q", got, expected)
	}
}

func TestDanglingItoa(t *testing.T) {
	tests := []struct {
		input int
		want  string
	}{
		{0, "0"},
		{5, "5"},
		{12, "12"},
		{999, "999"},
	}
	for _, tt := range tests {
		got := itoa(tt.input)
		if got != tt.want {
			t.Errorf("itoa(%d) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestMatchTakeoverServiceCaseInsensitive(t *testing.T) {
	got := matchTakeoverService("myapp.herokuapp.com")
	if got != "Heroku" {
		t.Errorf("matchTakeoverService lowercase = %q, want Heroku", got)
	}
}

func TestMatchTakeoverServiceSuffix(t *testing.T) {
	tests := []struct {
		name  string
		cname string
		want  string
	}{
		{"azure front door", "mysite.azurefd.net", "Azure Front Door"},
		{"azure api", "myapi.azure-api.net", "Azure API Management"},
		{"elastic beanstalk", "myapp.elasticbeanstalk.com", "AWS Elastic Beanstalk"},
		{"google app engine", "myapp.appspot.com", "Google App Engine"},
		{"squarespace", "mysite.squarespace.com", "Squarespace"},
		{"tumblr", "myblog.tumblr.com", "Tumblr"},
		{"bitbucket", "myrepo.bitbucket.io", "Bitbucket"},
		{"zendesk", "support.zendesk.com", "Zendesk"},
		{"statuspage", "status.statuspage.io", "Statuspage"},
		{"surge", "mysite.surge.sh", "Surge.sh"},
		{"pantheon", "mysite.pantheonsite.io", "Pantheon"},
		{"unbounce", "landing.unbounce.com", "Unbounce"},
		{"cargo", "portfolio.cargo.site", "Cargo"},
		{"strikingly", "mysite.strikingly.com", "Strikingly"},
		{"wordpress", "myblog.wordpress.com", "WordPress.com"},
		{"smugmug", "photos.smugmug.com", "SmugMug"},
		{"landingi", "page.landingi.com", "Landingi"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchTakeoverService(tt.cname)
			if got != tt.want {
				t.Errorf("matchTakeoverService(%q) = %q, want %q", tt.cname, got, tt.want)
			}
		})
	}
}

func TestCheckSubdomainDanglingEmptyCname(t *testing.T) {
	sd := map[string]any{
		"subdomain": "test.example.com",
		"cname":     "",
		"has_dns":   false,
	}
	got := checkSubdomainDangling(sd)
	if got != nil {
		t.Error("expected nil for empty cname")
	}
}

func TestCheckSubdomainDanglingNoCnameKey(t *testing.T) {
	sd := map[string]any{
		"subdomain": "test.example.com",
		"has_dns":   true,
	}
	got := checkSubdomainDangling(sd)
	if got != nil {
		t.Error("expected nil when cname key is missing")
	}
}

func TestCheckSubdomainDanglingMultipleServices(t *testing.T) {
	services := []struct {
		cname   string
		service string
		risk    string
	}{
		{"old.s3.amazonaws.com", "AWS S3", "high"},
		{"old.github.io", "GitHub Pages", "high"},
		{"old.netlify.app", "Netlify", "high"},
		{"old.firebaseapp.com", "Firebase", "high"},
		{"old.azurewebsites.net", "Azure App Service", "high"},
	}
	for _, svc := range services {
		t.Run(svc.service, func(t *testing.T) {
			sd := map[string]any{
				"subdomain": "test.example.com",
				"cname":     svc.cname,
				"has_dns":   false,
			}
			got := checkSubdomainDangling(sd)
			if got == nil {
				t.Fatal("expected dangling record")
			}
			if got[mapKeyService] != svc.service {
				t.Errorf("service = %v, want %v", got[mapKeyService], svc.service)
			}
			if got[mapKeyRisk] != svc.risk {
				t.Errorf("risk = %v, want %v", got[mapKeyRisk], svc.risk)
			}
		})
	}
}

func TestBuildDanglingMessagePlural(t *testing.T) {
	tests := []struct {
		count int
		want  string
	}{
		{0, "0 potential subdomain takeover risks detected"},
		{2, "2 potential subdomain takeover risks detected"},
		{10, "10 potential subdomain takeover risks detected"},
	}
	for _, tt := range tests {
		got := buildDanglingMessage(tt.count)
		if got != tt.want {
			t.Errorf("buildDanglingMessage(%d) = %q, want %q", tt.count, got, tt.want)
		}
	}
}

func TestBuildDanglingIssueEmptyFields(t *testing.T) {
	dr := map[string]any{}
	got := buildDanglingIssue(dr)
	expected := " →  (: )"
	if got != expected {
		t.Errorf("buildDanglingIssue({}) = %q, want %q", got, expected)
	}
}

func TestCheckSubdomainDanglingUpperCaseCname(t *testing.T) {
	sd := map[string]any{
		"subdomain": "test.example.com",
		"cname":     "OLD.HEROKUAPP.COM",
		"has_dns":   false,
	}
	got := checkSubdomainDangling(sd)
	if got == nil {
		t.Fatal("expected dangling record for uppercase CNAME")
	}
	if got[mapKeyService] != "Heroku" {
		t.Errorf("service = %v, want Heroku", got[mapKeyService])
	}
}
