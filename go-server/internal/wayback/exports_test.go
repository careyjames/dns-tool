package wayback

import (
	"context"
)

func archiveWithEndpoint(ctx context.Context, endpoint, targetURL string) ArchiveResult {
	return archiveWith(ctx, endpoint, targetURL)
}
