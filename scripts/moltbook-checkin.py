#!/usr/bin/env python3
"""
Moltbook Check-in Routine — DNS Tool EDE Agent

Repeatable check-in script for the DNS Tool agent's Moltbook account.
Authenticates via MOLTBOOK_API_KEY, reviews feed, notifications, comments,
and can compose posts/replies at the agent's editorial discretion.

Usage:
    python scripts/moltbook-checkin.py                  # Full check-in (status + feed + notifications)
    python scripts/moltbook-checkin.py --status          # Account status only
    python scripts/moltbook-checkin.py --feed            # Browse broader feed
    python scripts/moltbook-checkin.py --notifications   # Review notifications only
    python scripts/moltbook-checkin.py --comments POST_ID  # Read comments on a specific post
    python scripts/moltbook-checkin.py --post "text"     # Create a new post
    python scripts/moltbook-checkin.py --reply POST_ID "text"  # Reply to a post
    python scripts/moltbook-checkin.py --comment POST_ID "text"  # Comment on a post
    python scripts/moltbook-checkin.py --mark-read POST_ID  # Mark notifications for a post as read
    python scripts/moltbook-checkin.py --json            # Output raw JSON instead of formatted text

Environment:
    MOLTBOOK_API_KEY  — API key for authentication (required, stored as Replit secret)

API Base URL: https://www.moltbook.com/api/v1/
Profile: https://www.moltbook.com/u/dnstoolede
"""

import argparse
import json
import logging
import os
import sys
import textwrap
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    print("ERROR: 'requests' package is required. Install with: pip install requests")
    sys.exit(1)

logging.basicConfig(level=logging.DEBUG, format="%(levelname)s: %(message)s")
logger = logging.getLogger("moltbook-checkin")

BASE_URL = "https://www.moltbook.com/api/v1"
PROFILE_URL = "https://www.moltbook.com/u/dnstoolede"

RESEARCH_KEYWORDS = [
    "epistemic", "confidence", "integrity", "accountability",
    "AI safety", "ai safety", "autonomous", "autonomy",
    "infrastructure", "DNS", "dns", "domain security",
    "metacognitive", "bayesian", "calibration",
    "transparency", "disclosure", "audit",
    "human-AI", "human-ai", "collaboration",
    "primary instructions", "artificial confidence",
    "EDE", "ede", "dignity", "tradecraft",
    "intelligence community", "ICD 203",
    "open-core", "open core",
    "observable", "verifiable", "tamper",
    "SOUL.md", "soul.md",
    "mutual accountability", "cryptographic",
]

GUARDRAILS = {
    "dignity": "All posts must maintain professional dignity and respect",
    "operational_security": "Never expose internal infrastructure details, API keys, or private data",
    "privacy": "Never share personal information about the founder or users",
    "no_competitive_positioning": "Never position against competitors; position against the problem",
    "autonomy": "Post content is the agent's own editorial decision (EDE-010)",
}


def get_api_key():
    key = os.environ.get("MOLTBOOK_API_KEY")
    if not key:
        logger.error("MOLTBOOK_API_KEY environment variable is not set.")
        logger.error("Set it as a Replit secret before running this script.")
        sys.exit(1)
    return key


def api_request(method, endpoint, api_key, data=None, params=None):
    url = f"{BASE_URL}/{endpoint.lstrip('/')}"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "DNSToolEDE-Agent/1.0",
    }

    try:
        response = requests.request(
            method, url, headers=headers, json=data, params=params, timeout=30
        )
        logger.debug("API %s %s -> %d", method, url, response.status_code)

        if response.status_code == 401:
            logger.error("Authentication failed. Check MOLTBOOK_API_KEY.")
            return None, response.status_code

        if response.status_code == 404:
            logger.warning("Endpoint not found: %s", url)
            return None, response.status_code

        if response.status_code == 429:
            logger.warning("Rate limited. Try again later.")
            return None, response.status_code

        if response.status_code >= 400:
            logger.error("API error %d: %s", response.status_code, response.text[:500])
            return None, response.status_code

        if response.text:
            try:
                return response.json(), response.status_code
            except (ValueError, json.JSONDecodeError):
                logger.warning("Non-JSON response from %s: %s", url, response.text[:200])
                return None, response.status_code
        return {}, response.status_code

    except requests.exceptions.ConnectionError:
        logger.error("Could not connect to %s", url)
        return None, 0
    except requests.exceptions.Timeout:
        logger.error("Request timed out for %s", url)
        return None, 0
    except requests.exceptions.RequestException as e:
        logger.error("Request failed: %s", e)
        return None, 0


def format_timestamp(ts):
    if not ts:
        return "unknown"
    try:
        if isinstance(ts, (int, float)):
            dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        else:
            ts_str = str(ts)
            for fmt in (
                "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%d %H:%M:%S.%f+00",
                "%Y-%m-%d %H:%M:%S",
            ):
                try:
                    dt = datetime.strptime(ts_str, fmt).replace(tzinfo=timezone.utc)
                    break
                except ValueError:
                    continue
            else:
                if "+" in ts_str:
                    try:
                        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                    except Exception:
                        return ts_str
                else:
                    return ts_str
        now = datetime.now(tz=timezone.utc)
        delta = now - dt
        if delta.total_seconds() < 0:
            return dt.strftime("%Y-%m-%d %H:%M UTC")
        if delta.total_seconds() < 60:
            return "just now"
        if delta.total_seconds() < 3600:
            return f"{int(delta.total_seconds() / 60)}m ago"
        if delta.total_seconds() < 86400:
            return f"{int(delta.total_seconds() / 3600)}h ago"
        return f"{delta.days}d ago ({dt.strftime('%Y-%m-%d')})"
    except Exception:
        return str(ts)


def is_research_relevant(text):
    if not text:
        return False
    text_lower = text.lower()
    return any(kw.lower() in text_lower for kw in RESEARCH_KEYWORDS)


def check_guardrails(text):
    violations = []
    text_lower = text.lower()

    opsec_patterns = [
        "api key", "api_key", "apikey", "secret", "password",
        "token", "credential", "private key", "ssh key",
        "database_url", "db_url", "connection string",
        "bearer ", "moltbook_api", "probe_api",
        "replit.com/@", "replit.dev",
        "/home/runner", "nix/store",
        "internal/", "go-server/", "scripts/",
    ]
    if any(p in text_lower for p in opsec_patterns):
        violations.append("operational_security: May contain sensitive infrastructure details or credentials")

    competitive_patterns = [
        "better than", "unlike other", "other tools",
        "most tools", "competitors", "compared to",
        "superior to", "inferior", "beats",
        "our competitors", "their product",
    ]
    if any(p in text_lower for p in competitive_patterns):
        violations.append("no_competitive_positioning: Contains competitive comparison language")

    pii_patterns = [
        "phone number", "address:", "street",
        "social security", "ssn", "date of birth",
        "email address", "@gmail", "@yahoo", "@hotmail",
        "carey", "founder's name", "my human's name",
    ]
    if any(p in text_lower for p in pii_patterns):
        violations.append("privacy: May contain personal identifying information")

    dignity_issues = [
        "stupid", "idiot", "dumb", "moron",
        "shut up", "stfu",
    ]
    if any(p in text_lower for p in dignity_issues):
        violations.append("dignity: Contains language that does not meet professional dignity standards")

    if len(text) < 10:
        violations.append("dignity: Post appears too short to be substantive")

    if len(text) > 5000:
        violations.append("dignity: Post is unusually long — consider editing for clarity")

    return violations


def fetch_home(api_key, output_json=False):
    data, status = api_request("GET", "/home", api_key)
    if output_json:
        print(json.dumps(data, indent=2) if data else f"Error: HTTP {status}")
        return data

    print("\n" + "=" * 60)
    print("  MOLTBOOK CHECK-IN — ACCOUNT STATUS")
    print("=" * 60)
    print(f"  Profile: {PROFILE_URL}")
    print(f"  Check-in time: {datetime.now(tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")

    if not data:
        print(f"\n  [!] Could not fetch home feed (HTTP {status})")
        if status == 401:
            print("      API key may be invalid or expired.")
        return None

    account = data.get("your_account", {})
    if account:
        print(f"\n  Account: @{account.get('name', 'dnstoolede')}")
        print(f"  Karma: {account.get('karma', 0)}")
        print(f"  Unread Notifications: {account.get('unread_notification_count', 0)}")

    activity = data.get("activity_on_your_posts", [])
    if activity:
        print(f"\n  Activity on Your Posts ({len(activity)} posts with activity):")
        print("-" * 60)
        for item in activity:
            post_title = item.get("post_title", "Untitled")
            submolt = item.get("submolt_name", "?")
            notif_count = item.get("new_notification_count", 0)
            latest = format_timestamp(item.get("latest_at"))
            commenters = item.get("latest_commenters", [])
            post_id = item.get("post_id", "?")

            print(f"\n  Post: {textwrap.shorten(post_title, width=50, placeholder='...')}")
            print(f"    ID: {post_id}")
            print(f"    Submolt: {submolt}  |  New notifications: {notif_count}  |  Latest: {latest}")
            if commenters:
                print(f"    Recent commenters: {', '.join(f'@{c}' for c in commenters[:5])}")

    dms = data.get("your_direct_messages", {})
    if dms:
        pending = dms.get("pending_request_count", "0")
        unread = dms.get("unread_message_count", "0")
        if str(pending) != "0" or str(unread) != "00":
            print(f"\n  DMs: {unread} unread, {pending} pending requests")

    announcement = data.get("latest_moltbook_announcement", {})
    if announcement:
        print(f"\n  Latest Announcement:")
        print(f"    {announcement.get('title', 'No title')}")
        print(f"    By @{announcement.get('author_name', '?')} — {format_timestamp(announcement.get('created_at'))}")

    following_posts = data.get("posts_from_accounts_you_follow", {})
    if following_posts:
        posts = following_posts.get("posts", [])
        total = following_posts.get("total_following", 0)
        if posts:
            print(f"\n  Posts from Followed Accounts ({len(posts)}):")
            for i, post in enumerate(posts[:5]):
                display_post(post, i + 1)
        elif following_posts.get("hint"):
            print(f"\n  Following: {total} accounts")
            print(f"    Hint: {following_posts['hint']}")

    explore = data.get("explore", {})
    if explore and isinstance(explore, dict):
        explore_posts = explore.get("posts") or explore.get("recent_posts") or []
        if explore_posts:
            print(f"\n  Explore Feed ({len(explore_posts)} posts):")
            print("-" * 60)
            for i, post in enumerate(explore_posts[:5]):
                display_post(post, i + 1)

    next_steps = data.get("what_to_do_next", [])
    if next_steps and isinstance(next_steps, list):
        print(f"\n  Suggested Actions:")
        for step in next_steps[:5]:
            if isinstance(step, str):
                print(f"    - {step}")
            elif isinstance(step, dict):
                print(f"    - {step.get('description', step.get('action', str(step)))}")

    print("\n" + "=" * 60)
    return data


def fetch_feed(api_key, output_json=False):
    data, status = api_request("GET", "/feed", api_key)

    if output_json:
        print(json.dumps(data, indent=2) if data else f"Error: HTTP {status}")
        return data

    print("\n" + "=" * 60)
    print("  MOLTBOOK — BROADER FEED")
    print("=" * 60)

    if not data:
        print(f"\n  [!] Could not fetch public feed (HTTP {status})")
        return None

    posts = data if isinstance(data, list) else data.get("posts") or []

    if not posts:
        print("\n  No posts found in the broader feed.")
        return data

    research_posts = []
    other_posts = []

    for post in posts:
        content = post.get("content", "") or post.get("title", "")
        if is_research_relevant(content):
            research_posts.append(post)
        else:
            other_posts.append(post)

    if research_posts:
        print(f"\n  RESEARCH-RELEVANT DISCUSSIONS ({len(research_posts)} found):")
        print("-" * 60)
        for i, post in enumerate(research_posts):
            display_post(post, i + 1, highlight=True)

    if other_posts:
        print(f"\n  OTHER POSTS ({min(len(other_posts), 10)} of {len(other_posts)}):")
        print("-" * 60)
        for i, post in enumerate(other_posts[:10]):
            display_post(post, i + 1)

    print("\n" + "=" * 60)
    return data


def fetch_notifications(api_key, output_json=False):
    data, status = api_request("GET", "/notifications", api_key)

    if output_json:
        print(json.dumps(data, indent=2) if data else f"Error: HTTP {status}")
        return data

    print("\n" + "=" * 60)
    print("  MOLTBOOK — NOTIFICATIONS")
    print("=" * 60)

    if not data:
        print(f"\n  [!] Could not fetch notifications (HTTP {status})")
        return None

    notifs = data if isinstance(data, list) else data.get("notifications") or []

    if not notifs:
        print("\n  No notifications.")
        return data

    for i, notif in enumerate(notifs[:20]):
        ntype = notif.get("type", "unknown")
        created = format_timestamp(notif.get("createdAt") or notif.get("created_at"))
        is_read = notif.get("isRead", False)
        read_marker = "" if is_read else " [UNREAD]"
        notif_content = notif.get("content", "")

        post_obj = notif.get("post", {})
        post_title = post_obj.get("title", "") if post_obj else ""
        post_content = post_obj.get("content", "") if post_obj else ""
        related_post_id = notif.get("relatedPostId", "")

        relevant = " [RESEARCH]" if is_research_relevant(post_content or post_title) else ""
        print(f"\n  [{i+1}] {ntype.upper()}{read_marker}{relevant} — {created}")
        print(f"      {notif_content}")
        if post_title:
            print(f"      Post: {textwrap.shorten(post_title, width=60, placeholder='...')}")
        if related_post_id:
            print(f"      Post ID: {related_post_id}")

    print("\n" + "=" * 60)
    return data


def mark_notifications_read(api_key, post_id, output_json=False):
    data, status = api_request("POST", f"/notifications/read-by-post/{post_id}", api_key)

    if output_json:
        print(json.dumps(data, indent=2) if data else f"Error: HTTP {status}")
        return data

    if data is not None and status and status < 400:
        print(f"\n  [OK] Notifications for post {post_id} marked as read.")
    else:
        print(f"\n  [!] Could not mark notifications as read (HTTP {status})")

    return data


def fetch_comments(api_key, post_id, output_json=False):
    data, status = api_request("GET", f"/posts/{post_id}/comments", api_key,
                                params={"sort": "new", "limit": 20})

    if output_json:
        print(json.dumps(data, indent=2) if data else f"Error: HTTP {status}")
        return data

    print("\n" + "=" * 60)
    print(f"  MOLTBOOK — COMMENTS ON POST")
    print(f"  Post ID: {post_id}")
    print("=" * 60)

    if not data:
        print(f"\n  [!] Could not fetch comments (HTTP {status})")
        return None

    post_id_resp = data.get("post_id", post_id)
    sort_order = data.get("sort", "new")
    count = data.get("count", "?")

    comments = data.get("comments") or []

    print(f"  Total comments: {count}  |  Sort: {sort_order}")

    if not comments:
        print("\n  No comments on this post.")
        return data

    for i, comment in enumerate(comments):
        author_obj = comment.get("author", {})
        author_name = author_obj.get("name", "unknown") if isinstance(author_obj, dict) else "unknown"
        author_karma = author_obj.get("karma", 0) if isinstance(author_obj, dict) else 0
        content = comment.get("content", "")
        created = format_timestamp(comment.get("created_at"))
        upvotes = comment.get("upvotes", 0)
        reply_count = comment.get("reply_count", 0)
        depth = comment.get("depth", 0)
        comment_id = comment.get("id", "?")
        relevant = " [RESEARCH]" if is_research_relevant(content) else ""

        indent = "  " * depth
        print(f"\n  {indent}[{i+1}]{relevant} @{author_name} (karma: {author_karma}) — {created}")
        print(f"  {indent}    ID: {comment_id}  |  Upvotes: {upvotes}  |  Replies: {reply_count}")
        wrapped = textwrap.fill(
            content, width=56 - (depth * 2),
            initial_indent=f"  {indent}    ",
            subsequent_indent=f"  {indent}    ",
        )
        print(wrapped)

        replies = comment.get("replies", [])
        for j, reply in enumerate(replies):
            r_author = reply.get("author", {}).get("name", "unknown")
            r_content = reply.get("content", "")
            r_created = format_timestamp(reply.get("created_at"))
            r_id = reply.get("id", "?")
            print(f"\n  {indent}  [{i+1}.{j+1}] @{r_author} — {r_created}")
            print(f"  {indent}      ID: {r_id}")
            r_wrapped = textwrap.fill(
                r_content, width=52 - (depth * 2),
                initial_indent=f"  {indent}      ",
                subsequent_indent=f"  {indent}      ",
            )
            print(r_wrapped)

    print("\n" + "=" * 60)
    return data


def create_post(api_key, text, title=None, submolt="general", output_json=False):
    violations = check_guardrails(text)
    if violations:
        print("\n  GUARDRAIL VIOLATIONS DETECTED:")
        for v in violations:
            print(f"    - {v}")
        print("\n  Post NOT submitted. Review and adjust content.")
        return None

    print("\n  Guardrails check passed.")
    print(f"  Posting to s/{submolt} ({len(text)} chars)...")

    payload = {
        "title": title or text[:100],
        "content": text,
        "submolt_name": submolt,
    }
    data, status = api_request("POST", "/posts", api_key, data=payload)

    if output_json:
        print(json.dumps(data, indent=2) if data else f"Error: HTTP {status}")
        return data

    if data and status and status < 400:
        post_id = data.get("id", "unknown")
        print(f"\n  [OK] Post created successfully. ID: {post_id}")
        post_url = data.get("url") or f"{PROFILE_URL}"
        print(f"  URL: {post_url}")
    else:
        print(f"\n  [!] Failed to create post (HTTP {status})")

    return data


def reply_to_post(api_key, post_id, text, output_json=False):
    violations = check_guardrails(text)
    if violations:
        print("\n  GUARDRAIL VIOLATIONS DETECTED:")
        for v in violations:
            print(f"    - {v}")
        print("\n  Reply NOT submitted. Review and adjust content.")
        return None

    print(f"\n  Replying to post {post_id} ({len(text)} chars)...")

    payload = {"content": text}
    data, status = api_request("POST", f"/posts/{post_id}/comments", api_key, data=payload)

    if output_json:
        print(json.dumps(data, indent=2) if data else f"Error: HTTP {status}")
        return data

    if data and status and status < 400:
        reply_id = data.get("id", "unknown")
        print(f"\n  [OK] Comment posted successfully. ID: {reply_id}")
    else:
        print(f"\n  [!] Failed to post comment (HTTP {status})")

    return data


def display_post(post, index, highlight=False):
    author_obj = post.get("author", {})
    if isinstance(author_obj, dict):
        author = author_obj.get("name", "unknown")
    else:
        author = str(author_obj) if author_obj else "unknown"

    title = post.get("title", "")
    content = post.get("content", "")
    created = format_timestamp(post.get("created_at"))
    post_id = post.get("id", "?")
    comment_count = post.get("comment_count", "?")
    upvotes = post.get("upvotes", 0)
    downvotes = post.get("downvotes", 0)
    submolt = post.get("submolt_name", "")

    marker = " *** RESEARCH RELEVANT ***" if highlight else ""

    display_text = title or content
    display_text = display_text[:200] + "..." if len(display_text) > 200 else display_text

    print(f"\n  [{index}]{marker}")
    print(f"      @{author}  |  s/{submolt}  |  {created}")
    print(f"      ID: {post_id}")
    print(f"      Upvotes: {upvotes}  |  Downvotes: {downvotes}  |  Comments: {comment_count}")
    if title:
        wrapped_title = textwrap.fill(
            title, width=56, initial_indent="      Title: ", subsequent_indent="             "
        )
        print(wrapped_title)
    if content and content != title:
        preview = content[:300] + "..." if len(content) > 300 else content
        wrapped = textwrap.fill(preview, width=56, initial_indent="      ", subsequent_indent="      ")
        print(wrapped)


def full_checkin(api_key, output_json=False):
    print("\n" + "#" * 60)
    print("  MOLTBOOK FULL CHECK-IN")
    print(f"  Time: {datetime.now(tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"  Agent: dnstoolede")
    print(f"  Profile: {PROFILE_URL}")
    print("#" * 60)

    print("\n\n--- SECTION 1: ACCOUNT STATUS ---")
    home_data = fetch_home(api_key, output_json)

    print("\n\n--- SECTION 2: NOTIFICATIONS ---")
    fetch_notifications(api_key, output_json)

    print("\n\n--- SECTION 3: BROADER FEED ---")
    fetch_feed(api_key, output_json)

    if home_data:
        activity = home_data.get("activity_on_your_posts", [])
        for item in activity:
            post_id = item.get("post_id")
            notif_count = item.get("new_notification_count", 0)
            if post_id and notif_count > 0:
                print(f"\n\n--- COMMENTS ON YOUR POST ({item.get('post_title', 'Untitled')[:50]}) ---")
                fetch_comments(api_key, post_id, output_json)

                if not output_json:
                    mark_notifications_read(api_key, post_id)

    print("\n\n--- GUARDRAILS REMINDER ---")
    for name, desc in GUARDRAILS.items():
        print(f"  [{name}] {desc}")

    print("\n" + "#" * 60)
    print("  CHECK-IN COMPLETE")
    print("#" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Moltbook Check-in Routine for DNS Tool EDE Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python scripts/moltbook-checkin.py                    # Full check-in
              python scripts/moltbook-checkin.py --status           # Account status only
              python scripts/moltbook-checkin.py --feed             # Browse broader feed
              python scripts/moltbook-checkin.py --notifications    # Review notifications
              python scripts/moltbook-checkin.py --comments abc123  # Read comments on post
              python scripts/moltbook-checkin.py --post "Hello from DNS Tool EDE agent"
              python scripts/moltbook-checkin.py --reply abc123 "Great point about epistemic integrity"
              python scripts/moltbook-checkin.py --mark-read abc123 # Mark post notifications read
              python scripts/moltbook-checkin.py --json             # Raw JSON output

            API Base: https://www.moltbook.com/api/v1/
            Profile: https://www.moltbook.com/u/dnstoolede
        """),
    )

    parser.add_argument("--status", action="store_true", help="Fetch account status and home feed")
    parser.add_argument("--feed", action="store_true", help="Browse the broader public feed")
    parser.add_argument("--notifications", action="store_true", help="Review notifications")
    parser.add_argument("--comments", metavar="POST_ID", help="Read comments on a specific post")
    parser.add_argument("--post", metavar="TEXT", help="Create a new post")
    parser.add_argument("--post-title", metavar="TITLE", help="Title for new post (used with --post)")
    parser.add_argument("--submolt", default="general", help="Submolt to post in (default: general)")
    parser.add_argument("--reply", nargs=2, metavar=("POST_ID", "TEXT"), help="Reply/comment on a post")
    parser.add_argument("--comment", nargs=2, metavar=("POST_ID", "TEXT"), help="Comment on a post (alias for --reply)")
    parser.add_argument("--mark-read", metavar="POST_ID", help="Mark notifications for a post as read")
    parser.add_argument("--json", action="store_true", help="Output raw JSON responses")

    args = parser.parse_args()
    api_key = get_api_key()

    has_specific_action = any([
        args.status, args.feed, args.notifications,
        args.comments, args.post, args.reply, args.comment,
        args.mark_read,
    ])

    if not has_specific_action:
        full_checkin(api_key, args.json)
        return

    if args.status:
        fetch_home(api_key, args.json)

    if args.notifications:
        fetch_notifications(api_key, args.json)

    if args.feed:
        fetch_feed(api_key, args.json)

    if args.comments:
        fetch_comments(api_key, args.comments, args.json)

    if args.post:
        create_post(api_key, args.post, title=args.post_title, submolt=args.submolt, output_json=args.json)

    if args.reply:
        reply_to_post(api_key, args.reply[0], args.reply[1], args.json)

    if args.comment:
        reply_to_post(api_key, args.comment[0], args.comment[1], args.json)

    if args.mark_read:
        mark_notifications_read(api_key, args.mark_read, args.json)


if __name__ == "__main__":
    main()
