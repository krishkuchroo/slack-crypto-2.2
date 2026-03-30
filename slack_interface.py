"""
slack_interface.py -- Slack API transport layer (no crypto).
NYU CS6903/4783 Project 2.2

This module handles ONLY Slack API calls. No cryptography here.
Uses slack_sdk.WebClient with token from SLACK_BOT_TOKEN env variable.
"""

import json
import os
from typing import Optional

from dotenv import load_dotenv
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError


load_dotenv()


def _get_client() -> WebClient:
    """Create a Slack WebClient using the bot token from the environment.

    Returns:
        Configured WebClient instance.

    Raises:
        EnvironmentError: If SLACK_BOT_TOKEN is not set.
    """
    token = os.environ.get("SLACK_BOT_TOKEN")
    if not token:
        raise EnvironmentError(
            "SLACK_BOT_TOKEN not set. Copy .env.example to .env and add your token."
        )
    return WebClient(token=token)


def resolve_channel_id(channel_name: str) -> str:
    """Resolve a channel name to its Slack channel ID.

    Searches public channels the bot has access to.

    Args:
        channel_name: Human-readable channel name (without #).

    Returns:
        Slack channel ID string (e.g. "C0123456789").

    Raises:
        ValueError: If the channel is not found.
        SlackApiError: On Slack API failures.
    """
    client = _get_client()
    cursor = None
    while True:
        response = client.conversations_list(
            types="public_channel",
            limit=200,
            cursor=cursor,
        )
        for ch in response["channels"]:
            if ch["name"] == channel_name:
                return ch["id"]
        cursor = response.get("response_metadata", {}).get("next_cursor")
        if not cursor:
            break
    raise ValueError(
        f"Channel '#{channel_name}' not found. "
        f"Ensure the bot is added to the channel."
    )


def post_message(channel: str, payload: dict) -> None:
    """JSON-serialize a payload and post it to a Slack channel.

    Args:
        channel: Slack channel name (will be resolved to ID).
        payload: Dictionary to serialize as the message body.

    Raises:
        SlackApiError: On Slack API failures.
    """
    client = _get_client()
    channel_id = resolve_channel_id(channel)
    text = json.dumps(payload)
    client.chat_postMessage(channel=channel_id, text=text)


def fetch_messages(
    channel: str, limit: int = 20, oldest: Optional[str] = None
) -> list:
    """Fetch recent messages from a Slack channel and parse JSON payloads.

    Non-JSON system messages are silently skipped.

    Args:
        channel: Slack channel name (will be resolved to ID).
        limit: Maximum number of messages to retrieve.
        oldest: Optional Unix timestamp string; only fetch messages after this.

    Returns:
        List of parsed JSON dicts from channel messages.

    Raises:
        SlackApiError: On Slack API failures.
    """
    client = _get_client()
    channel_id = resolve_channel_id(channel)

    kwargs = {"channel": channel_id, "limit": limit}
    if oldest:
        kwargs["oldest"] = oldest

    response = client.conversations_history(**kwargs)
    messages = []
    for msg in response.get("messages", []):
        text = msg.get("text", "")
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                messages.append(parsed)
        except (json.JSONDecodeError, TypeError):
            continue  # skip non-JSON system messages
    return messages
