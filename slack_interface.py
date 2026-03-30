import json
import os
from typing import Optional

from dotenv import load_dotenv
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError


load_dotenv()


def _get_client() -> WebClient:
    token = os.environ.get("SLACK_BOT_TOKEN")
    if not token:
        raise EnvironmentError(
            "SLACK_BOT_TOKEN not set. Copy .env.example to .env and add your token."
        )
    return WebClient(token=token)


def resolve_channel_id(channel_name: str) -> str:
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
    client = _get_client()
    channel_id = resolve_channel_id(channel)
    text = json.dumps(payload)
    client.chat_postMessage(channel=channel_id, text=text)


def fetch_messages(
    channel: str, limit: int = 20, oldest: Optional[str] = None
) -> list:
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
            continue
    return messages
