import hmac
import hashlib
import logging
import os
import httpx
from litestar import Litestar, Request, Response, post
from litestar.status_codes import (
    HTTP_200_OK,
    HTTP_400_BAD_REQUEST,
    HTTP_401_UNAUTHORIZED,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


APP_ID = os.getenv("APP_ID")
APP_SECRET = os.getenv("APP_SECRET")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET")
GENJIPK_WEBSITE_WEBHOOK_URL = os.getenv("GENJIPK_WEBSITE_WEBHOOK_URL")
GENJIPK_FRAMEWORK_WEBHOOK_URL = os.getenv("GENJIPK_FRAMEWORK_WEBHOOK_URL")

def verify_signature(secret: str, payload: bytes, signature: str) -> bool:
    computed_signature = (
        "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    )
    return hmac.compare_digest(computed_signature, signature)

def split_markdown_message(text, limit=2000):
    sections = text.split("\n\n")  # Split at double newlines for logical sections
    messages = []
    current_message = ""

    for section in sections:
        if len(section) + len(current_message) + 2 <= limit:  # +2 accounts for '\n\n' rejoining
            current_message += section + "\n\n"  # Add section with spacing
        else:
            if current_message:  
                messages.append(current_message.strip())  # Store the current chunk
            if len(section) > limit:  # If a single section is too large, split further
                sub_sections = section.split("\n")  
                temp_message = ""
                for line in sub_sections:
                    if len(line) + len(temp_message) + 1 <= limit:  # +1 for newline
                        temp_message += line + "\n"
                    else:
                        messages.append(temp_message.strip())
                        temp_message = line + "\n"
                if temp_message:
                    messages.append(temp_message.strip())
            else:
                current_message = section + "\n\n"

    if current_message.strip():  # Append any remaining content
        messages.append(current_message.strip())

    return messages


@post("/webhook")
async def handle_webhook(request: Request) -> Response:
    payload = await request.body()
    headers = request.headers

    signature = headers.get("x-hub-signature-256")
    if not signature or not verify_signature(WEBHOOK_SECRET, payload, signature):
        logger.warning("Invalid signature.")
        return Response(
            {"error": "Invalid signature"}, status_code=HTTP_401_UNAUTHORIZED
        )

    event = headers.get("x-github-event")
    if not event:
        logger.warning("Missing X-GitHub-Event header.")
        return Response(
            {"error": "Missing X-GitHub-Event header"}, status_code=HTTP_400_BAD_REQUEST
        )

    payload = await request.json()

    if event == "release" and payload.get("action") == "published":
        data = await request.json()
        release = data.get("release")
        repo = data.get("repository", {}).get("name")
        if not (release or repo):
            return Response(
                {"error": "Missing release or repo"}, status_code=HTTP_400_BAD_REQUEST
            )
        release_name = release.get("name")
        release_body = release.get("body")
        if not (release_name or release_body):
            return Response(
                {"error": "Missing release name or release body"}, status_code=HTTP_400_BAD_REQUEST
            )

        if repo == "genjiparkour_website":
            ping = "<@&1328055776358563990>"
            webhook_url = GENJIPK_WEBSITE_WEBHOOK_URL
        elif repo == "genji-framework":
            ping = "<@&1073292274877878314>"
            webhook_url = GENJIPK_FRAMEWORK_WEBHOOK_URL
        else:
            return Response(
                {"error": "Invalid repo name"}, status_code=HTTP_400_BAD_REQUEST
            )
        messages = split_markdown_message(release_body)
        messages = ["{ping}\n**{release_name}**\n"] + messages
        for message in messages:
            discord_payload = {"content": message}

            async with httpx.AsyncClient() as client:
                response = await client.post(webhook_url, json=discord_payload)
                if response.status_code == 204:
                    logger.info("Successfully posted to Discord.")
                    return Response({"status": "success"}, status_code=HTTP_200_OK)
                else:
                    logger.error("Failed to post to Discord.")
                    return Response(
                        {"error": "Failed to post to Discord"},
                        status_code=HTTP_400_BAD_REQUEST,
                    )

    logger.info("Unhandled event type: %s", event)
    return Response({"status": "ignored"}, status_code=HTTP_200_OK)


# Create Litestar app
app = Litestar(route_handlers=[handle_webhook])

# For debugging locally
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
