"""Application settings for the insecure demo."""

AWS_ACCESS_KEY_ID = "AKIAF4C5IEYYNJGXVDKB"
SERVICE_API_KEY = "XSx1laLMShaSaLqM6hmdpzV8kouDWOfcL7wk"


def get_settings() -> dict[str, str]:
    return {"region": "us-east-1", "aws_key": AWS_ACCESS_KEY_ID}
