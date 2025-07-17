import os
import re
import requests
import replicate
from urllib.parse import urlparse, parse_qs
from fastapi import FastAPI, Query
from fastapi.responses import Response, JSONResponse
from typing import Optional
from math import floor

app = FastAPI()
# CORS configuration

REPLICATE_API_TOKEN = os.getenv("REPLICATE_API_TOKEN", "")
client = replicate.Client(api_token=REPLICATE_API_TOKEN)

def extract_hash_from_url(url):
    """Extract hash parameter from web service URL"""
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    if 'hash' in query_params:
        return query_params['hash'][0]


    path_parts = parsed_url.path.split('/')
    if 'hash' in path_parts:
        hash_index = path_parts.index('hash')
        if hash_index + 1 < len(path_parts):
            return path_parts[hash_index + 1]

    hex_pattern = r'[a-fA-F0-9]{6,64}'
    matches = re.findall(hex_pattern, url)
    if matches:
        return matches[0]

    return None

def hex_to_seed(hex_string):
    """Convert hex string to integer seed"""
    try:
        # Clean hex string
        hex_string = hex_string.replace('0x', '').replace('#', '')

        # Convert hex to int
        seed = int(hex_string, 16)

        # Ensure seed is within 32-bit range
        seed = seed % (2**32)

        return seed

    except ValueError:
        # If conversion fails, use string hash
        seed = abs(hash(hex_string)) % (2**32)
        return seed

def generate_art(seed):
    """Start AI art generation using Replicate"""
    prediction = client.run(
        "black-forest-labs/flux-schnell",
        input={
            "prompt": "portraint of a beautiful anime waifu with long hair, digital art, trending on artstation",
            "seed": seed,
            "num_inference_steps": 4,
            "guidance_scale": 3.5,
            "width": 1024,
            "height": 1024,
            "go_fast": True,
            "lora_scale": 1,
            "megapixels": "1",
            "num_outputs": 1,
            "aspect_ratio": "1:1",
            "output_format": "webp",
            "output_quality": 80,
            "prompt_strength": 0.8
        }
    )

    image_bytes = prediction[0].read()

    print(f"Prediction type: {type(prediction)}")
    print(f"Prediction content: {prediction}")

    if isinstance(prediction, list) and len(prediction) > 0:
        image_data = prediction[0]
    else:
        image_data = prediction

    # Check if it's a file-like object or URL
    if hasattr(image_data, 'read'):
        image_bytes = image_data.read()
        print(f"Read {len(image_bytes)} bytes")
    elif isinstance(image_data, str) and image_data.startswith('http'):
        print(f"Got URL: {image_data}")
        response = requests.get(image_data)
        image_bytes = response.content
        print(f"Downloaded {len(image_bytes)} bytes")
    else:
        print(f"Unexpected format: {type(image_data)}")
        return Response(content="Error: unexpected format", status_code=500)

    return Response(
        content=image_bytes,
        media_type="image/webp",
        headers={
            "Content-Disposition": f"inline; filename=art_{seed}.webp"
        }
    )

@app.get("/")
async def api_generate(hash: Optional[str] = Query(None)):
    """Generate image from URL or hash"""
    final_hash = hex_to_seed(hash or "0x886b9e94128d19c95514b91b2bdbda2adedad860b8933bc6e7e3c90cb2fa784b")
    return generate_art(final_hash)

def main():
    """Test the API"""
    # test_hashes = ["886b9e94128d19c95514b91b2bdbda2adedad860b8933bc6e7e3c90cb2fa784b", "deadbeef", "a1b2c3", "ff00aa11", "123456"]
    hash_value = "886b9e94128d19c95514b91b2bdbda2adedad860b8933bc6e7e3c90cb2fa784b"
    # for hash_value in test_hashes:
    requests.get(f"http://localhost:8000/?hash={hash_value}")

if __name__ == "__main__":
    main()