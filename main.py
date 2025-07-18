import os
import re
import requests
import replicate
from urllib.parse import urlparse, parse_qs
from fastapi import FastAPI, Query
from fastapi.responses import Response
from typing import Optional
from upstash_redis import Redis
import base64

app = FastAPI()

REPLICATE_API_TOKEN = os.getenv("REPLICATE_API_TOKEN", "")
REDIS_URL = os.getenv("REDIS_URL", "")
REDIS_TOKEN = os.getenv("REDIS_TOKEN", "")

client = replicate.Client(api_token=REPLICATE_API_TOKEN)
redis = Redis(url=REDIS_URL, token=REDIS_TOKEN) if REDIS_URL and REDIS_TOKEN else None

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

        hex_string = hex_string.replace('0x', '').replace('#', '')
        seed = int(hex_string, 16)
        seed = seed % (2**32) % 100
        return seed

    except ValueError:
        # If conversion fails, use string hash
        seed = abs(hash(hex_string)) % (2**32) % 100
        return seed

def get_cached_image(seed):
    """Get image from Redis cache"""
    if not redis:
        return None

    try:
        cached_data = redis.get(f"art:{seed}")
        if cached_data:
            print(f"Found cached image for seed {seed}")
            return base64.b64decode(cached_data)
    except Exception as e:
        print(f"Cache error: {e}")

    return None

def cache_image(seed, image_data):
    """Cache image URL and data in Redis"""
    if not redis:
        return

    try:
        # Store image as base64 (expires in 7 days)
        image_b64 = base64.b64encode(image_data).decode('utf-8')
        redis.setex(f"art:{seed}", 604800, image_b64)
        print(f"Cached image for seed {seed}")
    except Exception as e:
        print(f"Cache save error: {e}")


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
            "output_format": "png",
            "output_quality": 80,
            "prompt_strength": 0.8
        }
    )

    image_bytes = prediction[0].read()
    print(f"Generated {len(image_bytes)} bytes")

    # Cache the result
    cache_image(seed, image_bytes)

    return image_bytes

@app.get("/")
async def api_generate(hash: Optional[str] = Query(None)):
    """Generate image from hash with caching"""

    default_hash = "886b9e94128d19c95514b91b2bdbda2adedad860b8933bc6e7e3c90cb2fa784b"
    final_hash_str = hash or default_hash

    print(f"Using hash: {final_hash_str}")

    # Convert to seed (limited to 0-99)
    seed = hex_to_seed(final_hash_str)
    print(f"Converted to seed: {seed} (limited to 0-99)")

    # Try to get from cache first
    cached_image = get_cached_image(seed)
    if cached_image:
        return Response(
            content=cached_image,
            media_type="image/webp",
            headers={"X-Cache": "HIT"}  # for testing/debugging
        )

    # Generate new image
    image_bytes = generate_art(seed)

    return Response(
        content=image_bytes,
        media_type="image/png",
        headers={"X-Cache": "MISS"}  # for testing/debugging
    )

@app.get("/api/generate/{hash_value}")
async def api_generate_path(hash_value: str):
    """Generate image from URL path with caching"""
    return await api_generate(hash=hash_value)

@app.get("/cache/stats")
async def cache_stats():
    """Get cache statistics"""
    if not redis:
        return {"error": "Redis not configured"}

    try:
        # Count cached items
        url_keys = redis.keys("art_url:*")
        data_keys = redis.keys("art_data:*")

        return {
            "cached_urls": len(url_keys) if url_keys else 0,
            "cached_data": len(data_keys) if data_keys else 0,
            "max_seeds": 100
        }
    except Exception as e:
        return {"error": str(e)}



def main():
    """Test the API"""
    # test_hashes = [ "72ea9faf9bc36c7f473b37a608f9b3d66335de3513b5ef52bfd34d8f2d612811","886b9e94128d19c95514b91b2bdbda2adedad860b8933bc6e7e3c90cb2fa784b", "25a2174a1ba5be0637bce0e68101cf1511f109f27a398826630de1e6d0d4e573"]
    hash_value = "886b9e94128d19c95514b91b2bdbda2adedad860b8933bc6e7e3c90cb2fa784b"
    # for hash_value in test_hashes:
    requests.get(f"http://localhost:8000/?hash={hash_value}")
    print(f"Response status: {response.status_code}")
    print(f"Cache status: {response.headers.get('X-Cache', 'UNKNOWN')}")

if __name__ == "__main__":
    main()