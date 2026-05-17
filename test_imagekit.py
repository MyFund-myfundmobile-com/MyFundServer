#!/usr/bin/env python
import os
import sys
import base64
from PIL import Image
import io
import requests

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Set Django settings module
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "myfundproject.settings")

try:
    import django

    django.setup()
    print("✅ Django setup successful")
except Exception as e:
    print(f"⚠️ Django setup failed: {e}")
    print("Will try direct environment variables...")

# Try to import settings
try:
    from django.conf import settings

    private_key = settings.IMAGEKIT_PRIVATE_KEY
    public_key = settings.IMAGEKIT_PUBLIC_KEY
    url_endpoint = settings.IMAGEKIT_URL_ENDPOINT
    print("✅ Using Django settings")
except Exception as e:
    print(f"⚠️ Could not import Django settings: {e}")
    # Fall back to .env file
    from dotenv import load_dotenv

    load_dotenv()
    private_key = os.getenv("IMAGEKIT_PRIVATE_KEY")
    public_key = os.getenv("IMAGEKIT_PUBLIC_KEY")
    url_endpoint = os.getenv("IMAGEKIT_URL_ENDPOINT")
    print("✅ Using .env file")

from imagekitio import ImageKit
from imagekitio.models.UploadFileRequestOptions import UploadFileRequestOptions


def test_imagekit_upload():
    print("=" * 50)
    print("Testing ImageKit Upload")
    print("=" * 50)

    if not private_key:
        print("❌ IMAGEKIT_PRIVATE_KEY not found")
        return False

    print(f"✅ Private key found (first 10 chars): {private_key[:10]}...")
    print(f"✅ URL Endpoint: {url_endpoint}")

    # Initialize ImageKit
    try:
        imagekit = ImageKit(
            private_key=private_key,
            public_key=public_key,
            url_endpoint=url_endpoint,
        )
        print("✅ ImageKit client initialized")
    except Exception as e:
        print(f"❌ Failed to initialize ImageKit: {e}")
        return False

    # Create a simple test image (1x1 pixel)
    try:
        print("\n📝 Creating test image...")
        # Create a 1x1 pixel image (very small)
        img = Image.new("RGB", (1, 1), color="red")
        img_byte_arr = io.BytesIO()
        img.save(img_byte_arr, format="JPEG")
        file_content = img_byte_arr.getvalue()
        print(f"   Test image size: {len(file_content)} bytes")

        # Encode to base64
        encoded_string = base64.b64encode(file_content).decode("utf-8")
        print(f"   Base64 encoded length: {len(encoded_string)}")
    except Exception as e:
        print(f"❌ Failed to create test image: {e}")
        return False

    # Upload to ImageKit using OBJECT options
    try:
        print("\n📤 Uploading to ImageKit...")

        # Create options as OBJECT (not dict)
        upload_options = UploadFileRequestOptions()
        upload_options.folder = "test_folder"
        upload_options.use_unique_file_name = True
        upload_options.is_private_file = False

        result = imagekit.upload(
            file=encoded_string,
            file_name="test_upload.jpg",
            options=upload_options,
        )

        # Extract URL
        if hasattr(result, "url"):
            url = result.url
        elif isinstance(result, dict):
            url = result.get("url")
        else:
            url = str(result)

        print(f"\n✅ Upload successful!")
        print(f"   URL: {url}")

        # Test if URL is accessible
        print("\n🔍 Testing URL accessibility...")
        response = requests.head(url, timeout=10)
        if response.status_code == 200:
            print(f"✅ URL is accessible (status: {response.status_code})")
            return True
        else:
            print(f"⚠️ URL returned status: {response.status_code}")
            return False

    except Exception as e:
        print(f"❌ Upload failed: {e}")
        import traceback

        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = test_imagekit_upload()
    print("\n" + "=" * 50)
    if success:
        print("✅ ImageKit is working correctly!")
    else:
        print("❌ ImageKit test failed!")
    print("=" * 50)
