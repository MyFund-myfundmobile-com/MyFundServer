import os
import requests
from dotenv import load_dotenv

load_dotenv()


def test_connection():
    print("\n=== Testing ImageKit Connection ===")
    try:
        response = requests.get(
            "https://api.imagekit.io/v1/files",
            auth=(os.getenv("IMAGEKIT_PRIVATE_KEY"), ""),
            timeout=10,
        )
        if response.status_code == 200:
            print("✅ Connection successful!")
            return True
        print(f"❌ Connection failed (HTTP {response.status_code}): {response.text}")
        return False
    except Exception as e:
        print(f"❌ Connection error: {str(e)}")
        return False


def test_upload():
    print("\n=== Testing File Upload ===")
    try:
        test_file = os.path.join(os.path.dirname(__file__), "test.png")
        if not os.path.exists(test_file):
            print("❌ Test file 'test.png' not found in project root")
            return False

        with open(test_file, "rb") as f:
            response = requests.post(
                "https://upload.imagekit.io/api/v1/files/upload",
                auth=(os.getenv("IMAGEKIT_PRIVATE_KEY"), ""),
                files={"file": ("test.png", f)},
                data={"fileName": "test_upload.png", "folder": "/profile_pictures/"},
                timeout=30,
            )

        if response.status_code == 200:
            print(f"✅ Upload successful!\nURL: {response.json().get('url')}")
            return True
        print(f"❌ Upload failed (HTTP {response.status_code}): {response.text}")
        return False
    except Exception as e:
        print(f"❌ Upload error: {str(e)}")
        return False


if __name__ == "__main__":
    if test_connection():
        test_upload()
