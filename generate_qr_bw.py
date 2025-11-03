import qrcode
from PIL import Image

url = "https://myfund-push.web.app/download"

def make_qr(filename, fill, back):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10,
        border=4,
    )
    qr.add_data(url)
    qr.make(fit=True)

    img = qr.make_image(fill_color=fill, back_color=back).convert('RGB')
    img.save(filename)
    print(f"✅ Saved {filename}")

# --- Standard black on white ---
make_qr("myfund_qr_black.png", fill="black", back="white")

# --- Inverted (white on black) for dark backgrounds ---
make_qr("myfund_qr_white.png", fill="white", back="black")

