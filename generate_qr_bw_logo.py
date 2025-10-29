import qrcode
from PIL import Image, ImageOps

url = "https://myfund-push.web.app/download"
logo_path = "myfund_logo.png"

def make_qr(filename, fill, back):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10,
        border=4,
    )
    qr.add_data(url)
    qr.make(fit=True)

    # Create QR image
    img_qr = qr.make_image(fill_color=fill, back_color=back).convert("RGB")

    # Load and convert logo to black & white
    logo = Image.open(logo_path)
    logo = ImageOps.grayscale(logo)   # convert to grayscale
    logo = ImageOps.autocontrast(logo)  # boost contrast
    logo = logo.convert("RGBA")        # ensure transparency works

    # Resize logo (small)
    logo_size = img_qr.size[0] // 6
    logo = logo.resize((logo_size, logo_size))

    # Center position
    pos = ((img_qr.size[0] - logo_size) // 2, (img_qr.size[1] - logo_size) // 2)
    img_qr.paste(logo, pos, mask=logo)

    img_qr.save(filename)
    print(f"✅ Saved {filename}")

# --- Black QR for light backgrounds ---
make_qr("myfund_qr_black_logo_bw.png", fill="black", back="white")

# --- White QR for dark backgrounds ---
make_qr("myfund_qr_white_logo_bw.png", fill="white", back="black")

