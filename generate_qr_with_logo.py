import qrcode
from PIL import Image

# --- QR code setup ---
url = "https://myfund-push.web.app/download"

qr = qrcode.QRCode(
    version=1,
    error_correction=qrcode.constants.ERROR_CORRECT_H,  # High correction for logo
    box_size=10,
    border=4,
)
qr.add_data(url)
qr.make(fit=True)

img_qr = qr.make_image(fill_color="#4C28BC", back_color="white").convert('RGB')

# --- Add logo ---
logo_path = "myfund_logo.png"
logo = Image.open(logo_path)

# resize logo
logo_size = 100
logo = logo.resize((logo_size, logo_size))

# calculate position to center it
pos = (
    (img_qr.size[0] - logo_size) // 2,
    (img_qr.size[1] - logo_size) // 2
)

# paste logo
img_qr.paste(logo, pos, mask=logo if logo.mode == "RGBA" else None)

# save final QR
img_qr.save("myfund_qr_logo.png")

print("✅ Done! Saved as myfund_qr_logo.png")

