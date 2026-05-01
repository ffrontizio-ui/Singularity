import hashlib
from PIL import Image
import io
import os

def verify_pow(content: str, nonce: str, difficulty: int = 4) -> bool:
    """
    Verify the Proof of Work.
    The challenge is that the SHA-256 hash of the content combined with the nonce
    must start with `difficulty` number of zeros.
    """
    target = '0' * difficulty
    
    # Textarea DOM value normalizes to '\n', but multipart forms can send '\r\n' and add trailing breaks.
    c_lf = content.replace("\r\n", "\n")
    
    variations = [
        content + nonce,
        c_lf + nonce,
        c_lf.rstrip() + nonce,
        content.rstrip() + nonce
    ]
    
    for payload in variations:
        computed_hash = hashlib.sha256(payload.encode('utf-8')).hexdigest()
        
        if computed_hash.startswith(target):
            return True
            
    return False

def strip_exif_and_save(file_bytes: bytes, output_path: str) -> None:
    """
    Strips EXIF data by opening image and rewriting only pixel data.
    """
    with Image.open(io.BytesIO(file_bytes)) as img:
        # Converting ensures we strip non-image data.
        # Handle formats depending on image
        rgb_im = img.convert('RGB')
        rgb_im.save(output_path, format='JPEG', quality=85)

BANNED_WORDS = ['csam', 'cp', 'hitman', 'terrorist', 'bomb', 'murder', 'illegal']

def check_banned_words(content: str) -> bool:
    content_lower = content.lower()
    for word in BANNED_WORDS:
        if word in content_lower:
            return True
    return False

# Initialize NudeNet lazily or globally
try:
    from nudenet import NudeDetector
    detector = NudeDetector()
except Exception:
    detector = None

def is_explicit_image(image_path: str) -> bool:
    """
    Checks the saved image for explicit content using NudeNet.
    Returns True if threshold is crossed.
    """
    if not detector:
        return False # Fallback if model fails to load
    
    try:
        preds = detector.detect(image_path)
        for pred in preds:
            cls = pred.get('class', '')
            score = pred.get('score', 0)
            # Check for high confidence explicit classes
            if 'EXPOSED' in cls and score > 0.6:
                return True
    except Exception:
        pass
    return False
