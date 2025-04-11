from flask import Flask, request, send_file, jsonify
from flask_cors import CORS
from PIL import Image
import io
import numpy as np
import base64
import logging
import traceback
import tempfile
import os
import hashlib
import bcrypt
import piexif
from PIL.ExifTags import TAGS, GPSTAGS
import re
import requests
from datetime import datetime
import json
import subprocess
from PIL import ExifTags
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os

app = Flask(__name__)
CORS(app)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

NULL_TERMINATOR = '00000000'

def encode_message_in_image(image, message):
    if image.mode != 'RGB':
        image = image.convert('RGB')
    message_length = len(message)
    binary_length = format(message_length, '032b')  # 32-bit binary representation of length
    binary_message = ''.join(format(ord(char), '08b') for char in message)
    binary_data = binary_length + binary_message

    width, height = image.size
    pixels = list(image.getdata())

    if len(binary_data) > len(pixels) * 3:
        raise ValueError(f"Message too large for image. Image can hold {len(pixels) * 3 // 8} bytes, but message is {len(message)} bytes")
    new_pixels = []
    binary_index = 0
    for pixel in pixels:
        r, g, b = pixel

        if binary_index < len(binary_data):
            r = (r & ~1) | int(binary_data[binary_index])
            binary_index += 1

        if binary_index < len(binary_data):
            g = (g & ~1) | int(binary_data[binary_index])
            binary_index += 1

        if binary_index < len(binary_data):
            b = (b & ~1) | int(binary_data[binary_index])
            binary_index += 1

        new_pixels.append((r, g, b))
        if binary_index >= len(binary_data):
            new_pixels.extend(pixels[len(new_pixels):])
            break
    new_image = Image.new(image.mode, (width, height))
    new_image.putdata(new_pixels)
    return new_image

def decode_text_from_image(image):
    if image.mode != 'RGB':
        image = image.convert('RGB')

    pixels = list(image.getdata())

    binary_data = ""
    for pixel in pixels:
        r, g, b = pixel
        binary_data += str(r & 1)
        binary_data += str(g & 1)
        binary_data += str(b & 1)

        if len(binary_data) >= 32:
            binary_length = binary_data[:32]
            try:
                message_length = int(binary_length, 2)
                required_bits = 32 + (message_length * 8)
                if len(binary_data) >= required_bits:
                    break
            except ValueError:
                continue

    try:
        binary_length = binary_data[:32]
        message_length = int(binary_length, 2)

        message_bits = binary_data[32:32 + (message_length * 8)]

        message = ""
        for i in range(0, len(message_bits), 8):
            if i + 8 <= len(message_bits):
                byte = message_bits[i:i+8]
                message += chr(int(byte, 2))

        return message
    except (ValueError, IndexError) as e:
        logger.error(f"Error decoding message: {str(e)}")
        return "No hidden message found or the image format was changed."

def encode_image_in_image(cover_image, secret_image):
    secret_image = secret_image.resize(cover_image.size)

    cover_data = np.array(cover_image)
    secret_data = np.array(secret_image)

    encoded_data = (cover_data & 0xF0) | (secret_data >> 4)

    encoded_image = Image.fromarray(encoded_data)
    return encoded_image

def decode_image_from_image(encoded_image):
    data = np.array(encoded_image)

    decoded_data = (data & 0x0F) << 4

    decoded_image = Image.fromarray(decoded_data)
    return decoded_image

# Password encryption functions
def encrypt_password(password, rounds=12):
    """Encrypts a password using bcrypt with the specified number of rounds."""
    if isinstance(password, str):
        password = password.encode('utf-8')
    salt = bcrypt.gensalt(rounds=rounds)
    hashed = bcrypt.hashpw(password, salt)
    return hashed.decode('utf-8')

def verify_password(stored_hash, provided_password):
    """Verifies a password against a stored hash."""
    if isinstance(provided_password, str):
        provided_password = provided_password.encode('utf-8')
    if isinstance(stored_hash, str):
        stored_hash = stored_hash.encode('utf-8')
    return bcrypt.checkpw(provided_password, stored_hash)

def hash_password_sha256(password, salt=None):
    """Creates a SHA-256 hash of the password with an optional salt."""
    if salt is None:
        salt = os.urandom(32)  # 32 bytes = 256 bits

    if isinstance(password, str):
        password = password.encode('utf-8')
    if isinstance(salt, str):
        salt = salt.encode('utf-8')

    pwdhash = hashlib.pbkdf2_hmac('sha256', password, salt, 100000)
    return salt, pwdhash.hex()

# OSINT Image Analysis Functions
def get_exif_data(image):
    """Extract all EXIF data from an image."""
    exif_data = {}
    try:
        # Method 1: Using PIL's _getexif
        if hasattr(image, '_getexif') and image._getexif() is not None:
            exif = image._getexif()
            if exif:
                for tag, value in exif.items():
                    if tag in TAGS:
                        exif_data[TAGS[tag]] = value
                    else:
                        exif_data[tag] = value

        # Method 2: Using PIL's getexif (newer method)
        else:
            try:
                exif = image.getexif()
                if exif:
                    for tag_id in exif:
                        tag = TAGS.get(tag_id, tag_id)
                        value = exif.get(tag_id)
                        exif_data[tag] = value
            except (AttributeError, TypeError):
                pass

        # Method 3: Using piexif for more robust extraction
        try:
            # Extract binary exif data
            exif_dict = piexif.load(image.info.get('exif', b''))
            for ifd in ("0th", "Exif", "GPS", "1st"):
                for tag in exif_dict.get(ifd, {}):
                    try:
                        tag_name = piexif.TAGS[ifd].get(tag, tag)
                        exif_data[tag_name] = exif_dict[ifd][tag]
                    except:
                        pass
        except (ValueError, piexif.InvalidImageDataError):
            pass

    except Exception as e:
        logger.error(f"Error extracting EXIF data: {str(e)}")
        logger.error(traceback.format_exc())

    return exif_data

def get_gps_info(exif_data):
    """Extract GPS information from EXIF data."""
    gps_info = {}

    # Check for GPS info in different possible formats
    if 'GPSInfo' in exif_data:
        gps_tags = exif_data['GPSInfo']
        type_of_tags = "GPSInfo"
    elif 34853 in exif_data:  # GPSInfo tag number
        gps_tags = exif_data[34853]
        type_of_tags = "34853"
    elif 'GPS' in exif_data:
        gps_tags = exif_data['GPS']
        type_of_tags = "GPS"
    else:
        logger.info("No GPS information found in exif_data")
        return None

    logger.info(f"Found GPS data with type: {type_of_tags}, content: {gps_tags}")

    # Process GPS tags
    if isinstance(gps_tags, dict):
        for key, value in gps_tags.items():
            try:
                if isinstance(key, int):
                    # For numeric keys, try to decode using GPSTAGS
                    decoded = GPSTAGS.get(key, key)
                else:
                    # For string keys, use as is
                    decoded = key
                gps_info[decoded] = value
                logger.info(f"Decoded GPS tag: {key} -> {decoded} = {value}")
            except Exception as e:
                logger.error(f"Error processing GPS tag {key}: {str(e)}")
    elif isinstance(gps_tags, (list, tuple)):
        # Some implementations might return GPS data as a list
        logger.info(f"GPS data is a list/tuple: {gps_tags}")
        # Try to extract any usable information
        if len(gps_tags) >= 2:
            gps_info["Latitude"] = gps_tags[0]
            gps_info["Longitude"] = gps_tags[1]
    else:
        logger.info(f"GPS data is of unexpected type: {type(gps_tags)}")

    # Try to find GPS data in exif_data directly
    for key, value in exif_data.items():
        if isinstance(key, str) and "GPS" in key:
            gps_info[key] = value
            logger.info(f"Found GPS-related data in exif: {key} = {value}")

    return gps_info if gps_info else None

def convert_to_degrees(value):
    """Helper function to convert the GPS coordinates format."""
    try:
        # Handle different GPS value formats
        if isinstance(value, tuple) or isinstance(value, list):
            # Standard format: (degrees, minutes, seconds)
            if len(value) >= 3:
                d = float(value[0]) if value[0] is not None else 0
                m = float(value[1]) if value[1] is not None else 0
                s = float(value[2]) if value[2] is not None else 0
                return d + (m / 60.0) + (s / 3600.0)
            # Simplified format: (degrees, minutes)
            elif len(value) == 2:
                d = float(value[0]) if value[0] is not None else 0
                m = float(value[1]) if value[1] is not None else 0
                return d + (m / 60.0)
            # Single value format
            elif len(value) == 1:
                return float(value[0]) if value[0] is not None else 0
        elif isinstance(value, (int, float)):
            return float(value)
        elif isinstance(value, str):
            # Try to parse string as a float
            return float(value)
        else:
            logger.warning(f"Unexpected GPS value format: {type(value)}, value: {value}")
            return None
    except Exception as e:
        logger.error(f"Error converting GPS value {value}: {str(e)}")
        return None

def get_lat_lon(gps_info):
    """Extract latitude and longitude from GPS info."""
    if not gps_info:
        logger.info("No GPS info provided to get_lat_lon")
        return None, None

    try:
        logger.info(f"Extracting lat/lon from GPS info: {gps_info}")

        # Initialize lat/lon
        lat = None
        lon = None

        # Check for various possible GPS coordinate keys
        # Latitude checks
        latitude_keys = ['GPSLatitude', 'Latitude', 2]
        ref_latitude_keys = ['GPSLatitudeRef', 'LatitudeRef', 1]

        # Longitude checks
        longitude_keys = ['GPSLongitude', 'Longitude', 4]
        ref_longitude_keys = ['GPSLongitudeRef', 'LongitudeRef', 3]

        # Check for latitude
        for key in latitude_keys:
            if key in gps_info:
                lat_value = gps_info[key]
                logger.info(f"Found latitude with key {key}: {lat_value}")
                lat = convert_to_degrees(lat_value)
                if lat is not None:
                    # Check for reference (N/S)
                    for ref_key in ref_latitude_keys:
                        if ref_key in gps_info:
                            ref = gps_info[ref_key]
                            if isinstance(ref, bytes):
                                ref = ref.decode('utf-8', errors='ignore')
                            logger.info(f"Found latitude ref with key {ref_key}: {ref}")
                            if ref in ('S', 's', 'South', 'south'):
                                lat = -lat
                    break

        # Check for longitude
        for key in longitude_keys:
            if key in gps_info:
                lon_value = gps_info[key]
                logger.info(f"Found longitude with key {key}: {lon_value}")
                lon = convert_to_degrees(lon_value)
                if lon is not None:
                    # Check for reference (E/W)
                    for ref_key in ref_longitude_keys:
                        if ref_key in gps_info:
                            ref = gps_info[ref_key]
                            if isinstance(ref, bytes):
                                ref = ref.decode('utf-8', errors='ignore')
                            logger.info(f"Found longitude ref with key {ref_key}: {ref}")
                            if ref in ('W', 'w', 'West', 'west'):
                                lon = -lon
                    break

        logger.info(f"Extracted coordinates: lat={lat}, lon={lon}")
        return lat, lon
    except Exception as e:
        logger.error(f"Error extracting lat/lon: {str(e)}")
        logger.error(traceback.format_exc())
        return None, None

def get_location_from_coordinates(lat, lon):
    """Get location information from coordinates using reverse geocoding API."""
    try:
        if lat is None or lon is None:
            logger.info("Cannot get location: coordinates are None")
            return None

        url = f"https://nominatim.openstreetmap.org/reverse?format=json&lat={lat}&lon={lon}&zoom=18&addressdetails=1"
        headers = {'User-Agent': 'SteganoOSINT/1.0'}
        logger.info(f"Making geocoding request to: {url}")

        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            location_data = response.json()
            logger.info(f"Geocoding successful: {location_data.get('display_name', 'Unknown location')}")
            return location_data
        else:
            logger.error(f"Error with geocoding API: {response.status_code}")
            logger.error(f"Response content: {response.text}")
            return None
    except Exception as e:
        logger.error(f"Error getting location: {str(e)}")
        logger.error(traceback.format_exc())
        return None

def extract_device_info(exif_data):
    """Extract device information from EXIF data."""
    device_info = {}

    # Map of common alternative tag names
    tag_mappings = {
        'make': ['Make', 'CameraMake', 'camera_make', 'manufacturer'],
        'model': ['Model', 'CameraModel', 'camera_model', 'device_model'],
        'software': ['Software', 'ProcessingSoftware', 'editing_software'],
    }

    # Process known EXIF tags
    for category, possible_tags in tag_mappings.items():
        for tag in possible_tags:
            if tag in exif_data:
                value = exif_data[tag]
                # Convert bytes to string if needed
                if isinstance(value, bytes):
                    try:
                        value = value.decode('utf-8', errors='replace')
                    except:
                        value = str(value)
                if isinstance(value, str):
                    device_info[category] = value.strip()
                    break

    return device_info

def try_exiftool_extraction(temp_file_path):
    """Try to extract metadata using exiftool if available."""
    try:
        # Check if exiftool is installed
        result = subprocess.run(['which', 'exiftool'],
                              capture_output=True, text=True)
        if result.returncode != 0:
            logger.info("exiftool not found in system, skipping")
            return None

        # Run exiftool to extract metadata
        result = subprocess.run(['exiftool', '-json', '-a', '-u', '-g1', temp_file_path],
                              capture_output=True, text=True)
        if result.returncode == 0:
            try:
                exiftool_data = json.loads(result.stdout)
                logger.info("Successfully extracted metadata with exiftool")
                return exiftool_data[0] if exiftool_data else None
            except json.JSONDecodeError:
                logger.error("Failed to parse exiftool JSON output")
                return None
        else:
            logger.error(f"exiftool error: {result.stderr}")
            return None
    except Exception as e:
        logger.error(f"Error using exiftool: {str(e)}")
        return None

def analyze_image_metadata(image):
    """Analyze an image for OSINT data."""
    results = {
        'exif_present': False,
        'gps_present': False,
        'timestamp': None,
        'device_info': {},
        'gps_coordinates': {},
        'location_data': {},
        'all_metadata': {}
    }

    # Save image to temporary file for potential exiftool use
    temp_file = None
    try:
        temp_file = tempfile.NamedTemporaryFile(suffix=f".{image.format.lower() if image.format else 'jpg'}", delete=False)
        temp_file_path = temp_file.name
        image.save(temp_file_path)
        temp_file.close()
        logger.info(f"Saved image to temporary file: {temp_file_path}")

        # Try exiftool extraction first if available
        exiftool_data = try_exiftool_extraction(temp_file_path)
        if exiftool_data:
            # Extract data from exiftool results
            results['exif_present'] = True
            results['all_metadata'].update({"ExifTool": exiftool_data})

            # Try to extract GPS data
            if 'GPS' in exiftool_data:
                results['gps_present'] = True
                gps_data = exiftool_data['GPS']
                if 'GPSLatitude' in gps_data and 'GPSLongitude' in gps_data:
                    lat = gps_data.get('GPSLatitude')
                    lon = gps_data.get('GPSLongitude')

                    # Check for N/S and E/W references
                    lat_ref = gps_data.get('GPSLatitudeRef', 'N')
                    lon_ref = gps_data.get('GPSLongitudeRef', 'E')

                    if lat_ref in ('S', 's'):
                        lat = -lat if isinstance(lat, (int, float)) else lat
                    if lon_ref in ('W', 'w'):
                        lon = -lon if isinstance(lon, (int, float)) else lon

                    results['gps_coordinates'] = {
                        'latitude': lat,
                        'longitude': lon
                    }

                    # Get location from coordinates
                    location_data = get_location_from_coordinates(lat, lon)
                    if location_data:
                        results['location_data'] = location_data
    except Exception as e:
        logger.error(f"Error with exiftool extraction: {str(e)}")

    # Extract all EXIF data using PIL
    exif_data = get_exif_data(image)
    if exif_data:
        results['exif_present'] = True
        results['all_metadata'].update({"PIL": {k: str(v) for k, v in exif_data.items()}})

        # Extract timestamps
        timestamp_keys = ['DateTimeOriginal', 'DateTime', 'CreateDate', 'ModifyDate']
        for key in timestamp_keys:
            if key in exif_data:
                value = exif_data[key]
                if isinstance(value, bytes):
                    value = value.decode('utf-8', errors='replace')
                results['timestamp'] = value
                break

        # Extract device information
        results['device_info'] = extract_device_info(exif_data)

        # Extract GPS data
        gps_info = get_gps_info(exif_data)
        if gps_info:
            results['gps_present'] = True
            lat, lon = get_lat_lon(gps_info)
            if lat is not None and lon is not None:
                results['gps_coordinates'] = {
                    'latitude': lat,
                    'longitude': lon
                }

                # Get location information from coordinates
                location_data = get_location_from_coordinates(lat, lon)
                if location_data:
                    results['location_data'] = location_data

    # Image dimensions
    results['dimensions'] = {
        'width': image.width,
        'height': image.height
    }

    # Image format
    results['format'] = image.format

    # Image size
    img_byte_arr = io.BytesIO()
    image.save(img_byte_arr, format=image.format or 'JPEG')
    results['file_size_bytes'] = img_byte_arr.tell()

    # Clean up
    if temp_file and os.path.exists(temp_file_path):
        try:
            os.unlink(temp_file_path)
        except:
            pass

    return results

# File Encryption Functions
def generate_key_from_password(password, salt=None):
    """Generate a Fernet key from a password and optional salt."""
    if salt is None:
        salt = os.urandom(16)

    if isinstance(password, str):
        password = password.encode('utf-8')

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )

    key = base64.urlsafe_b64encode(kdf.derive(password))
    return salt, key

def encrypt_file(file_data, password):
    """
    Encrypt file data with a password.

    Args:
        file_data (bytes): The file data to encrypt
        password (str): The password to use for encryption

    Returns:
        tuple: (salt, encrypted_data)
    """
    salt, key = generate_key_from_password(password)
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(file_data)
    return salt, encrypted_data

def decrypt_file(encrypted_data, password, salt):
    """
    Decrypt file data with a password and salt.

    Args:
        encrypted_data (bytes): The encrypted file data
        password (str): The password used for encryption
        salt (bytes): The salt used in key derivation

    Returns:
        bytes: The decrypted file data
    """
    _, key = generate_key_from_password(password, salt)
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data)
    return decrypted_data

# Routes
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({"status": "ok", "message": "Steganography API is running"}), 200

@app.route('/api/steganography/image/encode-text', methods=['POST'])
def encode_text_in_image_api():
    try:
        if 'image' not in request.files:
            return jsonify({"error": "No image file uploaded"}), 400

        image_file = request.files['image']
        message = request.form.get('message', '')

        if not message:
            return jsonify({"error": "No message provided"}), 400

        # Log the received data for debugging
        logger.info(f"Encoding text in image, message length: {len(message)}")

        image = Image.open(image_file)
        logger.info(f"Image opened: mode={image.mode}, size={image.size}")

        encoded_image = encode_message_in_image(image, message)
        logger.info("Image encoding completed")

        img_io = io.BytesIO()
        encoded_image.save(img_io, format='PNG', optimize=False, compress_level=0)
        img_io.seek(0)
        logger.info("Encoded image saved to buffer")

        return send_file(
            img_io,
            mimetype='image/png',
            as_attachment=True,
            download_name='encoded_image.png'
        )
    except ValueError as e:
        logger.error(f"Value error in encode_text_in_image_api: {str(e)}")
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error(f"Unexpected error in encode_text_in_image_api: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": "An unexpected error occurred"}), 500

@app.route('/api/steganography/image/decode-text', methods=['POST'])
def decode_text_from_image_api():
    try:
        if 'image' not in request.files:
            return jsonify({"error": "No image file uploaded"}), 400

        image_file = request.files['image']
        # Log the received file for debugging
        logger.info(f"Decoding text from image, file name: {image_file.filename}")

        image = Image.open(image_file)
        logger.info(f"Image opened: mode={image.mode}, size={image.size}")

        message = decode_text_from_image(image)
        logger.info(f"Decoded message length: {len(message)}")

        return jsonify({
            "success": True,
            "message": message
        })
    except Exception as e:
        logger.error(f"Error in decode_text_from_image_api: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@app.route('/api/steganography/image/encode-image', methods=['POST'])
def encode_image_in_image_api():
    try:
        if 'coverImage' not in request.files or 'secretImage' not in request.files:
            return jsonify({"error": "Both cover image and secret image must be provided"}), 400

        cover_file = request.files['coverImage']
        secret_file = request.files['secretImage']

        cover_image = Image.open(cover_file)
        secret_image = Image.open(secret_file)

        encoded_image = encode_image_in_image(cover_image, secret_image)

        img_io = io.BytesIO()
        encoded_image.save(img_io, 'PNG')
        img_io.seek(0)

        return send_file(
            img_io,
            mimetype='image/png',
            as_attachment=True,
            download_name='encoded_with_image.png'
        )
    except Exception as e:
        logger.error(f"Error in encode_image_in_image_api: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@app.route('/api/steganography/image/decode-image', methods=['POST'])
def decode_image_from_image_api():
    try:
        if 'image' not in request.files:
            return jsonify({"error": "No image file uploaded"}), 400

        image_file = request.files['image']
        encoded_image = Image.open(image_file)
        decoded_image = decode_image_from_image(encoded_image)

        img_io = io.BytesIO()
        decoded_image.save(img_io, 'PNG')
        img_io.seek(0)

        img_io.seek(0)
        img_base64 = base64.b64encode(img_io.getvalue()).decode()

        return jsonify({
            "success": True,
            "image": f"data:image/png;base64,{img_base64}"
        })
    except Exception as e:
        logger.error(f"Error in decode_image_from_image_api: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@app.route('/api/osint/image-analysis', methods=['POST'])
def analyze_image_for_osint_api():
    try:
        if 'image' not in request.files:
            return jsonify({"error": "No image file uploaded"}), 400

        image_file = request.files['image']
        image = Image.open(image_file)

        # Preserve original format
        image_format = image.format

        # Analyze image metadata
        analysis_results = analyze_image_metadata(image)

        # Log results for debugging
        logger.info(f"OSINT analysis completed with results: exif_present={analysis_results['exif_present']}, gps_present={analysis_results['gps_present']}")
        if analysis_results['gps_present']:
            logger.info(f"GPS coordinates: {analysis_results['gps_coordinates']}")

        return jsonify({
            "success": True,
            "image_format": image_format,
            "analysis_results": analysis_results
        })
    except Exception as e:
        logger.error(f"Error in analyze_image_for_osint_api: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@app.route('/api/password/encrypt', methods=['POST'])
def encrypt_password_api():
    try:
        data = request.get_json()
        if not data or 'password' not in data:
            return jsonify({"error": "No password provided"}), 400

        password = data['password']
        method = data.get('method', 'bcrypt')

        if method == 'bcrypt':
            rounds = data.get('rounds', 12)
            hashed_password = encrypt_password(password, rounds)
            return jsonify({
                "success": True,
                "method": "bcrypt",
                "hashed_password": hashed_password
            })
        elif method == 'sha256':
            salt = data.get('salt', None)
            if salt:
                salt = bytes.fromhex(salt)
            salt, hashed_password = hash_password_sha256(password, salt)
            return jsonify({
                "success": True,
                "method": "sha256",
                "salt": salt.hex(),
                "hashed_password": hashed_password
            })
        else:
            return jsonify({"error": f"Unsupported encryption method: {method}"}), 400
    except Exception as e:
        logger.error(f"Error in encrypt_password_api: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@app.route('/api/password/verify', methods=['POST'])
def verify_password_api():
    try:
        data = request.get_json()
        if not data or 'stored_hash' not in data or 'password' not in data:
            return jsonify({"error": "Both stored hash and password must be provided"}), 400

        stored_hash = data['stored_hash']
        password = data['password']
        method = data.get('method', 'bcrypt')

        if method == 'bcrypt':
            is_valid = verify_password(stored_hash, password)
            return jsonify({
                "success": True,
                "is_valid": is_valid
            })
        elif method == 'sha256':
            salt = data.get('salt')
            if not salt:
                return jsonify({"error": "Salt must be provided for SHA-256 verification"}), 400

            salt = bytes.fromhex(salt)
            _, hashed_password = hash_password_sha256(password, salt)
            is_valid = (hashed_password == stored_hash)

            return jsonify({
                "success": True,
                "is_valid": is_valid
            })
        else:
            return jsonify({"error": f"Unsupported encryption method: {method}"}), 400
    except Exception as e:
        logger.error(f"Error in verify_password_api: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@app.route('/api/encryption/encrypt-file', methods=['POST'])
def encrypt_file_api():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        file = request.files['file']
        password = request.form.get('password')
        return_type = request.form.get('return_type', 'json')  # 'json' or 'file'

        if not password:
            return jsonify({"error": "No password provided"}), 400

        # Read file data
        file_data = file.read()
        original_filename = file.filename

        # Encrypt the file
        salt, encrypted_data = encrypt_file(file_data, password)

        # Check if client wants direct file download or JSON response
        if return_type == 'file':
            # Return as a file download
            encrypted_io = io.BytesIO(encrypted_data)
            encrypted_io.seek(0)

            # Create a downloadable file with the salt embedded in the filename
            # The salt is base64 encoded and added to the filename for future reference
            salt_b64 = base64.urlsafe_b64encode(salt).decode('utf-8')
            download_name = f"encrypted_{original_filename}_{salt_b64}.enc"

            return send_file(
                encrypted_io,
                mimetype='application/octet-stream',
                as_attachment=True,
                download_name=download_name
            )
        else:
            # Return as JSON
            response = {
                "success": True,
                "salt": base64.b64encode(salt).decode('utf-8'),
                "encrypted_file": base64.b64encode(encrypted_data).decode('utf-8'),
                "original_filename": original_filename,
                "file_size": len(file_data),
                "encrypted_size": len(encrypted_data)
            }
            return jsonify(response)

    except Exception as e:
        logger.error(f"Error in encrypt_file_api: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@app.route('/api/encryption/decrypt-file', methods=['POST'])
def decrypt_file_api():
    try:
        # Check if we're receiving a file upload or JSON data
        if request.files and 'encrypted_file' in request.files:
            # File upload method
            encrypted_file = request.files['encrypted_file']
            encrypted_data = encrypted_file.read()

            # Get salt from either form data or try to extract from filename
            salt_str = request.form.get('salt')

            if not salt_str:
                # Try to extract salt from filename (if it's embedded)
                filename = encrypted_file.filename
                if '_' in filename and filename.endswith('.enc'):
                    # Extract the salt from the filename
                    salt_part = filename.split('_')[-1].replace('.enc', '')
                    try:
                        salt_str = salt_part
                    except:
                        return jsonify({"error": "Could not extract salt from filename"}), 400

            if not salt_str:
                return jsonify({"error": "Salt must be provided for decryption"}), 400

            try:
                # Try both urlsafe_b64decode and regular b64decode
                try:
                    salt = base64.urlsafe_b64decode(salt_str)
                except:
                    salt = base64.b64decode(salt_str)
            except:
                return jsonify({"error": "Invalid salt format"}), 400

            password = request.form.get('password')
            if not password:
                return jsonify({"error": "Password must be provided for decryption"}), 400

            return_as_download = request.form.get('return_as_download', 'true').lower() == 'true'

        elif request.is_json:
            # JSON method
            data = request.get_json()

            if not data or 'encrypted_file' not in data or 'salt' not in data or 'password' not in data:
                return jsonify({"error": "Encrypted file, salt, and password must be provided"}), 400

            encrypted_data = base64.b64decode(data['encrypted_file'])
            salt = base64.b64decode(data['salt'])
            password = data['password']
            return_as_download = data.get('return_as_download', False)
            filename = data.get('original_filename', 'decrypted_file')

        else:
            # Form data
            encrypted_file_b64 = request.form.get('encrypted_file')
            if not encrypted_file_b64:
                return jsonify({"error": "Encrypted file must be provided"}), 400

            salt_str = request.form.get('salt')
            if not salt_str:
                return jsonify({"error": "Salt must be provided for decryption"}), 400

            password = request.form.get('password')
            if not password:
                return jsonify({"error": "Password must be provided for decryption"}), 400

            encrypted_data = base64.b64decode(encrypted_file_b64)
            salt = base64.b64decode(salt_str)
            return_as_download = request.form.get('return_as_download', 'false').lower() == 'true'

        filename = request.form.get('original_filename', 'decrypted_file')

        # Decrypt the file
        try:
            decrypted_data = decrypt_file(encrypted_data, password, salt)
        except Exception as e:
            return jsonify({"error": f"Decryption failed: {str(e)}"}), 400

        # Return as downloadable file or as base64 in JSON
        if return_as_download:
            # Return as downloadable file
            file_io = io.BytesIO(decrypted_data)
            file_io.seek(0)

            return send_file(
                file_io,
                mimetype='application/octet-stream',
                as_attachment=True,
                download_name=filename
            )
        else:
            # Return as base64 in JSON
            return jsonify({
                "success": True,
                "decrypted_file": base64.b64encode(decrypted_data).decode('utf-8'),
                "filename": filename,
                "file_size": len(decrypted_data)
            })

    except Exception as e:
        logger.error(f"Error in decrypt_file_api: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@app.route('/api/encryption/download-encrypted-file', methods=['POST'])
def download_encrypted_file_api():
    try:
        if request.is_json:
            data = request.get_json()

            if not data or 'encrypted_file' not in data:
                return jsonify({"error": "Encrypted file data must be provided"}), 400

            encrypted_data = base64.b64decode(data['encrypted_file'])
            filename = data.get('filename', 'encrypted_file.enc')

            # Return as downloadable file
            file_io = io.BytesIO(encrypted_data)
            file_io.seek(0)

            return send_file(
                file_io,
                mimetype='application/octet-stream',
                as_attachment=True,
                download_name=filename
            )
        else:
            encrypted_file_b64 = request.form.get('encrypted_file')
            if not encrypted_file_b64:
                return jsonify({"error": "Encrypted file must be provided"}), 400

            encrypted_data = base64.b64decode(encrypted_file_b64)
            filename = request.form.get('filename', 'encrypted_file.enc')

            # Return as downloadable file
            file_io = io.BytesIO(encrypted_data)
            file_io.seek(0)

            return send_file(
                file_io,
                mimetype='application/octet-stream',
                as_attachment=True,
                download_name=filename
            )

    except Exception as e:
        logger.error(f"Error in download_encrypted_file_api: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run()
