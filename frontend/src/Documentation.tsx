import React, { useState, useEffect, useRef } from 'react';
import { BookOpen, ChevronDown, ChevronUp, Lock, Database, Search, FileText, Image as ImageIcon, Key, Shield, MessageCircle, FileQuestion, Code, Terminal, X } from 'lucide-react';
import ReactMarkdown from 'react-markdown';

// Documentation content in markdown format
const documentationContent = {
  overview: `
# DIGITAL FORENSICS SUITE

## Overview

DIGITAL_FORENSICS_SUITE is an advanced toolset designed for cybersecurity professionals, digital investigators, and privacy enthusiasts. This suite combines powerful techniques in steganography, OSINT (Open Source Intelligence), and encryption to provide a comprehensive set of utilities for digital forensics and secure communications.

### Core Features:

- **Steganography**: Hide sensitive information within digital media
- **OSINT**: Extract metadata and intelligence from digital assets
- **Encryption**: Secure data with industry-standard encryption algorithms

### Use Cases:

- Digital investigations and evidence gathering
- Secure communication channels
- Privacy protection
- Metadata analysis and cleansing
- Password management
- Secure file storage

> **SECURITY NOTE**: This tool should be used responsibly and ethically. Always ensure you have proper authorization before analyzing any data or assets.

### Technical Foundation:

The suite is built with a React frontend and Flask backend, leveraging modern cryptographic libraries and image processing techniques to provide robust, secure functionality.
  `,
  steganography_text: `
# STEGANOGRAPHY: TEXT IN IMAGE

## Overview

Text-in-Image steganography is a technique that allows you to hide text messages within digital images. The changes made to the image are imperceptible to the human eye, making this an effective method for covert communications or digital watermarking.

## How It Works

This tool uses the Least Significant Bit (LSB) steganography technique:

1. Each pixel in an image contains RGB (Red, Green, Blue) values from 0-255
2. The tool modifies the least significant bit of each color channel to encode your message
3. These subtle changes are invisible to the naked eye
4. The modified image can be shared normally, while carrying your hidden message

## Usage Instructions

### Encoding Text:

1. Select the **STEGANOGRAPHY** category
2. Choose the **Text in Image** tool
3. Upload your cover image (PNG format recommended)
4. Enter your secret message in the text field
5. Click the **ENCODE** button
6. Download the resulting image, which now contains your hidden message

### Decoding Text:

1. Select the **STEGANOGRAPHY** category
2. Choose the **Text in Image** tool
3. Upload an image that contains a hidden message
4. Click the **DECODE** button
5. View the extracted message in the results section

## Limitations

- The maximum message length depends on the image size (each pixel can store up to 3 bits)
- Using lossy compression (like JPEG) on encoded images may corrupt the hidden message
- For optimal results, use PNG format for both input and output images

## Security Considerations

While steganography conceals the existence of communication, it is not encryption:

- The hidden message is not encrypted unless separately encrypted before hiding
- Advanced steganalysis techniques may detect the presence of hidden data
- For maximum security, combine steganography with proper encryption
  `,
  steganography_image: `
# STEGANOGRAPHY: IMAGE IN IMAGE

## Overview

The Image-in-Image steganography tool allows you to conceal one image inside another. This advanced technique can be used for watermarking, covert communication, or creating puzzles that reveal hidden visual content.

## How It Works

This tool uses a technique that stores the secret image's data in the lower bits of the cover image:

1. The cover (carrier) image and secret image are processed pixel by pixel
2. The higher 4 bits of each channel in the secret image are stored in the lower 4 bits of the cover image
3. The resulting image looks similar to the original cover image, but contains the hidden image
4. When decoded, the hidden image is extracted and reconstructed

## Usage Instructions

### Encoding Image:

1. Select the **STEGANOGRAPHY** category
2. Choose the **Image in Image** tool
3. Upload your cover image (the visible container image)
4. Upload your secret image (the image to be hidden)
5. Click the **ENCODE** button
6. Download the resulting image, which now contains your hidden image

### Decoding Image:

1. Select the **STEGANOGRAPHY** category
2. Choose the **Image in Image** tool
3. Upload an image that contains a hidden image
4. Click the **DECODE** button
5. View the extracted image in the results section

## Limitations

- The quality of the hidden image is reduced due to bit-depth limitations
- The cover image will show some visual artifacts due to bit manipulation
- Both images must have the same dimensions (automatic resizing is applied)
- Using lossy compression (like JPEG) on encoded images will corrupt the hidden image

## Advanced Techniques

- For better quality of the hidden image, consider using grayscale secret images
- Smaller secret images with less detail will produce better results
- Pre-processing images to enhance contrast can improve extraction results
  `,
  osint_image: `
# OSINT: IMAGE METADATA ANALYSIS

## Overview

The Image Metadata Analysis tool extracts hidden information embedded within digital images. Nearly all digital photos and images contain metadata that can reveal details about the device, location, time, and even the software used to create or edit the image.

## Types of Metadata Extracted

- **EXIF Data**: Camera settings, device information, date/time
- **GPS Coordinates**: Location where the image was captured
- **Device Information**: Make, model, and software details
- **Timestamps**: When the image was created or modified
- **Location Data**: Reverse geocoding of GPS coordinates to real-world locations

## Usage Instructions

1. Select the **OSINT** category
2. Choose the **Image Metadata Analysis** tool
3. Upload the image you want to analyze
4. Click the **ANALYZE** button
5. Review the extracted metadata in the results section

## Key Features

- **GPS Visualization**: For images with geolocation data, a direct link to view the location on Google Maps
- **Device Fingerprinting**: Identify the specific device used to capture the image
- **Temporal Analysis**: Determine when the image was created or modified
- **Comprehensive Raw Data**: Access to all available metadata for detailed investigation

## Privacy Implications

Understanding image metadata is crucial for:

- **Privacy Protection**: Identify what personal information may be unintentionally shared in images
- **Source Verification**: Validate the origin and authenticity of digital images
- **Location Analysis**: Determine where images were captured for investigative purposes
- **Digital Forensics**: Extract evidence for investigations or legal proceedings

## Security Considerations

Be aware that images downloaded from the internet or shared on social media may have had their metadata stripped or modified. Always verify metadata findings with additional sources when conducting critical investigations.
  `,
  encryption_password: `
# ENCRYPTION: PASSWORD ENCRYPTION

## Overview

The Password Encryption tool provides a secure way to hash passwords using industry-standard algorithms. Password hashing is a one-way process that transforms cleartext passwords into cryptographic hashes, which are essential for secure password storage and verification.

## Supported Algorithms

### BCrypt
- Adaptive hashing function built specifically for passwords
- Includes automatic salt generation
- Configurable work factor to adjust computational intensity
- Recommended for most use cases

### SHA-256
- Cryptographic hash function producing a 256-bit (32-byte) hash
- Requires manual salt management
- Fast computation (requires additional security measures for passwords)
- Useful for specific compatibility requirements

## Usage Instructions

### Encrypting a Password:

1. Select the **ENCRYPTION** category
2. Choose the **Password Encryption** tool
3. Select your preferred encryption method (BCrypt or SHA-256)
4. Enter the password to encrypt
5. For SHA-256, optionally provide a custom salt (hexadecimal format)
6. Click the **ENCRYPT** button
7. Save the resulting hash and salt (for SHA-256) securely

### Verifying a Password:

1. Enter the password to verify
2. Paste the stored hash from your database
3. For SHA-256, also provide the original salt
4. Click the **VERIFY** button
5. Check the verification result

## Security Best Practices

- Always use BCrypt for new implementations when possible
- Never store plaintext passwords
- Use a unique salt for each password
- For SHA-256, use a salt of at least 16 bytes (128 bits)
- Store the salt alongside the hash (they're not secret)
- Consider increasing the work factor for BCrypt as hardware improves

## Technical Details

- BCrypt implementation uses OpenBSD's Blowfish-based scheme
- SHA-256 implementation uses PBKDF2 with 100,000 iterations
- All cryptographic operations are performed server-side for security
  `,
  encryption_file: `
# ENCRYPTION: FILE ENCRYPTION

## Overview

The File Encryption tool provides a secure method to encrypt and decrypt files using strong cryptographic algorithms. This ensures that sensitive files remain confidential and can only be accessed by those with the correct password.

## Encryption Technology

This tool implements AES-256 (Advanced Encryption Standard) in GCM mode with the following security features:

- **AES-256**: Military-grade symmetric encryption algorithm
- **Password-Based Key Derivation**: Using PBKDF2-HMAC-SHA256
- **Unique Salt**: Each encryption operation uses a random salt
- **Authentication**: Ensures the encrypted data hasn't been tampered with

## Usage Instructions

### Encrypting a File:

1. Select the **ENCRYPTION** category
2. Choose the **File Encryption** tool
3. Upload the file you want to encrypt
4. Enter a strong password (mix of letters, numbers, and symbols)
5. Click the **ENCRYPT** button
6. Download the encrypted file
7. **IMPORTANT**: Save the displayed encryption salt - you will need this for decryption

### Decrypting a File:

1. Select the **ENCRYPTION** category
2. Choose the **File Encryption** tool
3. Upload the encrypted file
4. Enter the original encryption password
5. Enter the salt that was provided during encryption
6. Click the **DECRYPT** button
7. Download the decrypted file

## Security Considerations

- **Password Strength**: The security of your encrypted file depends entirely on the strength of your password
- **Salt Management**: The salt must be stored securely but separately from the encrypted file
- **Key Security**: Never share your encryption password through insecure channels
- **Data Integrity**: If the encrypted file is modified, decryption will fail

## Technical Details

- Key derivation uses PBKDF2 with 100,000 iterations
- AES-256 implementation uses the Fernet specification
- Each file is encrypted with a unique key derived from your password
- The encryption process automatically handles file of any type or size
  `,
  technical: `
# TECHNICAL DETAILS & SECURITY CONSIDERATIONS

## Architecture Overview

The DIGITAL_FORENSICS_SUITE employs a modern client-server architecture:

- **Frontend**: React-based application with responsive UI
- **Backend**: Flask API server with specialized processing modules
- **Security**: End-to-end encryption for sensitive operations

## Steganography Implementation

### Text-in-Image
- Uses Least Significant Bit (LSB) manipulation
- Employs a length-prefixed encoding scheme
- Operates on the RGB channels of PNG images
- Theoretical capacity: 3 bits per pixel

### Image-in-Image
- Uses 4-bit plane manipulation technique
- Automatically resizes images to match dimensions
- Best suited for PNG format to prevent data loss

## OSINT Capabilities

- EXIF extraction using multiple methods for resilience
- GPS coordinate parsing with format detection
- Reverse geocoding integration via OpenStreetMap
- Device fingerprinting through metadata analysis

## Cryptographic Foundations

- Password hashing: BCrypt and PBKDF2-SHA256
- File encryption: AES-256 with Fernet implementation
- Key derivation: PBKDF2 with 100,000 iterations
- Secure random number generation for all cryptographic operations

## Data Privacy

- All processing occurs on your local system
- No data is sent to external servers beyond the local API
- No logging of sensitive information
- Session-only data storage with no persistence

## Limitations & Considerations

- Steganography is not equivalent to encryption; it merely hides data
- Image metadata extraction depends on the presence of EXIF data
- Password security is dependent on the user's password selection
- File encryption security relies on proper salt management

## Development & Extension

The DIGITAL_FORENSICS_SUITE is designed with modularity in mind:

- Backend API endpoints follow RESTful design patterns
- New tools can be added by implementing additional endpoints
- Frontend components are isolated for easy extension
- Documentation is provided for all API endpoints and functions
  `,
};

// Modal component that can be triggered from the footer
const Documentation = () => {
  const [isOpen, setIsOpen] = useState(false);
  const [activePage, setActivePage] = useState<keyof typeof documentationContent>('overview');
  const modalRef = useRef<HTMLDivElement>(null);

  // Close modal when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (modalRef.current && !modalRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };

    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [isOpen]);

  // Prevent scrolling on body when modal is open
  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = 'auto';
    }

    return () => {
      document.body.style.overflow = 'auto';
    };
  }, [isOpen]);

  return (
    <>
      {/* Documentation Button in Footer */}
      <button
        onClick={() => setIsOpen(true)}
        className="inline-flex items-center gap-2 cyber-border bg-green-900/20 hover:bg-green-900/30 text-green-400 px-3 py-1.5 rounded-lg transition-all"
      >
        <BookOpen className="w-4 h-4" />
        <span>DOCUMENTATION</span>
      </button>

      {/* Modal Overlay */}
      {isOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm">
          {/* Modal Content */}
          <div
            ref={modalRef}
            className="relative w-11/12 max-w-7xl h-5/6 bg-[#0a0f0d] cyber-border rounded-lg overflow-hidden p-1"
          >
            {/* Modal Header */}
            <div className="h-14 bg-gray-900/70 rounded-t-lg flex items-center justify-between px-6">
              <div className="flex items-center gap-3">
                <BookOpen className="w-5 h-5 text-green-500" />
                <h2 className="text-xl text-green-500 font-bold">DIGITAL_FORENSICS_SUITE :: DOCUMENTATION</h2>
              </div>
              <button
                onClick={() => setIsOpen(false)}
                className="text-gray-400 hover:text-red-500 transition-colors"
              >
                <X className="w-6 h-6" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-6 grid grid-cols-1 md:grid-cols-4 gap-6 h-[calc(100%-3.5rem)] overflow-hidden">
              {/* Documentation Navigation */}
              <div className="col-span-1 overflow-y-auto pr-2 border-r border-gray-800">
                <nav className="space-y-1">
                  <button
                    onClick={() => setActivePage('overview')}
                    className={`w-full text-left p-3 flex items-center gap-2 rounded-lg transition-all ${activePage === 'overview' ? 'bg-green-900/30 text-green-400' : 'text-gray-400 hover:bg-gray-900 hover:text-green-400'}`}
                  >
                    <Terminal className="w-4 h-4 flex-shrink-0" />
                    <span>Overview</span>
                  </button>

                  <div className="pl-2">
                    <h3 className="text-xs text-red-500 uppercase mt-4 mb-2 font-bold">Steganography</h3>

                    <button
                      onClick={() => setActivePage('steganography_text')}
                      className={`w-full text-left p-3 flex items-center gap-2 rounded-lg transition-all ${activePage === 'steganography_text' ? 'bg-green-900/30 text-green-400' : 'text-gray-400 hover:bg-gray-900 hover:text-green-400'}`}
                    >
                      <FileText className="w-4 h-4 flex-shrink-0" />
                      <span>Text in Image</span>
                    </button>

                    <button
                      onClick={() => setActivePage('steganography_image')}
                      className={`w-full text-left p-3 flex items-center gap-2 rounded-lg transition-all ${activePage === 'steganography_image' ? 'bg-green-900/30 text-green-400' : 'text-gray-400 hover:bg-gray-900 hover:text-green-400'}`}
                    >
                      <ImageIcon className="w-4 h-4 flex-shrink-0" />
                      <span>Image in Image</span>
                    </button>
                  </div>

                  <div className="pl-2">
                    <h3 className="text-xs text-red-500 uppercase mt-4 mb-2 font-bold">OSINT</h3>

                    <button
                      onClick={() => setActivePage('osint_image')}
                      className={`w-full text-left p-3 flex items-center gap-2 rounded-lg transition-all ${activePage === 'osint_image' ? 'bg-green-900/30 text-green-400' : 'text-gray-400 hover:bg-gray-900 hover:text-green-400'}`}
                    >
                      <Search className="w-4 h-4 flex-shrink-0" />
                      <span>Image Metadata Analysis</span>
                    </button>
                  </div>

                  <div className="pl-2">
                    <h3 className="text-xs text-red-500 uppercase mt-4 mb-2 font-bold">Encryption</h3>

                    <button
                      onClick={() => setActivePage('encryption_password')}
                      className={`w-full text-left p-3 flex items-center gap-2 rounded-lg transition-all ${activePage === 'encryption_password' ? 'bg-green-900/30 text-green-400' : 'text-gray-400 hover:bg-gray-900 hover:text-green-400'}`}
                    >
                      <Key className="w-4 h-4 flex-shrink-0" />
                      <span>Password Encryption</span>
                    </button>

                    <button
                      onClick={() => setActivePage('encryption_file')}
                      className={`w-full text-left p-3 flex items-center gap-2 rounded-lg transition-all ${activePage === 'encryption_file' ? 'bg-green-900/30 text-green-400' : 'text-gray-400 hover:bg-gray-900 hover:text-green-400'}`}
                    >
                      <Lock className="w-4 h-4 flex-shrink-0" />
                      <span>File Encryption</span>
                    </button>
                  </div>

                  <button
                    onClick={() => setActivePage('technical')}
                    className={`w-full text-left p-3 flex items-center gap-2 rounded-lg transition-all ${activePage === 'technical' ? 'bg-green-900/30 text-green-400' : 'text-gray-400 hover:bg-gray-900 hover:text-green-400'}`}
                  >
                    <Code className="w-4 h-4 flex-shrink-0" />
                    <span>Technical Details</span>
                  </button>
                </nav>
              </div>

              {/* Documentation Content */}
              <div className="col-span-1 md:col-span-3 bg-black/40 rounded-lg overflow-auto">
                <div className="documentation-content text-green-300 p-6">
                  <ReactMarkdown
                    components={{
                      h1: ({node, ...props}) => <h1 className="text-3xl font-bold mb-6 text-red-500 border-b border-red-900/50 pb-2" {...props} />,
                      h2: ({node, ...props}) => <h2 className="text-2xl font-bold mt-8 mb-4 text-green-500" {...props} />,
                      h3: ({node, ...props}) => <h3 className="text-xl font-bold mt-6 mb-3 text-green-400" {...props} />,
                      p: ({node, ...props}) => <p className="mb-4 text-green-300" {...props} />,
                      ul: ({node, ...props}) => <ul className="list-disc pl-6 mb-4" {...props} />,
                      ol: ({node, ...props}) => <ol className="list-decimal pl-6 mb-4" {...props} />,
                      li: ({node, ...props}) => <li className="mb-1" {...props} />,
                      code: ({node, ...props}) => <code className="bg-black/50 px-1 rounded text-green-400" {...props} />,
                      blockquote: ({node, ...props}) => <blockquote className="border-l-4 border-red-500 pl-4 py-1 mb-4 text-gray-400 italic" {...props} />,
                      strong: ({node, ...props}) => <strong className="text-green-400 font-bold" {...props} />,
                      em: ({node, ...props}) => <em className="text-green-200 italic" {...props} />,
                    }}
                  >
                    {documentationContent[activePage]}
                  </ReactMarkdown>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  );
};

export default Documentation;
