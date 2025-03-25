import React, { useState } from 'react';
import { FileText, Image as ImageIcon, Upload, Download, AlertCircle, Shield, Terminal, Lock, Search, Key, Eye, EyeOff, Database, Code, ExternalLink, Info } from 'lucide-react';
import Footer from './Footer';

// Main categories
type CategoryType = 'steganography' | 'osint' | 'encryption';

// Steganography modes
type StegMode = 'text-in-image' | 'image-in-image';

// All tool modes combined
type ToolMode = StegMode | 'osint-image' | 'password-encrypt' | 'file-encrypt';

function App() {
  // Main state
  const [category, setCategory] = useState<CategoryType>('steganography');
  const [mode, setMode] = useState<ToolMode>('text-in-image');
  const [message, setMessage] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [secretFile, setSecretFile] = useState<File | null>(null);
  const [result, setResult] = useState<string>('');
  const [error, setError] = useState<string>('');
  const [loading, setLoading] = useState(false);

  // Password encryption state
  const [showPassword, setShowPassword] = useState(false);
  const [passwordToEncrypt, setPasswordToEncrypt] = useState('');
  const [encryptionMethod, setEncryptionMethod] = useState('bcrypt');
  const [passwordToVerify, setPasswordToVerify] = useState('');
  const [storedHash, setStoredHash] = useState('');
  const [salt, setSalt] = useState('');

  // File encryption state
  const [fileToEncrypt, setFileToEncrypt] = useState<File | null>(null);
  const [fileToDecrypt, setFileToDecrypt] = useState<File | null>(null);
  const [encryptionPassword, setEncryptionPassword] = useState('');
  const [encryptedFileUrl, setEncryptedFileUrl] = useState<string | null>(null);
  const [encryptedFileSalt, setEncryptedFileSalt] = useState<string | null>(null);
  const [decryptedFileData, setDecryptedFileData] = useState<string | null>(null);

  // OSINT state
  const [osintResults, setOsintResults] = useState<any>(null);

  const API_URL = import.meta.env.VITE_API_URL;

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>, isSecret = false, isDecrypt = false) => {
    const selectedFile = e.target.files?.[0];
    if (selectedFile) {
      if (isSecret) {
        setSecretFile(selectedFile);
      } else if (isDecrypt) {
        setFileToDecrypt(selectedFile);
      } else {
        setFile(selectedFile);
        setFileToEncrypt(selectedFile);
      }
      setError('');
    }
  };

  const handleCategoryChange = (newCategory: CategoryType) => {
    setCategory(newCategory);
    // Set default mode for each category
    switch (newCategory) {
      case 'steganography':
        setMode('text-in-image');
        break;
      case 'osint':
        setMode('osint-image');
        break;
      case 'encryption':
        setMode('password-encrypt');
        break;
    }
    // Reset results
    setResult('');
    setOsintResults(null);
    setError('');
    setEncryptedFileUrl(null);
    setEncryptedFileSalt(null);
    setDecryptedFileData(null);
  };

  const handleEncode = async () => {
    setLoading(true);
    setError('');
    setResult('');
    setEncryptedFileUrl(null);
    setEncryptedFileSalt(null);

    const formData = new FormData();

    if (!file && mode !== 'password-encrypt' && mode !== 'file-encrypt') {
      setError('Please select a file');
      setLoading(false);
      return;
    }

    if (mode === 'file-encrypt' && !fileToEncrypt) {
      setError('Please select a file to encrypt');
      setLoading(false);
      return;
    }

    try {
      let endpoint = '';
      switch (mode) {
        case 'text-in-image':
          endpoint = '/steganography/image/encode-text';
          formData.append('image', file!);
          formData.append('message', message);
          break;
        case 'image-in-image':
          endpoint = '/steganography/image/encode-image';
          formData.append('coverImage', file!);
          if (secretFile) formData.append('secretImage', secretFile);
          break;
        case 'osint-image':
          endpoint = '/osint/image-analysis';
          formData.append('image', file!);
          break;
        case 'password-encrypt':
          endpoint = '/password/encrypt';
          // This will be handled separately
          break;
        case 'file-encrypt':
          endpoint = '/encryption/encrypt-file';
          formData.append('file', fileToEncrypt!);
          formData.append('password', encryptionPassword);
          break;
      }

      if (mode === 'password-encrypt') {
        if (!passwordToEncrypt) {
          setError('Please enter a password to encrypt');
          setLoading(false);
          return;
        }

        const response = await fetch(`${API_URL}${endpoint}`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            password: passwordToEncrypt,
            method: encryptionMethod,
            salt: salt || undefined
          })
        });

        if (!response.ok) throw new Error('Encryption failed');

        const data = await response.json();
        if (data.success) {
          setResult(JSON.stringify(data, null, 2));
          if (data.salt) {
            setSalt(data.salt);
          }
          setStoredHash(data.hashed_password);
        } else {
          throw new Error(data.error || 'Encryption failed');
        }
      } else if (mode === 'osint-image') {
        const response = await fetch(`${API_URL}${endpoint}`, {
          method: 'POST',
          body: formData,
        });

        if (!response.ok) throw new Error('OSINT analysis failed');

        const data = await response.json();
        if (data.success) {
          setOsintResults(data.analysis_results);
          setResult(JSON.stringify(data.analysis_results, null, 2));
        } else {
          throw new Error(data.error || 'OSINT analysis failed');
        }
      } else if (mode === 'file-encrypt') {
        const response = await fetch(`${API_URL}${endpoint}`, {
          method: 'POST',
          body: formData,
        });

        if (!response.ok) throw new Error('File encryption failed');

        // For file encryption, check if we received a blob or JSON
        const contentType = response.headers.get('content-type');

        if (contentType && contentType.includes('application/json')) {
          const data = await response.json();
          if (data.success) {
            // Store the salt for later decryption
            setEncryptedFileSalt(data.salt);

            // Create a download URL for the encrypted file
            const byteCharacters = atob(data.encrypted_file);
            const byteNumbers = new Array(byteCharacters.length);
            for (let i = 0; i < byteCharacters.length; i++) {
              byteNumbers[i] = byteCharacters.charCodeAt(i);
            }
            const byteArray = new Uint8Array(byteNumbers);
            const blob = new Blob([byteArray], { type: 'application/octet-stream' });
            const url = URL.createObjectURL(blob);
            setEncryptedFileUrl(url);

            setResult(JSON.stringify({
              success: true,
              message: "File encrypted successfully",
              salt: data.salt,
              original_filename: data.original_filename,
              file_size: data.file_size,
              encrypted_size: data.encrypted_size
            }, null, 2));
          } else {
            throw new Error(data.error || 'File encryption failed');
          }
        } else {
          // Direct file download
          const blob = await response.blob();
          const url = URL.createObjectURL(blob);
          setEncryptedFileUrl(url);
          setResult("File encrypted successfully. Click the download button to save it.");
        }
      } else {
        const response = await fetch(`${API_URL}${endpoint}`, {
          method: 'POST',
          body: formData,
        });

        if (!response.ok) throw new Error('Encoding failed');

        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        setResult(url);
      }
    } catch (err: any) {
      setError(err.message || 'An error occurred during processing');
    } finally {
      setLoading(false);
    }
  };

  const handleDecode = async () => {
    setLoading(true);
    setError('');
    setResult('');
    setDecryptedFileData(null);

    if (!file && mode !== 'password-encrypt' && mode !== 'file-encrypt') {
      setError('Please select a file');
      setLoading(false);
      return;
    }

    try {
      let endpoint = '';
      const formData = new FormData();

      switch (mode) {
        case 'text-in-image':
          endpoint = '/steganography/image/decode-text';
          formData.append('image', file!);
          break;
        case 'image-in-image':
          endpoint = '/steganography/image/decode-image';
          formData.append('image', file!);
          break;
        case 'password-encrypt':
          endpoint = '/password/verify';
          // This will be handled separately
          break;
        case 'file-encrypt':
          endpoint = '/encryption/decrypt-file';

          if (fileToDecrypt) {
            // If we have a file to decrypt, use that
            formData.append('encrypted_file', fileToDecrypt);
            if (encryptedFileSalt) {
              formData.append('salt', encryptedFileSalt);
            }
            formData.append('password', encryptionPassword);
          } else {
            // Otherwise, we need both the salt and encrypted file data
            if (!encryptedFileSalt) {
              setError('Missing salt for decryption');
              setLoading(false);
              return;
            }
            if (!encryptedFileUrl) {
              setError('No encrypted file to decrypt');
              setLoading(false);
              return;
            }

            const response = await fetch(encryptedFileUrl);
            const blob = await response.blob();
            const fileReader = new FileReader();

            const readFileAsBase64 = (blob: Blob): Promise<string> => {
              return new Promise((resolve, reject) => {
                fileReader.onload = () => {
                  const base64 = (fileReader.result as string).split(',')[1];
                  resolve(base64);
                };
                fileReader.onerror = reject;
                fileReader.readAsDataURL(blob);
              });
            };

            const base64Data = await readFileAsBase64(blob);

            // Switch to JSON for this case
            return await fetch(`${API_URL}${endpoint}`, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json'
              },
              body: JSON.stringify({
                encrypted_file: base64Data,
                salt: encryptedFileSalt,
                password: encryptionPassword,
                return_as_download: true
              })
            }).then(async (response) => {
              if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Decryption failed');
              }

              const contentType = response.headers.get('content-type');

              if (contentType && contentType.includes('application/json')) {
                const data = await response.json();
                if (data.success) {
                  setDecryptedFileData(data.decrypted_file);
                  setResult(JSON.stringify({
                    success: true,
                    message: "File decrypted successfully",
                    filename: data.filename,
                    file_size: data.file_size
                  }, null, 2));
                } else {
                  throw new Error(data.error || 'Decryption failed');
                }
              } else {
                // Direct file download
                const blob = await response.blob();
                const url = URL.createObjectURL(blob);
                window.location.href = url;
                setResult("File decrypted successfully and downloaded.");
              }

              setLoading(false);
            }).catch(err => {
              setError(err.message || 'Decryption failed');
              setLoading(false);
            });
          }
          break;
        default:
          setError('This mode does not support decoding');
          setLoading(false);
          return;
      }

      if (mode === 'password-encrypt') {
        if (!passwordToVerify || !storedHash) {
          setError('Please enter both the password to verify and the stored hash');
          setLoading(false);
          return;
        }

        const requestBody: any = {
          password: passwordToVerify,
          stored_hash: storedHash,
          method: encryptionMethod
        };

        if (encryptionMethod === 'sha256' && salt) {
          requestBody.salt = salt;
        }

        const response = await fetch(`${API_URL}${endpoint}`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(requestBody)
        });

        if (!response.ok) throw new Error('Verification failed');

        const data = await response.json();
        if (data.success) {
          setResult(`Password Verification: ${data.is_valid ? 'VALID' : 'INVALID'}`);
        } else {
          throw new Error(data.error || 'Verification failed');
        }
      } else if (mode === 'file-encrypt') {
        // This case is handled above with the separate return
        const response = await fetch(`${API_URL}${endpoint}`, {
          method: 'POST',
          body: formData,
        });

        if (!response.ok) throw new Error('File decryption failed');

        const contentType = response.headers.get('content-type');

        if (contentType && contentType.includes('application/json')) {
          const data = await response.json();
          if (data.success) {
            setDecryptedFileData(data.decrypted_file);
            setResult(JSON.stringify({
              success: true,
              message: "File decrypted successfully",
              filename: data.filename,
              file_size: data.file_size
            }, null, 2));
          } else {
            throw new Error(data.error || 'File decryption failed');
          }
        } else {
          // Direct file download
          const blob = await response.blob();
          const url = URL.createObjectURL(blob);
          window.location.href = url;
          setResult("File decrypted successfully and downloaded.");
        }
      } else {
        const response = await fetch(`${API_URL}${endpoint}`, {
          method: 'POST',
          body: formData,
        });

        if (!response.ok) throw new Error('Decoding failed');

        const data = await response.json();
        setResult(data.message || data.image);
      }
    } catch (err: any) {
      setError(err.message || 'An error occurred during processing');
    } finally {
      setLoading(false);
    }
  };

  // Button/action label based on mode
  const getActionLabel = () => {
    switch (mode) {
      case 'osint-image':
        return 'ANALYZE';
      case 'password-encrypt':
        return 'ENCRYPT';
      case 'file-encrypt':
        return 'ENCRYPT';
      default:
        return 'ENCODE';
    }
  };

  // Second button label based on mode
  const getSecondActionLabel = () => {
    switch (mode) {
      case 'password-encrypt':
        return 'VERIFY';
      case 'file-encrypt':
        return 'DECRYPT';
      default:
        return 'DECODE';
    }
  };

  return (
    <div className="min-h-screen bg-[#0a0f0d] text-green-400 font-mono">
      <div className="container mx-auto px-4 py-8">
        {/* Header */}
        <div className="flex items-center justify-center gap-3 mb-8">
          <Shield className="w-8 h-8 text-red-500" />
          <h1 className="text-4xl font-bold text-center text-green-500 tracking-wider">
            DIGITAL_FORENSICS_SUITE
          </h1>
          <Lock className="w-8 h-8 text-red-500" />
        </div>

        {/* Main Category Selection */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          {[
            { id: 'steganography', icon: Database, label: 'STEGANOGRAPHY', desc: 'Hide & extract secret data' },
            { id: 'osint', icon: Search, label: 'OSINT', desc: 'Extract image intelligence' },
            { id: 'encryption', icon: Key, label: 'ENCRYPTION', desc: 'Secure password management' }
          ].map(({ id, icon: Icon, label, desc }) => (
            <button
              key={id}
              onClick={() => handleCategoryChange(id as CategoryType)}
              className={`cyber-border p-5 rounded-lg flex flex-col items-center justify-center gap-3 transition-all
                ${category === id
                  ? 'bg-green-900/30 text-green-300 shadow-[0_0_20px_rgba(34,197,94,0.4)]'
                  : 'bg-gray-900/70 hover:bg-gray-800/70 text-gray-400 hover:text-green-600'}`}
            >
              <Icon className="w-10 h-10" />
              <div className="flex flex-col items-center">
                <span className="text-xl tracking-wide font-bold">{label}</span>
                <span className="text-xs opacity-70 mt-1">{desc}</span>
              </div>
            </button>
          ))}
        </div>

        {/* Tool Selection - Displays based on selected category */}
        <div className="mb-8">
          <h2 className="text-xl text-red-500 mb-4 border-b border-red-900/50 pb-2">// SELECT_TOOL</h2>

          {/* Steganography Tools */}
          {category === 'steganography' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {[
                { id: 'text-in-image', icon: FileText, label: 'Text in Image', desc: 'Hide text messages in images' },
                { id: 'image-in-image', icon: ImageIcon, label: 'Image in Image', desc: 'Conceal one image inside another' }
              ].map(({ id, icon: Icon, label, desc }) => (
                <button
                  key={id}
                  onClick={() => setMode(id as ToolMode)}
                  className={`cyber-border p-4 rounded-lg flex items-center gap-4 transition-all
                    ${mode === id
                      ? 'bg-green-900/20 text-green-400 shadow-[0_0_15px_rgba(34,197,94,0.3)]'
                      : 'bg-gray-900/50 hover:bg-gray-800/50 text-gray-400 hover:text-green-600'}`}
                >
                  <Icon className="w-8 h-8 flex-shrink-0" />
                  <div className="text-left">
                    <div className="font-bold">{label}</div>
                    <div className="text-xs opacity-70">{desc}</div>
                  </div>
                </button>
              ))}
            </div>
          )}

          {/* OSINT Tools */}
          {category === 'osint' && (
            <div className="grid grid-cols-1 gap-4">
              <button
                onClick={() => setMode('osint-image')}
                className="cyber-border p-4 rounded-lg flex items-center gap-4 bg-green-900/20 text-green-400 shadow-[0_0_15px_rgba(34,197,94,0.3)]"
              >
                <Search className="w-8 h-8 flex-shrink-0" />
                <div className="text-left">
                  <div className="font-bold">Image Metadata Analysis</div>
                  <div className="text-xs opacity-70">Extract EXIF data, GPS coordinates, device info</div>
                </div>
              </button>

              {/* Placeholder for future OSINT tools */}
              <div className="cyber-border p-4 rounded-lg flex items-center gap-4 bg-gray-900/30 text-gray-500 opacity-60 cursor-not-allowed">
                <Code className="w-8 h-8 flex-shrink-0" />
                <div className="text-left">
                  <div className="font-bold">Advanced Network Analysis</div>
                  <div className="text-xs opacity-70">COMING SOON - Network traffic analysis</div>
                </div>
              </div>
            </div>
          )}

          {/* Encryption Tools */}
          {category === 'encryption' && (
            <div className="grid grid-cols-1 gap-4">
              <button
                onClick={() => setMode('password-encrypt')}
                className={`cyber-border p-4 rounded-lg flex items-center gap-4 transition-all
                  ${mode === 'password-encrypt'
                    ? 'bg-green-900/20 text-green-400 shadow-[0_0_15px_rgba(34,197,94,0.3)]'
                    : 'bg-gray-900/50 hover:bg-gray-800/50 text-gray-400 hover:text-green-600'}`}
              >
                <Key className="w-8 h-8 flex-shrink-0" />
                <div className="text-left">
                  <div className="font-bold">Password Encryption</div>
                  <div className="text-xs opacity-70">Secure password hashing with bcrypt and SHA-256</div>
                </div>
              </button>

              {/* File Encryption Tool */}
              <button
                onClick={() => setMode('file-encrypt')}
                className={`cyber-border p-4 rounded-lg flex items-center gap-4 transition-all
                  ${mode === 'file-encrypt'
                    ? 'bg-green-900/20 text-green-400 shadow-[0_0_15px_rgba(34,197,94,0.3)]'
                    : 'bg-gray-900/50 hover:bg-gray-800/50 text-gray-400 hover:text-green-600'}`}
              >
                <Lock className="w-8 h-8 flex-shrink-0" />
                <div className="text-left">
                  <div className="font-bold">File Encryption</div>
                  <div className="text-xs opacity-70">Encrypt files with AES-256</div>
                </div>
              </button>
            </div>
          )}
        </div>

        {/* Tool Interface */}
        <div className="cyber-border bg-gray-900/50 rounded-lg p-6 mb-8">
          <h2 className="text-xl text-red-500 mb-4 border-b border-red-900/50 pb-2">
            // {category.toUpperCase()}_CONSOLE {'>'} {mode.toUpperCase()}
          </h2>

          {mode === 'password-encrypt' ? (
            <>
              {/* Password Encrypt */}
              <div className="mb-6">
                <label className="block text-sm font-medium mb-2 text-green-500"> {'>'} ENCRYPTION_METHOD</label>
                <div className="cyber-border rounded-lg p-px">
                  <select
                    className="w-full px-3 py-2 bg-gray-900/30 rounded-lg focus:outline-none focus:ring-1 focus:ring-green-500 text-green-400"
                    value={encryptionMethod}
                    onChange={(e) => setEncryptionMethod(e.target.value)}
                  >
                    <option value="bcrypt">BCrypt</option>
                    <option value="sha256">SHA-256</option>
                  </select>
                </div>
              </div>

              {/* Password Input */}
              <div className="mb-6">
                <label className="block text-sm font-medium mb-2 text-green-500"> {'>'} PASSWORD_TO_ENCRYPT</label>
                <div className="cyber-border rounded-lg p-px flex">
                  <input
                    type={showPassword ? "text" : "password"}
                    className="w-full px-3 py-2 bg-gray-900/30 rounded-l-lg focus:outline-none focus:ring-1 focus:ring-green-500 text-green-400 placeholder-gray-600"
                    value={passwordToEncrypt}
                    onChange={(e) => setPasswordToEncrypt(e.target.value)}
                    placeholder="ENTER_PASSWORD..."
                  />
                  <button
                    className="px-3 py-2 bg-gray-800/50 rounded-r-lg"
                    onClick={() => setShowPassword(!showPassword)}
                  >
                    {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                  </button>
                </div>
              </div>

              {encryptionMethod === 'sha256' && (
                <div className="mb-6">
                  <label className="block text-sm font-medium mb-2 text-green-500"> {'>'} SALT (Optional, hex format)</label>
                  <div className="cyber-border rounded-lg p-px">
                    <input
                      type="text"
                      className="w-full px-3 py-2 bg-gray-900/30 rounded-lg focus:outline-none focus:ring-1 focus:ring-green-500 text-green-400 placeholder-gray-600"
                      value={salt}
                      onChange={(e) => setSalt(e.target.value)}
                      placeholder="ENTER_HEX_SALT (leave empty for random salt)..."
                    />
                  </div>
                </div>
              )}

              {/* Stored Hash */}
              <div className="mb-6">
                <label className="block text-sm font-medium mb-2 text-green-500"> {'>'} STORED_HASH (For verification)</label>
                <div className="cyber-border rounded-lg p-px">
                  <input
                    type="text"
                    className="w-full px-3 py-2 bg-gray-900/30 rounded-lg focus:outline-none focus:ring-1 focus:ring-green-500 text-green-400 placeholder-gray-600"
                    value={storedHash}
                    onChange={(e) => setStoredHash(e.target.value)}
                    placeholder="PASTE_STORED_HASH_HERE..."
                    readOnly={!!result}
                  />
                </div>
              </div>

              {/* Password to Verify */}
              <div className="mb-6">
                <label className="block text-sm font-medium mb-2 text-green-500"> {'>'} PASSWORD_TO_VERIFY</label>
                <div className="cyber-border rounded-lg p-px flex">
                  <input
                    type={showPassword ? "text" : "password"}
                    className="w-full px-3 py-2 bg-gray-900/30 rounded-lg focus:outline-none focus:ring-1 focus:ring-green-500 text-green-400 placeholder-gray-600"
                    value={passwordToVerify}
                    onChange={(e) => setPasswordToVerify(e.target.value)}
                    placeholder="ENTER_PASSWORD_TO_VERIFY..."
                  />
                  <button
                    className="px-3 py-2 bg-gray-800/50 rounded-r-lg"
                    onClick={() => setShowPassword(!showPassword)}
                  >
                    {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                  </button>
                </div>
              </div>
            </>
          ) : mode === 'file-encrypt' ? (
            <>
              {/* Encryption File Upload Section */}
              <div className="mb-6">
                <label className="block text-sm font-medium mb-2 text-green-500">
                  {'>'} FILE_TO_ENCRYPT
                </label>
                <div className="flex items-center justify-center w-full">
                  <label className="w-full flex flex-col items-center px-4 py-6 cyber-border bg-gray-900/30 rounded-lg cursor-pointer hover:bg-gray-800/30 transition-all">
                    <Upload className="w-8 h-8 mb-2 text-red-500" />
                    <span className="text-sm text-gray-400">UPLOAD_FILE_TO_ENCRYPT.exe</span>
                    <input
                      type="file"
                      className="hidden"
                      onChange={(e) => handleFileChange(e)}
                    />
                  </label>
                </div>
                {fileToEncrypt && <p className="mt-2 text-sm text-green-500">FILE_SELECTED: {fileToEncrypt.name}</p>}
              </div>

              {/* Decryption File Upload Section */}
              <div className="mb-6">
                <label className="block text-sm font-medium mb-2 text-green-500">
                  {'>'} FILE_TO_DECRYPT (Optional)
                </label>
                <div className="flex items-center justify-center w-full">
                  <label className="w-full flex flex-col items-center px-4 py-6 cyber-border bg-gray-900/30 rounded-lg cursor-pointer hover:bg-gray-800/30 transition-all">
                    <Upload className="w-8 h-8 mb-2 text-red-500" />
                    <span className="text-sm text-gray-400">UPLOAD_FILE_TO_DECRYPT.exe</span>
                    <input
                      type="file"
                      className="hidden"
                      onChange={(e) => handleFileChange(e, false, true)}
                    />
                  </label>
                </div>
                {fileToDecrypt && <p className="mt-2 text-sm text-green-500">FILE_SELECTED: {fileToDecrypt.name}</p>}
              </div>

              {/* Salt Input (Optional for manual decryption) */}
              {fileToDecrypt && !encryptedFileSalt && (
                <div className="mb-6">
                  <label className="block text-sm font-medium mb-2 text-green-500"> {'>'} ENCRYPTION_SALT (Required for uploaded file)</label>
                  <div className="cyber-border rounded-lg p-px">
                    <input
                      type="text"
                      className="w-full px-3 py-2 bg-gray-900/30 rounded-lg focus:outline-none focus:ring-1 focus:ring-green-500 text-green-400 placeholder-gray-600"
                      value={encryptedFileSalt || ""}
                      onChange={(e) => setEncryptedFileSalt(e.target.value)}
                      placeholder="ENTER_ENCRYPTION_SALT"
                    />
                  </div>
                </div>
              )}

              {/* Password Input */}
              <div className="mb-6">
                <label className="block text-sm font-medium mb-2 text-green-500"> {'>'} ENCRYPTION_PASSWORD</label>
                <div className="cyber-border rounded-lg p-px flex">
                  <input
                    type={showPassword ? "text" : "password"}
                    className="w-full px-3 py-2 bg-gray-900/30 rounded-l-lg focus:outline-none focus:ring-1 focus:ring-green-500 text-green-400 placeholder-gray-600"
                    value={encryptionPassword}
                    onChange={(e) => setEncryptionPassword(e.target.value)}
                    placeholder="ENTER_PASSWORD..."
                  />
                  <button
                    className="px-3 py-2 bg-gray-800/50 rounded-r-lg"
                    onClick={() => setShowPassword(!showPassword)}
                  >
                    {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                  </button>
                </div>
              </div>
            </>
          ) : (
            <>
              {/* File Upload Section */}
              <div className="mb-6">
                <label className="block text-sm font-medium mb-2 text-green-500">
                  {mode === 'image-in-image' ? '>' + ' COVER_IMAGE' : '>' + ' UPLOAD_FILE'}
                </label>
                <div className="flex items-center justify-center w-full">
                  <label className="w-full flex flex-col items-center px-4 py-6 cyber-border bg-gray-900/30 rounded-lg cursor-pointer hover:bg-gray-800/30 transition-all">
                    <Upload className="w-8 h-8 mb-2 text-red-500" />
                    <span className="text-sm text-gray-400">INITIATE_UPLOAD.exe</span>
                    <input
                      type="file"
                      className="hidden"
                      onChange={(e) => handleFileChange(e)}
                      accept={'image/*'}
                    />
                  </label>
                </div>
                {file && <p className="mt-2 text-sm text-green-500">FILE_SELECTED: {file.name}</p>}
              </div>

              {/* Secret Image Upload */}
              {mode === 'image-in-image' && (
                <div className="mb-6">
                  <label className="block text-sm font-medium mb-2 text-green-500"> {'>'} SECRET_IMAGE</label>
                  <div className="flex items-center justify-center w-full">
                    <label className="w-full flex flex-col items-center px-4 py-6 cyber-border bg-gray-900/30 rounded-lg cursor-pointer hover:bg-gray-800/30 transition-all">
                      <Upload className="w-8 h-8 mb-2 text-red-500" />
                      <span className="text-sm text-gray-400">UPLOAD_SECRET.exe</span>
                      <input
                        type="file"
                        className="hidden"
                        onChange={(e) => handleFileChange(e, true)}
                        accept="image/*"
                      />
                    </label>
                  </div>
                  {secretFile && <p className="mt-2 text-sm text-green-500">SECRET_SELECTED: {secretFile.name}</p>}
                </div>
              )}

              {/* Message Input */}
              {mode === 'text-in-image' && (
                <div className="mb-6">
                  <label className="block text-sm font-medium mb-2 text-green-500"> {'>'} MESSAGE</label>
                  <div className="cyber-border rounded-lg p-px">
                    <textarea
                      className="w-full px-3 py-2 bg-gray-900/30 rounded-lg focus:outline-none focus:ring-1 focus:ring-green-500 text-green-400 placeholder-gray-600"
                      rows={4}
                      value={message}
                      onChange={(e) => setMessage(e.target.value)}
                      placeholder="ENTER_SECRET_MESSAGE..."
                    />
                  </div>
                </div>
              )}
            </>
          )}

          {/* Tool Info Banner */}
          <div className="mb-6 bg-black/30 border border-gray-800 rounded p-3 flex items-start gap-3">
            <Info className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
            <div className="text-xs text-gray-400">
              {mode === 'text-in-image' && "This tool hides text messages within image files using LSB steganography. The changes are invisible to the human eye."}
              {mode === 'image-in-image' && "This tool conceals one image inside another using bit manipulation. The cover image will appear slightly altered."}
              {mode === 'osint-image' && "Extract hidden metadata from images including GPS coordinates, camera details, and other EXIF data. Upload any image to analyze."}
              {mode === 'password-encrypt' && "Securely hash passwords using industry-standard encryption. BCrypt is recommended for most use cases."}
              {mode === 'file-encrypt' && "Encrypt files using AES-256 encryption. Provide a password to encrypt and decrypt files securely. Make sure to save both the encrypted file and the salt for later decryption."}
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex gap-4">
            <button
              onClick={handleEncode}
              disabled={loading}
              className="flex-1 cyber-border bg-green-900/20 hover:bg-green-900/30 text-green-400 px-4 py-2 rounded-lg flex items-center justify-center gap-2 transition-all disabled:opacity-50"
            >
              <Upload className="w-4 h-4" />
              {getActionLabel()}
            </button>
            {mode !== 'osint-image' && (
              <button
                onClick={handleDecode}
                disabled={loading}
                className="flex-1 cyber-border bg-red-900/20 hover:bg-red-900/30 text-red-400 px-4 py-2 rounded-lg flex items-center justify-center gap-2 transition-all disabled:opacity-50"
              >
                <Download className="w-4 h-4" />
                {getSecondActionLabel()}
              </button>
            )}
          </div>
        </div>

        {/* Result Section */}
        {(result || error || osintResults || encryptedFileUrl || decryptedFileData) && (
          <div className="cyber-border bg-gray-900/50 rounded-lg p-6">
            <h2 className="text-xl text-red-500 mb-4 border-b border-red-900/50 pb-2">// OUTPUT_DATA</h2>

            {error ? (
              <div className="flex items-center gap-2 text-red-500">
                <AlertCircle className="w-5 h-5" />
                <span>ERROR: {error}</span>
              </div>
            ) : (
              <div className="text-center">
                {result.startsWith('data:image') ? (
                  <img src={result} alt="Decoded" className="max-w-full h-auto mx-auto rounded-lg cyber-border" />
                ) : result.startsWith('blob:') ? (
                  <a
                    href={result}
                    download="encoded-file"
                    className="inline-flex items-center gap-2 cyber-border bg-green-900/20 hover:bg-green-900/30 text-green-400 px-4 py-2 rounded-lg transition-all"
                  >
                    <Download className="w-4 h-4" />
                    DOWNLOAD_RESULT.exe
                  </a>
                ) : mode === 'osint-image' && osintResults ? (
                  <div className="text-left">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {osintResults.exif_present ? (
                        <>
                          {/* Basic Information */}
                          <div className="cyber-border bg-gray-900/30 p-4 rounded-lg">
                            <h4 className="text-lg text-red-500 mb-2">BASIC_INFO</h4>
                            <p className="mb-1">Format: <span className="text-white">{osintResults.format || 'Unknown'}</span></p>
                            <p className="mb-1">Dimensions: <span className="text-white">{osintResults.dimensions?.width || 'Unknown'} x {osintResults.dimensions?.height || 'Unknown'}</span></p>
                            <p className="mb-1">File Size: <span className="text-white">{(osintResults.file_size_bytes / 1024).toFixed(2)} KB</span></p>
                            <p className="mb-1">Timestamp: <span className="text-white">{osintResults.timestamp || 'Not available'}</span></p>
                          </div>

                          {/* Device Information */}
                          <div className="cyber-border bg-gray-900/30 p-4 rounded-lg">
                            <h4 className="text-lg text-red-500 mb-2">DEVICE_INFO</h4>
                            <p className="mb-1">Make: <span className="text-white">{osintResults.device_info?.make || 'Not available'}</span></p>
                            <p className="mb-1">Model: <span className="text-white">{osintResults.device_info?.model || 'Not available'}</span></p>
                            <p className="mb-1">Software: <span className="text-white">{osintResults.device_info?.software || 'Not available'}</span></p>
                          </div>

                          {/* GPS Information */}
                          {osintResults.gps_present && (
                            <div className="cyber-border bg-gray-900/30 p-4 rounded-lg md:col-span-2">
                              <h4 className="text-lg text-red-500 mb-2">GPS_DATA</h4>
                              <p className="mb-1">Latitude: <span className="text-white">{osintResults.gps_coordinates?.latitude || 'Not available'}</span></p>
                              <p className="mb-1">Longitude: <span className="text-white">{osintResults.gps_coordinates?.longitude || 'Not available'}</span></p>

                              {osintResults.location_data && osintResults.location_data.display_name && (
                                <p className="mb-1">Location: <span className="text-white">{osintResults.location_data.display_name}</span></p>
                              )}

                              {osintResults.gps_coordinates?.latitude && osintResults.gps_coordinates?.longitude && (
                                <a
                                  href={`https://www.google.com/maps?q=${osintResults.gps_coordinates.latitude},${osintResults.gps_coordinates.longitude}`}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="mt-2 inline-flex items-center gap-2 cyber-border bg-blue-900/20 hover:bg-blue-900/30 text-blue-400 px-3 py-1 rounded-lg text-sm transition-all"
                                >
                                  <ExternalLink className="w-3 h-3" />
                                  View on Google Maps
                                </a>
                              )}
                            </div>
                          )}

                          {/* All Metadata */}
                          <div className="cyber-border bg-gray-900/30 p-4 rounded-lg md:col-span-2">
                            <h4 className="text-lg text-red-500 mb-2">ALL_METADATA</h4>
                            <pre className="text-xs text-white overflow-x-auto max-h-60 bg-gray-950 p-2 rounded">
                              {JSON.stringify(osintResults.all_metadata, null, 2)}
                            </pre>
                          </div>
                        </>
                      ) : (
                        <div className="cyber-border bg-gray-900/30 p-4 rounded-lg md:col-span-2">
                          <h4 className="text-lg text-red-500 mb-2">NO_EXIF_DATA</h4>
                          <p>No EXIF metadata found in this image. This could be because:</p>
                          <ul className="list-disc pl-5 mt-2">
                            <li>The image was stripped of metadata</li>
                            <li>The image was created digitally without metadata</li>
                            <li>The image format doesn't support metadata</li>
                          </ul>
                        </div>
                      )}
                    </div>
                  </div>
                ) : mode === 'file-encrypt' ? (
                  <div className="text-left">
                    <pre className="text-green-400 break-words font-mono overflow-x-auto max-h-96 bg-gray-950 p-4 rounded">
                      {result}
                    </pre>

                    <div className="flex flex-wrap gap-4 mt-4">
                      {encryptedFileUrl && (
                        <a
                          href={encryptedFileUrl}
                          download="encrypted_file.enc"
                          className="inline-flex items-center gap-2 cyber-border bg-blue-900/20 hover:bg-blue-900/30 text-blue-400 px-4 py-2 rounded-lg transition-all"
                        >
                          <Download className="w-4 h-4" />
                          DOWNLOAD_ENCRYPTED_FILE.exe
                        </a>
                      )}

                      {decryptedFileData && (
                        <a
                          href={`data:application/octet-stream;base64,${decryptedFileData}`}
                          download="decrypted_file"
                          className="inline-flex items-center gap-2 cyber-border bg-green-900/20 hover:bg-green-900/30 text-green-400 px-4 py-2 rounded-lg transition-all"
                        >
                          <Download className="w-4 h-4" />
                          DOWNLOAD_DECRYPTED_FILE.exe
                        </a>
                      )}
                    </div>

                    {encryptedFileSalt && (
                      <div className="mt-4 p-3 bg-black/40 border border-yellow-800 rounded text-yellow-400 text-sm">
                        <div className="flex items-start gap-2">
                          <AlertCircle className="w-4 h-4 mt-0.5 flex-shrink-0" />
                          <div>
                            <p className="font-bold mb-1">IMPORTANT: SAVE THIS ENCRYPTION SALT</p>
                            <p>You will need this salt to decrypt your file later:</p>
                            <code className="block mt-1 p-2 bg-black/50 rounded overflow-x-auto">{encryptedFileSalt}</code>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                ) : (
                  <pre className="text-green-400 break-words font-mono text-left overflow-x-auto max-h-96 bg-gray-950 p-4 rounded">
                    {result}
                  </pre>
                )}
              </div>
            )}
          </div>
        )}

        {/* Footer Component */}
        <Footer />
      </div>
    </div>
  );
}

export default App;
