use chacha20poly1305::aead::{Aead, KeyInit, Payload};                 // Encryption/decryption traits
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};                 // Cipher types
use rand::RngCore;                                                    // For secure random number generation
use sha2::{Digest, Sha512};                                           // SHA-512 hash function
use std::fs;                                                          // File system operations
use std::io::{self, Write, Read};                                     // Standard input/output
use std::path::{Path, PathBuf};                                       // For path types
use std::sync::Arc;                                                   // For sharing cipher between threads
use walkdir::WalkDir;                                                 // For directory traversal
use rayon::prelude::*;                                                // For parallel processing
use rpassword::read_password;                                         // For hidden password entry

/// Prompt user for the directory path to process
fn promptDirectory() -> String {
    print!("Enter the directory to process: ");                        // Print prompt
    io::stdout().flush().unwrap();                                     // Ensure prompt is displayed immediately
    let mut directoryInput = String::new();                            // Create mutable string
    io::stdin().read_line(&mut directoryInput)
        .expect("Failed to read line from user");                      // Get input from user
    let directory = directoryInput.trim().to_string();                 // Remove whitespace and line ending
    directory
}

/// Prompt user for password (input is hidden)
fn promptPassword() -> String {
    print!("Enter password: ");                                        // Prompt for password
    io::stdout().flush().unwrap();                                     // Flush prompt
    read_password().expect("Failed to read password")                  // Read password securely
}

/// Ask user to select encryption or decryption
fn promptEncryptionMode() -> String {
    loop {                                                             // Keep asking until valid
        print!("Type 'encrypt' or 'decrypt' and press Enter: ");       // Mode prompt
        io::stdout().flush().unwrap();
        let mut modeInput = String::new();
        io::stdin().read_line(&mut modeInput).expect("Failed to read line");
        let mode = modeInput.trim().to_lowercase();                    // Convert for case-insensitive check
        if mode == "encrypt" || mode == "decrypt" {
            return mode;                                               // Return the valid mode string
        } else {
            println!("Invalid input. Please type 'encrypt' or 'decrypt'."); // On error, re-prompt
        }
    }
}

/// Derive a 32-byte key from a password using SHA-512
fn deriveEncryptionKeyFromPassword(password: &str) -> Key {
    let sha512Digest = Sha512::digest(password.as_bytes());            // Hash password to 64-byte digest
    let keyBytes = &sha512Digest[..32];                                // Take first 32 bytes as key
    Key::from_slice(keyBytes).clone()                                  // Create Key object
}

/// Encrypt a file and overwrite original file as [nonce][ciphertext]
fn encryptSingleFile(filePath: &Path, cipher: &ChaCha20Poly1305) -> Result<(), String> {
    let fileContent = fs::read(filePath)
        .map_err(|error| format!("Failed to read file: {error}"))?;   // Read file bytes

    let mut randomNonceBytes = [0u8; 12];                             // Create buffer for 12-byte nonce
    rand::thread_rng().fill_bytes(&mut randomNonceBytes);              // Fill with secure random bytes
    let nonce = Nonce::from_slice(&randomNonceBytes);                 // Nonce instance

    let cipherText = cipher
        .encrypt(nonce, Payload { msg: &fileContent, aad: b"" })      // Encrypt the file content
        .map_err(|error| format!("Encryption failed: {error}"))?;

    let mut outputBytes = Vec::with_capacity(12 + cipherText.len());  // Create output buffer
    outputBytes.extend_from_slice(&randomNonceBytes);                 // Prepend the nonce
    outputBytes.extend_from_slice(&cipherText);                       // Append the ciphertext

    fs::write(filePath, outputBytes)
        .map_err(|error| format!("Failed to write encrypted file: {error}")) // Overwrite file
}

/// Decrypt a file (expects [nonce][ciphertext]), overwrites with plaintext
fn decryptSingleFile(filePath: &Path, cipher: &ChaCha20Poly1305) -> Result<(), String> {
    let encryptedFileBytes = fs::read(filePath)
        .map_err(|error| format!("Failed to read file: {error}"))?;   // Read file
    if encryptedFileBytes.len() < 12 {
        return Err("File too small (missing nonce)".to_string());     // Not enough data for nonce
    }

    let (nonceBytes, cipherTextBytes) = encryptedFileBytes.split_at(12); // First 12 bytes: nonce
    let nonce = Nonce::from_slice(nonceBytes);                          // Create Nonce

    let plainTextBytes = cipher
        .decrypt(nonce, Payload { msg: cipherTextBytes, aad: b"" })     // Attempt decryption
        .map_err(|error| 
            format!("Decryption failed (wrong password or file corrupted): {error}"))?;

    fs::write(filePath, plainTextBytes)
        .map_err(|error| format!("Failed to write decrypted file: {error}")) // Overwrite with plaintext
}

/// List all files in directory and subdirectories
fn listAllFilesRecursively(directoryPath: &Path) -> Vec<PathBuf> {
    WalkDir::new(directoryPath)
        .into_iter()
        .filter_map(|entry| entry.ok())                // Filter valid directory entries
        .filter(|entry| entry.file_type().is_file())   // Only process files, not directories
        .map(|entry| entry.path().to_path_buf())       // Convert to PathBuf
        .collect()                                     // Collect all file paths
}

fn main() {
    println!("==== ChaCha20-Poly1305 Directory Encryptor/Decryptor ====");   // Banner

    let targetDirectory = promptDirectory();                                 // Step 1: Ask which directory to process
    let targetDirectoryPath = Path::new(&targetDirectory);                   // Convert to Path object
    if !targetDirectoryPath.is_dir() {
        println!("{} is not a valid directory!", targetDirectory);           // Validation check
        std::process::exit(1);
    }

    let encryptionMode = promptEncryptionMode();                             // Step 2: Ask operation mode
    let userPassword = promptPassword();                                     // Step 3: Ask for password
    let derivedKey = deriveEncryptionKeyFromPassword(&userPassword);         // Step 4: Derive encryption key
    let cipherInstance = Arc::new(ChaCha20Poly1305::new(&derivedKey));       // Step 5: Create shared cipher

    let listOfAllFiles = listAllFilesRecursively(targetDirectoryPath);       // Step 6: Recursively collect all file paths
    if listOfAllFiles.is_empty() {
        println!("No files found in the specified directory.");              // Handle case where dir is empty
        return;
    }
    println!("Found {} files. Begin processing...", listOfAllFiles.len());   // Task progress print

    // Step 7: Process all files in parallel, use Arc to share cipher
    listOfAllFiles.par_iter().for_each(|singleFilePath| {
        let cipherForThread = Arc::clone(&cipherInstance);                   // Each thread gets cipher reference
        let operationResult = match encryptionMode.as_str() {
            "encrypt" => encryptSingleFile(singleFilePath, &cipherForThread),
            "decrypt" => decryptSingleFile(singleFilePath, &cipherForThread),
            _ => unreachable!(),
        };
        match operationResult {
            Ok(()) => println!("[OK]  {}", singleFilePath.display()),        // Print OK on success
            Err(errorMessage) => println!("[ERR] {}  ({})", 
                                          singleFilePath.display(), errorMessage), // Print error details
        }
    });

    println!("All done! Press Enter to exit.");                              // Final message
    let mut exitPause = [0u8];
    let _ = io::stdin().read(&mut exitPause).unwrap();                       // Pause for user input, then exit
}
