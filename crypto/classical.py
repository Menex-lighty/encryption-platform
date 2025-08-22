"""
Classical Encryption Implementations
Educational ciphers: Caesar, Vigenère, ROT13, Atbash, etc.
"""

import string
import logging

logger = logging.getLogger(__name__)

class CaesarCipher:
    """Caesar cipher with configurable shift"""
    
    def __init__(self):
        self.alphabet = string.ascii_lowercase
    
    def encrypt(self, plaintext: str, shift: int = 3) -> str:
        """
        Encrypt text using Caesar cipher
        
        Args:
            plaintext: Text to encrypt
            shift: Number of positions to shift (default: 3)
        
        Returns:
            Encrypted text
        """
        try:
            if not isinstance(plaintext, str):
                raise ValueError("Plaintext must be a string")
            
            # Normalize shift to 0-25 range
            shift = shift % 26
            
            result = ""
            for char in plaintext:
                if char.lower() in self.alphabet:
                    # Find position and shift
                    old_pos = self.alphabet.index(char.lower())
                    new_pos = (old_pos + shift) % 26
                    new_char = self.alphabet[new_pos]
                    
                    # Preserve case
                    if char.isupper():
                        new_char = new_char.upper()
                    
                    result += new_char
                else:
                    # Keep non-alphabetic characters unchanged
                    result += char
            
            logger.info(f"Caesar encryption completed, shift: {shift}")
            return result
            
        except Exception as e:
            logger.error(f"Caesar encryption failed: {str(e)}")
            raise
    
    def decrypt(self, ciphertext: str, shift: int = 3) -> str:
        """Decrypt Caesar cipher by using negative shift"""
        return self.encrypt(ciphertext, -shift)
    
    def brute_force_decrypt(self, ciphertext: str) -> list:
        """Try all possible shifts for brute force attack"""
        results = []
        for shift in range(26):
            decrypted = self.decrypt(ciphertext, shift)
            results.append({
                'shift': shift,
                'text': decrypted
            })
        return results


class VigenereCipher:
    """Vigenère cipher with keyword"""
    
    def __init__(self):
        self.alphabet = string.ascii_lowercase
    
    def encrypt(self, plaintext: str, keyword: str) -> str:
        """
        Encrypt text using Vigenère cipher
        
        Args:
            plaintext: Text to encrypt
            keyword: Encryption keyword
        
        Returns:
            Encrypted text
        """
        try:
            if not isinstance(plaintext, str) or not isinstance(keyword, str):
                raise ValueError("Both plaintext and keyword must be strings")
            
            if not keyword:
                raise ValueError("Keyword cannot be empty")
            
            # Clean keyword (remove non-alphabetic characters)
            keyword = ''.join(c.lower() for c in keyword if c.isalpha())
            
            result = ""
            keyword_index = 0
            
            for char in plaintext:
                if char.lower() in self.alphabet:
                    # Get keyword character for this position
                    key_char = keyword[keyword_index % len(keyword)]
                    key_shift = self.alphabet.index(key_char)
                    
                    # Apply Caesar cipher with keyword shift
                    old_pos = self.alphabet.index(char.lower())
                    new_pos = (old_pos + key_shift) % 26
                    new_char = self.alphabet[new_pos]
                    
                    # Preserve case
                    if char.isupper():
                        new_char = new_char.upper()
                    
                    result += new_char
                    keyword_index += 1
                else:
                    # Keep non-alphabetic characters unchanged
                    result += char
            
            logger.info(f"Vigenère encryption completed, keyword length: {len(keyword)}")
            return result
            
        except Exception as e:
            logger.error(f"Vigenère encryption failed: {str(e)}")
            raise
    
    def decrypt(self, ciphertext: str, keyword: str) -> str:
        """Decrypt Vigenère cipher"""
        try:
            if not isinstance(ciphertext, str) or not isinstance(keyword, str):
                raise ValueError("Both ciphertext and keyword must be strings")
            
            if not keyword:
                raise ValueError("Keyword cannot be empty")
            
            # Clean keyword
            keyword = ''.join(c.lower() for c in keyword if c.isalpha())
            
            result = ""
            keyword_index = 0
            
            for char in ciphertext:
                if char.lower() in self.alphabet:
                    # Get keyword character for this position
                    key_char = keyword[keyword_index % len(keyword)]
                    key_shift = self.alphabet.index(key_char)
                    
                    # Apply reverse Caesar cipher
                    old_pos = self.alphabet.index(char.lower())
                    new_pos = (old_pos - key_shift) % 26
                    new_char = self.alphabet[new_pos]
                    
                    # Preserve case
                    if char.isupper():
                        new_char = new_char.upper()
                    
                    result += new_char
                    keyword_index += 1
                else:
                    # Keep non-alphabetic characters unchanged
                    result += char
            
            logger.info(f"Vigenère decryption completed")
            return result
            
        except Exception as e:
            logger.error(f"Vigenère decryption failed: {str(e)}")
            raise


class ROTCipher:
    """ROT13/ROT47 ciphers"""
    
    def rot13(self, text: str) -> str:
        """ROT13 cipher (letters only)"""
        try:
            result = ""
            for char in text:
                if 'a' <= char <= 'z':
                    result += chr((ord(char) - ord('a') + 13) % 26 + ord('a'))
                elif 'A' <= char <= 'Z':
                    result += chr((ord(char) - ord('A') + 13) % 26 + ord('A'))
                else:
                    result += char
            
            logger.info("ROT13 transformation completed")
            return result
            
        except Exception as e:
            logger.error(f"ROT13 failed: {str(e)}")
            raise
    
    def rot47(self, text: str) -> str:
        """ROT47 cipher (ASCII printable characters)"""
        try:
            result = ""
            for char in text:
                if 33 <= ord(char) <= 126:  # Printable ASCII
                    result += chr(33 + (ord(char) - 33 + 47) % 94)
                else:
                    result += char
            
            logger.info("ROT47 transformation completed")
            return result
            
        except Exception as e:
            logger.error(f"ROT47 failed: {str(e)}")
            raise


class AtbashCipher:
    """Atbash cipher (reverse alphabet substitution)"""
    
    def __init__(self):
        self.alphabet = string.ascii_lowercase
        self.reverse_alphabet = self.alphabet[::-1]
    
    def encrypt(self, plaintext: str) -> str:
        """Encrypt using Atbash cipher"""
        return self.decrypt(plaintext)  # Atbash is its own inverse
    
    def decrypt(self, ciphertext: str) -> str:
        """Decrypt using Atbash cipher"""
        try:
            result = ""
            for char in ciphertext:
                if char.lower() in self.alphabet:
                    old_pos = self.alphabet.index(char.lower())
                    new_char = self.reverse_alphabet[old_pos]
                    
                    # Preserve case
                    if char.isupper():
                        new_char = new_char.upper()
                    
                    result += new_char
                else:
                    result += char
            
            logger.info("Atbash transformation completed")
            return result
            
        except Exception as e:
            logger.error(f"Atbash failed: {str(e)}")
            raise


class PlayfairCipher:
    """Playfair cipher implementation"""
    
    def __init__(self):
        self.alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # No J, use I
    
    def _create_key_square(self, keyword: str) -> list:
        """Create 5x5 key square from keyword"""
        # Remove duplicates and non-letters from keyword
        clean_keyword = ""
        seen = set()
        for char in keyword.upper():
            if char.isalpha() and char not in seen:
                if char == 'J':
                    char = 'I'  # Treat J as I
                clean_keyword += char
                seen.add(char)
        
        # Create key square
        key_square = []
        used_chars = set(clean_keyword)
        
        # Add keyword characters
        for char in clean_keyword:
            key_square.append(char)
        
        # Fill remaining positions with unused alphabet
        for char in self.alphabet:
            if char not in used_chars:
                key_square.append(char)
        
        # Convert to 5x5 matrix
        matrix = []
        for i in range(5):
            matrix.append(key_square[i*5:(i+1)*5])
        
        return matrix
    
    def _find_position(self, matrix: list, char: str) -> tuple:
        """Find position of character in matrix"""
        for row in range(5):
            for col in range(5):
                if matrix[row][col] == char:
                    return row, col
        return None, None
    
    def _prepare_text(self, text: str) -> str:
        """Prepare text for Playfair encryption"""
        # Remove non-letters and convert to uppercase
        clean_text = ''.join(c.upper() for c in text if c.isalpha())
        
        # Replace J with I
        clean_text = clean_text.replace('J', 'I')
        
        # Insert X between double letters and ensure even length
        prepared = ""
        i = 0
        while i < len(clean_text):
            prepared += clean_text[i]
            if i + 1 < len(clean_text) and clean_text[i] == clean_text[i + 1]:
                prepared += 'X'
            elif i + 1 < len(clean_text):
                prepared += clean_text[i + 1]
                i += 1
            i += 1
        
        # Add X if odd length
        if len(prepared) % 2 == 1:
            prepared += 'X'
        
        return prepared
    
    def encrypt(self, plaintext: str, keyword: str) -> str:
        """Encrypt using Playfair cipher"""
        try:
            matrix = self._create_key_square(keyword)
            prepared_text = self._prepare_text(plaintext)
            
            result = ""
            for i in range(0, len(prepared_text), 2):
                char1, char2 = prepared_text[i], prepared_text[i + 1]
                row1, col1 = self._find_position(matrix, char1)
                row2, col2 = self._find_position(matrix, char2)
                
                if row1 == row2:  # Same row
                    result += matrix[row1][(col1 + 1) % 5]
                    result += matrix[row2][(col2 + 1) % 5]
                elif col1 == col2:  # Same column
                    result += matrix[(row1 + 1) % 5][col1]
                    result += matrix[(row2 + 1) % 5][col2]
                else:  # Rectangle
                    result += matrix[row1][col2]
                    result += matrix[row2][col1]
            
            logger.info("Playfair encryption completed")
            return result
            
        except Exception as e:
            logger.error(f"Playfair encryption failed: {str(e)}")
            raise
    
    def decrypt(self, ciphertext: str, keyword: str) -> str:
        """Decrypt using Playfair cipher"""
        try:
            matrix = self._create_key_square(keyword)
            
            result = ""
            for i in range(0, len(ciphertext), 2):
                char1, char2 = ciphertext[i], ciphertext[i + 1]
                row1, col1 = self._find_position(matrix, char1)
                row2, col2 = self._find_position(matrix, char2)
                
                if row1 == row2:  # Same row
                    result += matrix[row1][(col1 - 1) % 5]
                    result += matrix[row2][(col2 - 1) % 5]
                elif col1 == col2:  # Same column
                    result += matrix[(row1 - 1) % 5][col1]
                    result += matrix[(row2 - 1) % 5][col2]
                else:  # Rectangle
                    result += matrix[row1][col2]
                    result += matrix[row2][col1]
            
            logger.info("Playfair decryption completed")
            return result
            
        except Exception as e:
            logger.error(f"Playfair decryption failed: {str(e)}")
            raise


# Utility functions for cryptanalysis
def frequency_analysis(text: str) -> dict:
    """Perform frequency analysis on text"""
    frequencies = {}
    total_letters = 0
    
    for char in text.upper():
        if char.isalpha():
            frequencies[char] = frequencies.get(char, 0) + 1
            total_letters += 1
    
    # Convert to percentages
    percentages = {}
    for char, count in frequencies.items():
        percentages[char] = (count / total_letters) * 100
    
    return {
        'counts': frequencies,
        'percentages': percentages,
        'total_letters': total_letters
    }

def index_of_coincidence(text: str) -> float:
    """Calculate Index of Coincidence for cryptanalysis"""
    clean_text = ''.join(c.upper() for c in text if c.isalpha())
    n = len(clean_text)
    
    if n <= 1:
        return 0.0
    
    frequencies = {}
    for char in clean_text:
        frequencies[char] = frequencies.get(char, 0) + 1
    
    ic = sum(freq * (freq - 1) for freq in frequencies.values()) / (n * (n - 1))
    return ic

def detect_cipher_type(ciphertext: str) -> dict:
    """Basic cipher type detection based on characteristics"""
    ic = index_of_coincidence(ciphertext)
    freq_analysis = frequency_analysis(ciphertext)
    
    analysis = {
        'index_of_coincidence': ic,
        'frequency_analysis': freq_analysis,
        'likely_cipher': 'Unknown'
    }
    
    # Basic detection heuristics
    if ic > 0.06:
        analysis['likely_cipher'] = 'Monoalphabetic (Caesar, Atbash, etc.)'
    elif 0.04 < ic < 0.06:
        analysis['likely_cipher'] = 'Polyalphabetic (Vigenère, etc.)'
    else:
        analysis['likely_cipher'] = 'Random or modern cipher'
    
    return analysis