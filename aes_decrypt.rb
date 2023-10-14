require 'openssl'
require 'base64'

def decrypt_string(encrypted_string, key)
    encrypted_string = Base64.strict_decode64(encrypted_string)
  
    cipher = OpenSSL::Cipher.new('AES-256-CBC')
    cipher.decrypt
    cipher.key = Digest::MD5.hexdigest(key)
    cipher.iv = '1234567890123456'
  
    decrypted_string = cipher.update(encrypted_string) + cipher.final
  
    return decrypted_string
end

key = 'my-secret-key'
encrypted_string = "+hf4+u7OyShUqhVQBPuuoQ=="

decrypted_string = decrypt_string(encrypted_string, key)

puts "The decrypted string is: #{decrypted_string}"