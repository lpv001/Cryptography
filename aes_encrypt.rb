require 'openssl'
require 'base64'

def encrypt_string(string, key)
  cipher = OpenSSL::Cipher.new('AES-256-CBC')
  cipher.encrypt
  cipher.key = Digest::MD5.hexdigest(key)
  cipher.iv = '1234567890123456'

  encrypted_string = cipher.update(string) + cipher.final

  return Base64.strict_encode64(encrypted_string)
end

key = 'my-secret-key'
string = 'hello_world'

encrypted_string = encrypt_string(string, key)

puts "The encrypted string is: #{encrypted_string}"
