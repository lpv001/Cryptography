require 'openssl'
require 'base64'

def encrypt_message(message, key)
    cipher = OpenSSL::Cipher.new('AES-256-CBC')
    cipher.encrypt
    cipher.key = Digest::MD5.hexdigest(key)
    cipher.iv = '1234567890123456'

    encrypted_message = cipher.update(message) + cipher.final
    return Base64.strict_encode64(encrypted_message)
end

def decrypt_message(encrypted_message, key)
    begin
        # code that may raise an exception
        encrypted_message = Base64.strict_decode64(encrypted_message)
        cipher = OpenSSL::Cipher.new('AES-256-CBC')
        cipher.decrypt
        cipher.key = Digest::MD5.hexdigest(key)
        cipher.iv = '1234567890123456'

        decrypted_message = cipher.update(encrypted_message) + cipher.final
        return decrypted_message
    rescue
        # code to handle the exception
        return "something went wrong!"
    end
end

def main()
	puts "Choose your options:
        1: Encrypt message
        2: Decrypt message"
    print "Your options: "
    option = gets.to_i

    if option == 1
        print "Input secret key: "
        secret_key = gets.to_s
        print "Input message: "
        message = gets.to_s
        puts "\nEncrypted text: #{encrypt_message(message, secret_key)}"
    elsif option == 2
        print "Input secret key: "
        secret_key = gets.to_s
        print "Input encrypted message: "
        message = gets.chomp
        puts "Decrypted text: #{decrypt_message(message, secret_key)}"
    else
        puts "Please input correct options."
    end
end

main()
