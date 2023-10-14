require 'openssl'
require 'base64'

def generate_keys
    keypair = OpenSSL::PKey::RSA.generate(1024)
    public_key = keypair.public_key
    private_key = keypair

    return public_key, private_key
end

def write_file(filename, data)
    file = File.open(filename, "w")
    file.write(data)
    file.close
end

def encrypt(message, public_key)
    encrypted_message = public_key.public_encrypt(message)
    return Base64.encode64(encrypted_message).to_s.strip.gsub("\n", " ")
end
  
def decrypt(encrypted_message, private_key)
    decrypted_message = private_key.private_decrypt(Base64.decode64(encrypted_message))
    return decrypted_message
end

def main()
    puts "Choose your options:
        1: Encrypt message
        2: Decrypt message
        3: Generate RSA KEY"
    print "Your options: "
    option = gets.to_i

    if option == 1
        print "Input message: "
        message = gets.to_s
        public_key_string = File.read('public_key.txt')
        puts(public_key_string)
        public_key = OpenSSL::PKey::RSA.new(public_key_string)
        puts "\nEncrypted text: #{encrypt(message, public_key)}"
    elsif option == 2
        print "Input encrypted message: "
        encrypted_message = gets.chomp
        private_key_string = File.read('private_key.txt')
        private_key = OpenSSL::PKey::RSA.new(private_key_string)
        puts "Decrypted text: #{decrypt(encrypted_message, private_key)}"
    elsif option == 3
        print "Generating key ."
        sleep 0.5
        print "."
        sleep 0.5
        print "."
        sleep 0.5
        print "."
        sleep 0.5
        print ".\n"
        public_key, private_key = generate_keys
        puts "Generate key successfully"
        write_file('public_key.txt', public_key)
        write_file('private_key.txt', private_key)
        puts "Public key is: #{public_key}"
        puts "Private key is: #{private_key}"
    else
        puts "Please input correct options."
    end

end

main()


