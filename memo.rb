require 'base64'
require 'securerandom'
require 'openssl'
require 'diff-lcs' # requires gem 'diff-lcs'
require 'io/console'
module Memo
  class Cipher
    def initialize(password, salt)
      key_iv = OpenSSL::PKCS5.pbkdf2_hmac_sha1 password, salt, 1024, 32 + 16
      @key = key_iv[0...-16]
      @iv = key_iv[-16..-1]
    end

    def encrypt(data)
      enc = OpenSSL::Cipher.new('AES-256-CBC').encrypt
      enc.key = @key
      enc.iv = @iv
      enc.update(data) + enc.final
    end

    def decrypt(data)
      dec = OpenSSL::Cipher.new('AES-256-CBC').decrypt
      dec.key = @key
      dec.iv = @iv
      dec.update(data) + dec.final
    end

    def decrypt_line(line)
      decrypted = decrypt Base64.strict_decode64(line)
      decrypted[8..-1].force_encoding 'utf-8'
    end

    def encrypt_line(line)
      encrypted = encrypt SecureRandom.random_bytes(8) + line.force_encoding('ascii-8bit')
      Base64.strict_encode64 encrypted
    end
  end

  module Command
    singleton_class.attr_accessor :password, :encrypted_dir, :data_dir

    def self.each_file_pair
      data_files = Dir.glob("#{data_dir}/*").map do |path|
        path[data_dir.size + 1..-1]
      end
      enc_files = Dir.glob("#{encrypted_dir}/*.enc").map do |path|
        path[encrypted_dir.size + 1..-5]
      end
      (data_files + enc_files).uniq.each do |path|
        yield "#{encrypted_dir}/#{path}.enc", "#{data_dir}/#{path}"
      end
    end

    def self.encrypt_file(file, dict = {})
      salt = dict && dict[:salt] ? dict[:salt] : SecureRandom.random_bytes(32)
      cipher = Cipher.new password, salt
      lines = File.read(file).lines
      encrypted_lines = lines.map do |line|
        dict[line]&.shift || cipher.encrypt_line(line)
      end
      digest = Digest::SHA256.base64digest salt + encrypted_lines.join
      digest + "\n" + Base64.strict_encode64(salt) + "\n" + encrypted_lines.join("\n")
    end

    def self.decrypt_file(file, dict = nil)
      lines = File.read(file).lines.map(&:chomp)
      return '' if lines.empty?
      salt = Base64.strict_decode64 lines[1]
      cipher = Cipher.new password, salt
      dict[:salt] = salt if dict
      digest = Digest::SHA256.base64digest salt + lines.drop(2).join
      raise 'digest malformed' unless lines.first == digest
      decrypted_lines = lines.drop(2).map do |line|
        decrypted = cipher.decrypt_line line
        (dict[decrypted] ||= []) << line if dict
        decrypted
      end
      decrypted_lines.join
    end

    def self.diff(detail: true)
      each_file_pair do |enc_file, file|
        data_was = File.exist?(enc_file) ? decrypt_file(enc_file) : ''
        data = File.exist?(file) ? File.read(file) : ''
        lines_was = data_was.lines.map(&:chomp)
        lines = data.lines.map(&:chomp)
        diff = Diff::LCS.diff(lines_was, lines).flatten
        next if diff.empty?
        adds = diff.count(&:adding?)
        dels = diff.count(&:deleting?)
        puts "\e[1m#{file}\e[m \e[32m+#{adds}\e[m \e[31m-#{dels}\e[m"
        next unless detail
        diff.each do |change|
          code = change.adding? ? 32 : 31
          puts "\e[#{code}m#{change.action}[#{change.position + 1}] #{change.element}\e[m"
        end
        puts
      end
    end

    def self.checkout
      each_file_pair do |enc_file, file|
        if File.exist? enc_file
          File.write file, decrypt_file(enc_file)
        else
          File.unlink file
        end
      end
    end

    def self.grep(format)
      each_file_pair do |enc_file, file|
        next unless File.exist? enc_file
        matched = decrypt_file(enc_file).lines.grep(format)
        puts "\e[1min #{file}\e[m", matched unless matched.empty?
      end
    end

    def self.commit
      each_file_pair do |enc_file, file|
        if File.exist? file
          dict = {}
          decrypt_file enc_file, dict if File.exist? enc_file
          File.write enc_file, encrypt_file(file, dict)
        else
          File.unlink enc_file
        end
      end
    end
  end
end

def readline(prompt: '> ', hide: false)
  chars = []
  STDIN.raw do
    loop do
      STDOUT.write "\r\e[K#{prompt}" + (hide ? '*' * chars.size : chars.join)
      c = STDIN.getc
      case c.ord
      when 0x03
        exit
      when 0x04, 0x0D
        break
      when 0x7F
        chars.pop
      else
        chars << c if (32..128).cover? c.ord
      end
    end
  end
  puts
  chars.join
end

Memo::Command.encrypted_dir = '.data'
Memo::Command.data_dir = 'data'
[Memo::Command.encrypted_dir, Memo::Command.data_dir].each do |dir|
  Dir.mkdir dir unless Dir.exist? dir
end
password = readline prompt: 'password> ', hide: true
exit if password.empty?

Memo::Command.password = password
loop do
  cmd = readline
  case cmd.split(' ').first
  when 'exit'
    exit
  when 'commit'
    Memo::Command.commit
  when 'diff'
    Memo::Command.diff
  when 'status'
    Memo::Command.diff detail: false
  when 'checkout'
    Memo::Command.checkout
  when 'grep'
    Memo::Command.grep Regexp.new(cmd.split(' ', 2).last)
  else
    puts 'commit diff status checkout exit'
  end
end
