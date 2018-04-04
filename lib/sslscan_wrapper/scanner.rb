require 'sslscan_wrapper/report'
require 'open3'

module SslscanWrapper
  class Scanner
    # sslscan executable
    attr_accessor :command

    # Hostname for SNI
    attr_accessor :sni_name
    # Only use IPv4
    attr_accessor :ipv4
    # Only use IPv6
    attr_accessor :ipv6
    # Only check SSLv2 ciphers
    attr_accessor :ssl2
    # Only check SSLv3 ciphers
    attr_accessor :ssl3
    # Only check TLSv1.0 ciphers
    attr_accessor :tls10
    # Only check TLSv1.1 ciphers
    attr_accessor :tls11
    # Only check TLSv1.2 ciphers
    attr_accessor :tls12
    # Only check TLS ciphers (all versions)
    attr_accessor :tlsall
    # Request OCSP response from server
    attr_accessor :ocsp
    # A file containing the private key or a PKCS12 file containing a private key/certificate pair
    attr_accessor :pk
    # The password for the private  key or PKCS12 file certs=<file> A file containing PEM/ASN1 formatted client certificates
    attr_accessor :pkpass
    # Use a server-to-server XMPP handshake
    attr_accessor :xmpp_server
    # Test a HTTP connection
    attr_accessor :http
    # Send RDP preamble before starting scan
    attr_accessor :rdp
    # Enable SSL implementation bug work-arounds
    attr_accessor :bugs
    # Set socket timeout. Default is 3s
    attr_accessor :timeout
    # Pause between connection request. Default is disabled
    attr_accessor :sleep

    @@SSL_SCAN_FLAGS = [ :ipv4, :ipv6, :ssl2, :ssl3, :tls10, :tls11, :tls12, :tlsall, :ocsp, :xmpp_server, :http, :bugs ]
    @@SSL_SCAN_OPTIONS = [ :sleep, :timeout, :sni_name, :pk, :pkpass ]
    @@SSL_SCAN_ARGS = [ '--xml=-', '--no-colour' ]

    # Initialize a new SslscanWrapper::Scanner object
    #
    # Examples
    #
    #   scan = SslscanWrapper::Scanner.new do |s|
    #     s.ipv4 = true
    #   end
    #
    # Returns a SslscanWrapper::Scanner object
    def initialize
      @command = 'sslscan'
      @port = 443
      yield self if block_given?
    end

    # Scan a target
    #
    # Returns a SslscanWrapper::Report object
    def scan(host, port)
      execute(host, port)
    end

    private

    def cmd(host, port)
      cmd = [ @command ] + @@SSL_SCAN_ARGS
      @@SSL_SCAN_FLAGS.each do |flag|
        next if send(flag).nil?
        cmd << "--#{flag.to_s.gsub('_', '-')}"
      end
      @@SSL_SCAN_OPTIONS.each do |option|
        next if (value = send(option)).nil?
        cmd << '--' + option.to_s.gsub('_', '-')
        cmd << value
      end
      cmd << "#{host}:#{port}"
    end

    def execute(host, port)
      command = cmd(host, port)
      report, err, status = Open3.capture3(*command)
      raise "Error while executing sslscan: #{err}" unless status.success?
      SslscanWrapper::Report.new(report)
    end
  end
end
