require 'nokogiri'
require 'time'

module SslscanWrapper
  class Report
    # The content body of the report
    attr_reader :body
    # The nokogiri document object
    attr_reader :doc
    # Initialize a new report object
    #
    # Examples
    #
    #   content = File.read('report.xml')
    #   SslscanWrapper::Report.new(content)
    #
    # Returns a new SslscanWrapper::Report
    def initialize(output)
      @body = output
      @doc = Nokogiri::XML(@body)
    end

    # The hostname of the scanned host
    def host
      @doc.xpath('//ssltest/@host').first.value
    end

    # The port of the scan report
    def port
      @doc.xpath('//ssltest/@port').first.value
    end

    # Is ssl compression supported on target?
    def compression_supported?
      @doc.xpath('//compression/@supported').first.value == '1'
    end

    # Does the target support TLS renegotiation?
    def renegotiation_supported?
      @doc.xpath('//renegotiation/@supported').first.value == '1'
    end

    def renegotiation_secure?
      @doc.xpath('//renegotiation/@secure').first.value == '1'
    end

    # Signature algorithm used in the certificate
    def signature_algorithm
      @doc.xpath('//certificate/signature-algorithm').first.content
    end

    # Subject of the certificate
    def subject
      @doc.xpath('//certificate/subject').first.content
    end

    # Subject alternative names of the certificate
    def altnames
      @doc.xpath('//certificate/altnames').first.content
    end

    # Issuer of the certificate
    def issuer
      @doc.xpath('//certificate/issuer').first.content
    end

    # Is the certificate a self-signed certificate?
    def self_signed?
      @doc.xpath('//certificate/self-signed').first.content == 'true'
    end

    # Is the certificate expired?
    def expired?
      @doc.xpath('//certificate/expired').first.content == 'true'
    end

    # Time the certificate starts to be valid
    def not_before
      time_str = @doc.xpath('//certificate/not-valid-before').first.content
      Time.parse(time_str)
    end

    # Time the certificate is no longer valid
    def not_after
      time_str = @doc.xpath('//certificate/not-valid-after').first.content
      Time.parse(time_str)
    end

    # Returns a list of supported ciphers
    def ciphers
      @doc.xpath('//cipher/@cipher').map(&:value)
    end

    # Is the cipher supported?
    def cipher_supported?(cipher)
      @doc.xpath("//cipher[@cipher=\"#{cipher}\"]").count > 0
    end

    # Returns a list of preferred ciphers
    def preferred_ciphers
      @doc.xpath('//cipher[@status="preferred"]/@cipher').map(&:value)
    end

    # Returns a list of SSL/TLS protocol versions vulnerable to heartbleed
    def heartbleed_vulnerable_sslversions
      @doc.xpath('//heartbleed[@vulnerable="1"]/@sslversion').map(&:value)
    end

    # Are there any heartblead vulnerable SSL/TLS protocol versions?
    def heartbleed_vulnerable?
      @doc.xpath('//heartbleed[@vulnerable="1"]').count > 0
    end
  end
end
