require 'nokogiri'
require 'openssl'
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

    def self.attr_first_value_accessor(name, xpath)
      define_method(name) do
        node = @doc.xpath(xpath).first
        node.value unless node.nil?
      end
    end

    def self.attr_first_value_boolean_true?(name, xpath)
      define_method(name) do
        node = @doc.xpath(xpath).first
        node.value.to_i == 1 unless node.nil?
      end
    end

    def self.content_first_node_accessor(name, xpath)
      define_method(name) do
        node = @doc.xpath(xpath).first
        node.content unless node.nil?
      end
    end

    def self.content_first_node_boolean_true?(name, xpath)
      define_method(name) do
        node = @doc.xpath(xpath).first
        node.content == 'true' unless node.nil?
      end
    end

    def self.all_attr_values_accessor(name, xpath)
      define_method(name) do
        @doc.xpath(xpath).map(&:value)
      end
    end

    # The hostname of the scanned host
    attr_first_value_accessor :host, '//ssltest/@host'

    # The port of the scan report
    attr_first_value_accessor :port, '//ssltest/@port'

    # Is ssl compression supported on target?
    attr_first_value_boolean_true? :compression_supported?, '//compression/@supported'

    # Does the target support TLS renegotiation?
    attr_first_value_boolean_true? :renegotiation_supported?, '//renegotiation/@supported'

    # Is the renegotiation secure?
    attr_first_value_boolean_true? :renegotiation_secure?, '//renegotiation/@secure'

    # Signature algorithm used in the certificate
    content_first_node_accessor :signature_algorithm, '//certificate/signature-algorithm'

    # Subject of the certificate
    content_first_node_accessor :subject, '//certificate/subject'

    # Subject alternative names of the certificate
    content_first_node_accessor :altnames, '//certificate/altnames'

    # Issuer of the certificate
    content_first_node_accessor :issuer, '//certificate/issuer'

    # Is the certificate a self-signed certificate?
    content_first_node_boolean_true? :self_signed?, '//certificate/self-signed'

    # Is the certificate expired?
    content_first_node_boolean_true? :expired?, '//certificate/expired'

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
    all_attr_values_accessor :ciphers, '//cipher/@cipher'

    # Is the cipher supported?
    def support_cipher?(cipher)
      @doc.xpath("//cipher[@cipher=$cipher]", nil, { cipher: cipher }).count > 0
    end

    # Returns a list of preferred ciphers
    all_attr_values_accessor :preferred_ciphers, '//cipher[@status="preferred"]/@cipher'

    # Returns a list of SSL/TLS protocol versions vulnerable to heartbleed
    all_attr_values_accessor :heartbleed_vulnerable_sslversions, '//heartbleed[@vulnerable="1"]/@sslversion'

    # Are there any heartblead vulnerable SSL/TLS protocol versions?
    def heartbleed_vulnerable?
      @doc.xpath('//heartbleed[@vulnerable="1"]').count > 0
    end

    # Returns a list of supported SSL protocol versions
    def sslversions
      @doc.xpath('//cipher/@sslversion').map(&:value).uniq
    end

    # Check if a SSL protocol version is supported
    def support_sslversion?(version)
      @doc.xpath("//cipher[@sslversion=$version]", nil, { version: version }).count > 0
    end

    # Return the parsed certificate blob as OpenSSL::X509::Certificate
    def certificate
      node = @doc.xpath('//certificate/certificate-blob').first
      OpenSSL::X509::Certificate.new(node.content) unless node.nil?
    end
  end
end
