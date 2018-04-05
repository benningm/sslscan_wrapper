require 'sslscan_wrapper'

RSpec.describe SslscanWrapper::Report do
  describe '#with default options' do
    it 'parse an sslscan report' do
      content = File.read(File.dirname(__FILE__) + "/reports/default.xml")
      report = SslscanWrapper::Report.new(content)
      expect(report.host).to eq('testsystem.mydomain.de')
      expect(report.port).to eq('443')
      expect(report.compression_supported?).to eq(false)
      expect(report.renegotiation_supported?).to eq(false)
      expect(report.renegotiation_secure?).to eq(false)
      expect(report.signature_algorithm).to eq('sha256WithRSAEncryption')
      expect(report.subject).to eq('testsystem.mydomain.de')
      expect(report.altnames).to eq('DNS:testsystem.mydomain.de')
      expect(report.issuer).to eq('Secure Certification Authority')
      expect(report.self_signed?).to eq(false)
      expect(report.expired?).to eq(false)
      expect(report.not_before).to be_a(Time)
      expect(report.not_after).to be_a(Time)
      expect(report.ciphers).to include('ECDHE-RSA-DES-CBC3-SHA')
      expect(report.ciphers.count).to eq(20)
      expect(report.preferred_ciphers).to include('ECDHE-RSA-AES256-GCM-SHA384')
      expect(report.preferred_ciphers.count).to eq(2)
      expect(report.heartbleed_vulnerable_sslversions.count).to eq(0)
      expect(report.heartbleed_vulnerable?).to eq(false)
      expect(report.sslversions).to match_array(['TLSv1.1', 'TLSv1.2'])
      expect(report.support_sslversion?('SSLv3')).to eq(false)
    end

    it 'parse an more verbose scan report' do
      content = File.read(File.dirname(__FILE__) + "/reports/verbose.xml")
      report = SslscanWrapper::Report.new(content)
      expect(report.host).to eq('localhost')
      expect(report.port).to eq('4433')
      expect(report.compression_supported?).to eq(false)
      expect(report.renegotiation_supported?).to eq(true)
      expect(report.renegotiation_secure?).to eq(true)
      expect(report.signature_algorithm).to eq('sha256WithRSAEncryption')
      expect(report.subject).to eq('/C=DE/ST=Bavaria/L=test/O=Default Company Ltd/CN=test.bla')
      expect(report.altnames).to eq(nil)
      expect(report.issuer).to eq('/C=DE/ST=Bavaria/L=test/O=Default Company Ltd/CN=test.bla')
      expect(report.self_signed?).to eq(true)
      expect(report.expired?).to eq(false)
      expect(report.not_before).to be_a(Time)
      expect(report.not_after).to be_a(Time)
      expect(report.ciphers).to include('ECDHE-RSA-DES-CBC3-SHA')
      expect(report.ciphers.count).to eq(88)
      expect(report.preferred_ciphers).to include('ECDHE-RSA-AES256-GCM-SHA384')
      expect(report.preferred_ciphers.count).to eq(4)
      expect(report.heartbleed_vulnerable_sslversions.count).to eq(0)
      expect(report.heartbleed_vulnerable?).to eq(false)
      expect(report.sslversions).to match_array(['SSLv3', 'TLSv1.0', 'TLSv1.1', 'TLSv1.2'])
      expect(report.support_sslversion?('SSLv3')).to eq(true)
    end

    it 'extracts the certificate from a report' do
      content = File.read(File.dirname(__FILE__) + "/reports/verbose.xml")
      report = SslscanWrapper::Report.new(content)
      expect(report.certificate).to be_a(OpenSSL::X509::Certificate)
    end
  end
end
