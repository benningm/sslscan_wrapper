require 'sslscan_wrapper'
require 'open3'

RSpec.describe SslscanWrapper::Scanner do
  describe '#with default options' do
    it 'run a default sslscan' do
      scan = SslscanWrapper::Scanner.new
      expect(scan.send(:cmd, 'testhost', 123)).to match_array([ 'sslscan', '--xml=-', '--no-colour', 'testhost:123'])
    end

    it '#with flags' do
      [:ipv4, :ipv6, :http, :xmpp_server].each do |flag|
        scan = SslscanWrapper::Scanner.new do |s|
          s.send("#{flag}=", true)
        end
        expect(scan.send(flag)).to eq(true)
        expect(scan.send(:cmd, 'testhost', 123)).to include("--#{flag}".gsub('_', '-'))
      end
    end

    it '#with options' do
      scan = SslscanWrapper::Scanner.new do |s|
        s.sni_name = 'snihost'
      end
      expect(scan.sni_name).to eq('snihost')
      expect(scan.send(:cmd, 'testhost', 123)).to include('--sni-name', 'snihost')
    end

    it '#executes the sslscan' do
      # mock the Open3.capture3 call
      content = File.read(File.dirname(__FILE__)+"/reports/default.xml")
      status = double('Process::Status', success?: true)
      allow(Open3).to receive(:capture3).and_return([content, '', status])

      s = SslscanWrapper::Scanner.new
      report = s.scan('testhost', 443)
      expect(report.body).to eq(content)
    end

    it '#raises exception on sslscan errors' do
      error = 'sslscan is foobared'
      status = double('Process::Status', success?: false)
      allow(Open3).to receive(:capture3).and_return(['', error, status])

      s = SslscanWrapper::Scanner.new
      expect {
        s.scan('testhost', 443)
      }.to raise_error('Error while executing sslscan: sslscan is foobared')
    end
  end
end
