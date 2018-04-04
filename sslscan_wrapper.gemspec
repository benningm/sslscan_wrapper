spec = Gem::Specification.new do |s| 
  s.name = 'sslscan_wrapper'
  s.version = '0.0.1'
  s.author = 'Markus Benning'
  s.email = 'ich@markusbenning.de'
  s.homepage = 'https://github.com/benningm/sslscan_wrapper'
  s.platform = Gem::Platform::RUBY
  s.summary = 'Wrapper for sslscan SSL/TLS protocol scanner'
  s.license = 'MIT'
  s.files = Dir.glob('lib/**/*.rb') + Dir.glob('bin/*') + Dir.glob('[A-Z]*') + Dir.glob('test/**/*')
  s.require_paths << 'lib'
  s.add_development_dependency('aruba', '~> 0')
  s.add_development_dependency('nokogiri', '~> 1')
  s.add_development_dependency('rake', '~> 12')
  s.add_development_dependency('rdoc', '~> 6')
end
