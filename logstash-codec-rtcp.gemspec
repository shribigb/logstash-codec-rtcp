Gem::Specification.new do |s|
  s.name          = 'logstash-codec-rtcp'
  s.version       = '0.1.0'
  s.licenses      = ['Apache License (2.0)']
  s.summary       = 'This codec is used to decode rtcp data'
  s.authors       = ['Shri Bodas']
  s.email         = 'shri.bodas@elastic.co'
  s.require_paths = ['lib']

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "codec" }

  # Gem dependencies
  s.add_runtime_dependency 'logstash-core-plugin-api', "~> 2.0"
  s.add_runtime_dependency 'logstash-codec-line'
  s.add_runtime_dependency 'rtcp'
  s.add_development_dependency 'logstash-devutils'
end
