#
# Be sure to run `pod lib lint MPUKeychain.podspec' to ensure this is a
# valid spec before submitting.
#
# Any lines starting with a # are optional, but their use is encouraged
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html
#

Pod::Spec.new do |s|
  s.name             = 'MPUKeychain'
  s.version          = '0.1.0'
  s.summary          = 'Quick and easy data saving in secured Keychain.'

  s.description      = <<-DESC
	Save any data securely to iOS Keychain.
					 DESC

  s.homepage         = 'https://github.com/martinpucik/MPUKeychain'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'Martin Púčik' => 'martin.pucik@me.com' }
  s.source           = { :git => 'https://github.com/martinpucik/MPUKeychain.git', :tag => s.version.to_s }
  s.social_media_url = 'https://twitter.com/martinpucik'

  s.ios.deployment_target = '8.0'

  s.source_files = 'MPUKeychain/Classes/**/*'
  
  # s.resource_bundles = {
  #   'MPUKeychain' => ['MPUKeychain/Assets/*.png']
  # }

  # s.public_header_files = 'Pod/Classes/**/*.h'
  # s.frameworks = 'UIKit', 'MapKit'
  # s.dependency 'AFNetworking', '~> 2.3'
end
