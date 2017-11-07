Pod::Spec.new do |s|
  s.name             = 'PVSS'
  s.version          = '2.1.0'
  s.summary          = 'An implementation of Publicly Verifiably Secret Sharing (PVSS) in Swift.'
  s.description      = <<-DESC
The library implements a PVSS scheme in Swift. The algorithm is based on "A Simple Publicly Verifiable Secret Sharing Scheme and its Application to Electronic Voting" by Berry Schoenmakers.
                       DESC

  s.homepage         = 'https://github.com/FabioTacke/PubliclyVerifiableSecretSharing'
  s.license          = { :type => 'MIT', :file => 'LICENSE.md' }
  s.author           = { 'Fabio Tacke' => 'fabio@tacke.berlin' }
  s.source           = { :git => 'https://github.com/FabioTacke/PubliclyVerifiableSecretSharing.git', :tag => 'v' + String(s.version) }
  s.social_media_url = 'https://twitter.com/FabioTacke'

  s.source_files = 'Sources/PVSS/*.swift'

  s.dependency 'BigInt'
  s.dependency 'CryptoSwift'

  s.ios.deployment_target = '8.0'
  s.osx.deployment_target = '10.10'
  s.tvos.deployment_target = '9.0'
  s.watchos.deployment_target = '3.0'
end
