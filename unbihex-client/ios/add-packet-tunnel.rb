#!/usr/bin/env ruby
# frozen_string_literal: true

# Adds the PacketTunnel app extension (ios/PacketTunnel) to the Xcode project made by
# `cargo tauri ios init`, embeds it into the app and regenerates the project with xcodegen.
# Replaces the manual Xcode steps from README "Сборка для iOS". Safe to run again.
#
#   cd unbihex-client
#   sh ios/PacketTunnel/build-ffi.sh          # ios/PacketTunnel/lib/libunbihex-{ios,sim}.a
#   ruby ios/add-packet-tunnel.rb [gen/apple]

require 'json'
require 'open3'
require 'pathname'
require 'yaml'

CLIENT = File.expand_path('..', __dir__)
APPLE = File.expand_path(ARGV[0] || File.join(CLIENT, 'app/src-tauri/gen/apple'))
SPEC = File.join(APPLE, 'project.yml')
TUNNEL = 'PacketTunnel'
NE_KEY = 'com.apple.developer.networking.networkextension'

abort "Нет #{SPEC}: сначала выполните `cargo tauri ios init` в app/src-tauri" unless File.file?(SPEC)

conf = JSON.parse(File.read(File.join(CLIENT, 'app/src-tauri/tauri.conf.json')))
version = conf.fetch('version')
identifier = conf.fetch('identifier')
min_ios = conf.dig('bundle', 'iOS', 'minimumSystemVersion') || '15.0'

# Path of a file under unbihex-client/, relative to the spec (xcodegen sources) ...
def rel(path)
  Pathname.new(File.join(CLIENT, path)).relative_path_from(Pathname.new(APPLE)).to_s
end

# ... and as a build setting.
def src(path)
  "$(SRCROOT)/#{rel(path)}"
end

spec = YAML.load_file(SPEC, aliases: true)
targets = spec.fetch('targets')
app_name, app = targets.find { |name, t| name != TUNNEL && t['type'] == 'application' && t['platform'] == 'iOS' }
abort "В #{SPEC} нет iOS-приложения" unless app

team = spec.dig('settingGroups', 'app', 'base', 'DEVELOPMENT_TEAM') || app.dig('settings', 'base', 'DEVELOPMENT_TEAM')

settings = {
  'PRODUCT_NAME' => TUNNEL,
  'PRODUCT_BUNDLE_IDENTIFIER' => "#{identifier}.tunnel",
  'MARKETING_VERSION' => version,
  'CURRENT_PROJECT_VERSION' => version,
  # Xcode adds the bundle keys to the NSExtension-only Info.plist from ios/PacketTunnel.
  'GENERATE_INFOPLIST_FILE' => 'YES',
  'INFOPLIST_FILE' => src('ios/PacketTunnel/Info.plist'),
  'CODE_SIGN_ENTITLEMENTS' => src('ios/PacketTunnel/PacketTunnel.entitlements'),
  'SWIFT_VERSION' => '5.0',
  'SWIFT_OBJC_BRIDGING_HEADER' => src('ios/PacketTunnel/PacketTunnel-Bridging-Header.h'),
  'HEADER_SEARCH_PATHS' => "$(inherited) #{src('crates/unbihex-ffi/include')}",
  'LIBRARY_SEARCH_PATHS' => "$(inherited) #{src('ios/PacketTunnel/lib')}",
  'OTHER_LDFLAGS[sdk=iphoneos*]' => '$(inherited) -lunbihex-ios -lresolv',
  'OTHER_LDFLAGS[sdk=iphonesimulator*]' => '$(inherited) -lunbihex-sim -lresolv',
  'ENABLE_BITCODE' => 'NO',
  'SKIP_INSTALL' => 'YES'
}
settings['DEVELOPMENT_TEAM'] = team if team

targets[TUNNEL] = {
  'type' => 'app-extension',
  'platform' => 'iOS',
  'deploymentTarget' => min_ios.to_s,
  'sources' => [{ 'path' => rel('ios/PacketTunnel/PacketTunnelProvider.swift') }],
  'settings' => { 'base' => settings },
  'dependencies' => %w[NetworkExtension Security SystemConfiguration].map { |f| { 'sdk' => "#{f}.framework" } }
}

deps = (app['dependencies'] ||= [])
deps.reject! { |d| d['target'] == TUNNEL }
deps << { 'target' => TUNNEL, 'embed' => true }

# The app needs the Packet Tunnel capability too; keep what the entitlements file already has.
ent = (app['entitlements'] ||= { 'path' => "#{app_name}/#{app_name}.entitlements" })
unless ent['properties']
  file = File.join(APPLE, ent['path'])
  ent['properties'] =
    if File.file?(file)
      out, status = Open3.capture2('plutil', '-convert', 'json', '-o', '-', file)
      status.success? ? JSON.parse(out) : {}
    else
      {}
    end
end
ent['properties'][NE_KEY] = ['packet-tunnel-provider']

File.write(SPEC, spec.to_yaml)
Dir.chdir(APPLE) { system('xcodegen', 'generate', '--spec', SPEC) || abort('xcodegen завершился с ошибкой') }

File.open(ENV['GITHUB_ENV'], 'a') { |f| f.puts "IOS_APP_TARGET=#{app_name}" } if ENV['GITHUB_ENV']
puts "#{TUNNEL} (#{identifier}.tunnel) добавлен в #{app_name}"
