#! /usr/bin/env ruby
#
#   check-http-json
#
# DESCRIPTION:
#   Takes either a URL or a combination of host/path/query/port/ssl, and checks
#   for valid JSON output in the response. Can also optionally validate simple
#   string key/value pairs.
#
# OUTPUT:
#   plain text
#
# PLATFORMS:
#   Linux
#
# DEPENDENCIES:
#   gem: sensu-plugin
#   gem: json
#
# USAGE:
#   #YELLOW
#
# NOTES:
#   Based on Check HTTP by Sonian Inc.
#
# LICENSE:
#   Copyright 2013 Matt Revell <nightowlmatt@gmail.com>
#   Released under the same terms as Sensu (the MIT license); see LICENSE
#   for details.
#

require 'sensu-plugin/check/cli'
require 'json'
require 'net/http'
require 'net/https'
require 'uri'



#
# Check JSON
#
class CheckJson < Sensu::Plugin::Check::CLI
  option :url, short: '-u URL'
  option :host, short: '-h HOST'
  option :path, short: '-p PATH'
  option :query, short: '-q QUERY'
  option :port, short: '-P PORT', proc: proc(&:to_i)
  option :method, short: '-m GET|POST'
  option :postbody, short: '-b /file/with/post/body'
  option :header, short: '-H HEADER', long: '--header HEADER'
  option :ssl, short: '-s', boolean: true, default: false
  option :insecure, short: '-k', boolean: true, default: false
  option :user, short: '-U', long: '--username USER'
  option :password, short: '-a', long: '--password PASS'
  option :cert, short: '-c FILE'
  option :cacert, short: '-C FILE'
  option :timeout, short: '-t SECS', proc: proc(&:to_i), default: 15
  option :key, short: '-K KEY', long: '--key KEY'
  option :value, short: '-v VALUE', long: '--value VALUE'
  option :key_regex, long: '--key-regex regex'
  option :value_regex, long: '--value-regex regex'
  option :redirect_limit, short: '-r redirect_limit', long: '--redirect-limit redirect_limit', default: 10, proc: proc(&:to_i)

  def run
    if config[:url]
      uri = URI.parse(config[:url])
      config[:host] = uri.host
      config[:path] = uri.path
      config[:query] = uri.query
      config[:port] = uri.port
      config[:ssl] = uri.scheme == 'https'
    else
      # #YELLOW
      unless config[:host] && config[:path]
        unknown 'No URL specified'
      end
      config[:port] ||= config[:ssl] ? 443 : 80
    end

    begin
      timeout(config[:timeout]) do
        acquire_resource
      end
    rescue Timeout::Error
      critical 'Connection timed out'
    rescue => e
      critical "Connection error: #{e.message}"
    end
  end

  def json_valid?(str)
    JSON.parse(str)
    return true
  rescue JSON::ParserError
    return false
  end

  def fetch(uri=nil, limit = 10)
    if limit == 0
      raise "Too many HTTP redirects (max limit of #{config[:redirect_limit]})"
    end

    response = create_request(uri)

    case response
    when Net::HTTPSuccess then
      response
    when Net::HTTPRedirection then
      location = response['location']
      fetch(URI.parse(location), limit - 1)
    else
      response.value
    end
  end

  def create_request(uri)
    if uri.nil?
      if config[:uri]
        uri = URI.parse(config[:url])
      else
        uri = URI::HTTP.build(
          :host => config[:host],
          :port => config[:port],
          :path => config[:path],
          :query => config[:query]
        )
      end
    end

    http = Net::HTTP.new(uri.host, uri.port)

    if config[:ssl]
      http.use_ssl = true
      if config[:cert]
        cert_data = File.read(config[:cert])
        http.cert = OpenSSL::X509::Certificate.new(cert_data)
        http.key = OpenSSL::PKey::RSA.new(cert_data, nil)
      end
      http.ca_file = config[:cacert] if config[:cacert]
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE if config[:insecure]
    end

    if config[:method] == 'POST'
      req = Net::HTTP::Post.new(uri.request_uri)
    else
      req = Net::HTTP::Get.new(uri.request_uri)
    end
    if config[:postbody]
      post_body = IO.readlines(config[:postbody])
      req.body = post_body.join
    end
    if !config[:user].nil? && !config[:password].nil?
      req.basic_auth config[:user], config[:password]
    end
    if config[:header]
      config[:header].split(',').each do |header|
        h, v = header.split(':', 2)
        req[h] = v.strip
      end
    end

    http.request(req)
  end


  def query_json(json, keyRegex, valueRegex)
    flattened = json.flatten_with_path

    matching_keys = flattened.map { |key,_| key if key.match(keyRegex) }.compact

    if matching_keys.empty?
      raise "Could not find keys with query #{keyRegex}"
    end

    values = matching_keys.map { |key|
      value = flattened[key]

      {
        :matches => value.match(valueRegex) ? true : false,
        :value => value,
        :key => key
      }
    }

    if values.all? { |val| val[:matches] == true }
      ok "All keys with '#{keyRegex}' match the value expression '#{valueRegex}'"
    else
      non_matched = values.map { |el| {el[:key] => el[:value]} if el[:matches] == false }.compact
      critical "One or more keys with '#{keyRegex}' did not match value expression '#{valueRegex}'. \n#{JSON.pretty_generate(non_matched)}"
    end
  end

  def acquire_resource

    res = fetch(nil, config[:redirect_limit])

    critical res.code unless res.code =~ /^2/
    critical 'invalid JSON from request' unless json_valid?(res.body)
    ok 'valid JSON returned' if config[:key].nil? && config[:value].nil? && config[:key_regex].nil? && config[:value_regex].nil?

    json = JSON.parse(res.body)

    if config[:key_regex] && config[:value_regex]
      query_json(json, config[:key_regex], config[:value_regex])
    else
      begin
        keys = config[:key].scan(/(?:\\\.|[^.])+/).map { |key| key.gsub(/\\./, '.') }

        puts keys

        leaf = keys.reduce(json) do |tree, key|
          fail "could not find key: #{config[:key]}" unless tree.key?(key)
          tree[key]
        end

        fail "unexpected value for key: '#{config[:value]}' != '#{leaf}'" unless leaf.to_s == config[:value].to_s

        ok "key has expected value: '#{config[:key]}' = '#{config[:value]}'"
      rescue => e
        critical "key check failed: #{e}"
      end
    end
  end
end

module Enumerable
  def flatten_with_path(parent_prefix = nil)
    res = {}

    self.each_with_index do |elem, i|
      if elem.is_a?(Array)
        k, v = elem
        key = parent_prefix ? "#{parent_prefix}.#{k}" : k
      else
        k, v = i, elem
        key = parent_prefix ? "#{parent_prefix}[#{k}]" : k
      end

      if v.is_a? Enumerable
        res.merge!(v.flatten_with_path(key))
      else
        res[key] = v
      end
    end

    res
  end
end

