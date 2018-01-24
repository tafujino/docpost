#!/usr/bin/env ruby

require 'thor'
require 'base64'
require 'net/http'
require 'uri'
require 'open-uri'
require 'json'
require 'pathname'

class DocPost < Thor
  @docpost_dir = Pathname.new(Dir.home) + '.docpost'
  @conf_path = @docpost_dir + 'conf.json'
  @conf = File.exist?(@conf_path) ? File.open(@conf_path) { |f| JSON.load(f) } : { }
  @default = @conf['default']

  class << self
    attr_accessor :conf, :default

    def option_override(v1, v2)
      v2.nil? ? v1 : v2
    end
  end

  class_option :version, :type => :boolean, :aliases => :'-v'
  map %w[--version -v] => :version

  desc 'sub [FILE] [options]', 'Submit (r)markdown text to DocBase (text is from STDIN when FILE is unspecified)'
  # for available parameters, see https://help.docbase.io/posts/92980
  option :teams,   type: :array,   default: default['sub']['teams']
  option :title,   type: :string,  default: ''
  option :tags,    type: :array,   default: default['sub']['tag']
  option :groups,  type: :array,   default: default['sub']['groups']
  option :draft,   type: :boolean, default: option_override(false, default['sub']['draft'])
  option :scope,   enum: %w[everyone group private], default: default['sub']['scope']
  option :notice,  type: :boolean, default: option_override(true, default['sub']['notice'])
  option :type,    enum: %w[md Rmd]
  option :dry_run, type: :boolean, default: false
  option :upload,  enum: %w[all local], default: option_override('local', default['sub']['upload'])
  def sub(path = nil)
    check_token
    file_type = options[:type]
    check_title = proc do 
      if !options[:title] || options[:title].empty?
        STDERR.puts "ERROR: title is missing"
        help('sub')
        exit 1
      end
    end
    if path
      unless File.exist?(path)
        error "ERROR: file not exist - #{path}"
        exit 1
      end
      body = File.read(path)
      unless options[:type]
        ext = File.extname(path)
        case ext
        when /^\.md$/i
          file_type = 'md'
          check_title.call
        when /^\.Rmd$/i
          file_type = 'Rmd'
        else
          error "ERROR: cannot determine file type: #{path}"
          exit 1
        end
      end
    else
      case file_type
      when 'Rmd'
        body = STDIN.read
      when 'md'
        check_title.call
        body = STDIN.read
      else
        check_title.call
        body = STDIN.read
        say 'suppose file type is Markdown'
        file_type = 'md'
      end
    end
    if 'group' != options[:scope] && options[:groups]
      error "ERROR: option \"scope\" should be \"group\" when group(s) are specified"
      help('sub')
      exit 1
    end
    if 'group' == options[:scope] && (!options[:groups] || options[:groups].empty?)
      error "ERROR: should specify group(s) when scope is \"group\""
      help('sub')
      exit 1
    end

    options[:teams].each do |team|
      body = upload_and_substitute_images(team, body)
      json = {
        title:  options[:title],
        body:   body,
        draft:  options[:draft],
        scope:  options[:scope],
        tags:   options[:tags],
        groups: options[:groups],
        notice: options[:notice],
      }.compact.to_json

      say "submitting" + (path ? ": #{path}" : '')
      response = post("https://api.docbase.io/teams/#{team}/posts", json)
      handle_response(response)      
    end
  end

  # for teams retrieval,  see https://help.docbase.io/posts/92977
  # for groups retrieval, see https://help.docbase.io/posts/92978
  desc 'print {teams, groups [TEAMS]}', 'Print list of teams/groups'
  def print(*args)
    if args.empty?
      help('print')
      exit 1
    end
    check_token
    target = args.shift
    case target
    when 'teams'
      response = get('https://api.docbase.io/teams')
      JSON.parse(response.body).each_with_index do |h, i|
        puts "domain = #{h['domain']}, name = #{h['name']}"
      end
      puts
      handle_response(response)
    when 'groups'
      teams = args.empty? ? @default['print']['groups']['teams'] : args
      unless teams
        error 'no teams are specified'
        exit 1
      end
      teams.each do |team|
        puts "team: #{team}"
        response = get("https://api.docbase.io/teams/#{team}/groups")
        JSON.parse(response.body).each_with_index do |h, i|
          puts "id = #{h['id']}, name = #{h['name']}"
        end
        puts
        handle_response(response)
      end
    end
  end

  desc 'set token TOKEN', 'Set token'
  def set(cmd, arg)
    unless 'token' == cmd
      help('set')
      exit 1
    end
  end

  desc 'update database', 'Update teams and groups database'
  def update(arg)
  end

  desc 'version', 'Show version'
  def version
    puts '0.1'
  end

  private

  def initialize(args = [], options = { }, config = { })
    @conf = DocPost.conf
    @default = @conf['default']
    @token = @conf['token']
    super(args, options, config)
  end

  def check_token
    return if @token
    error 'token is not registered'
    help('set token')
    exit 1
  end

  def request(uri, klass, dry_run = false)
    uri = URI.parse(uri) if uri.instance_of?(String)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    
    request = klass.new(uri.request_uri)
    request['Content-Type'] = 'application/json'
    request['X-DocBaseToken'] = @token
    yield request

    return nil if dry_run
    response = http.request(request)
  end

  def get(uri, dry_run = false)
    request(uri, Net::HTTP::Get, dry_run) { }
  end

  def post(uri, json, dry_run = false)
    request(uri, Net::HTTP::Post, dry_run) { |request| request.body = json }
  end

  def update_config_file
  end

  def upload_and_substitute_images(team, body)
    body = body.clone
    # to do: normalize path
    paths = body.scan(/!\[[^\[\]]*\]\(([^\(\)]*)\)/).flatten.uniq 
    paths.each do |path|
      uri = URI.parse(path)
      should_upload = false
      case uri
      when URI::HTTP, URI::HTTPS, URI::FTP
        should_upload = true if 'all' == options[:upload]
      when URI::Generic
        should_upload = true
      else
        error "cannot upload the following image: #{path}"
        exit 1
      end
      next unless should_upload
      content = nil
      say "reading and uploading: #{uri.path}"
      open(uri.path) { |f| content = f.read }
      json = {
        name:    File.basename(uri.path),
        content: Base64.strict_encode64(content)
      }.to_json
      res = post("https://api.docbase.io/teams/#{team}/attachments", json)
      body.gsub!(/!\[([^\[\]]*)\]\(#{path}\)/, JSON.parse(res.body)['markdown'])
    end
    body
  end

  def handle_response(response)
    case response.code.to_i
    when 200
    when 201
      say 'successfully submitted'
    when 204
      say 'successfully removed'
    when 400
      error 'invalid request'
      exit 1
    when 403
      error 'invalid token or non-existent team is specified'
      exit 1
    when 404
      error 'accessed to non-existent URL'
      exit 1
    when 429
      error 'quota exceeded'
      exit 1
    else
      # code 500 is included here
      error 'unknown error'
      exit 1
    end
    say "remaining quota: #{response['x-ratelimit-remaining']}/#{response['x-ratelimit-limit']}, to be reset at: #{Time.at(response['x-ratelimit-reset'].to_i)}"
    puts
  end
end

if $PROGRAM_NAME == __FILE__
  DocPost.start(ARGV)
end

