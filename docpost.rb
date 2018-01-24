#!/usr/bin/env ruby

require 'thor'
require 'base64'
require 'net/http'
require 'uri'
require 'open-uri'
require 'json'
require 'pathname'
require 'active_support'
require 'active_support/core_ext'

class DocPost < Thor
  class << self
    attr_reader :conf, :default, :options_table

    private

    def load_config(path)
      conf = File.exist?(path) ? File.open(path) { |f| JSON.load(f) } : { }
      conf.with_indifferent_access
    end

    def eval_option(cmd)
      @options_table[cmd].each do |key, value|
        value = value.clone
        value.delete(:loadable)
        option(key, value)
      end
    end
  end

  @docpost_dir = Pathname.new(Dir.home) + '.docpost'
  @conf_path = @docpost_dir + 'conf.json'
  @conf =  { default:
               { sub:
                   { teams:  nil,
                     groups: nil,
                     scope:  'private',
                     tags:   [],
                     draft:  false,
                     notice: true,
                     upload: 'standard',
                   },
               },
             path:
               { R:     nil,
                 token: @docpost_dir + 'token.json',
               },
           }.with_indifferent_access
  # should forbid to load keys undefined in the above
  @conf.deep_merge!(load_config(@conf_path))
  @default = @conf[:default]

  @options_table = { }.with_indifferent_access

  class_option :version, :type => :boolean, :aliases => :'-v'
  map %w[--version -v] => :version

  desc 'sub [FILE] [options]', 'Submit (r)markdown text to DocBase (text is from STDIN when FILE is unspecified)'
  # for available parameters, see https://help.docbase.io/posts/92980
  # option priority: 1. options in JSON 2. options from a command line 3. in FILE (i.e. R Markdown title) 4. default
  @options_table[:sub] =
    { teams:        { type: :array,                     default: default[:sub][:teams]                   },
      title:        { type: :string,                    default: ''                                      },
      tags:         { type: :array,                     default: default[:sub][:tag]                     },
      groups:       { type: :array,                     default: default[:sub][:groups]                  },
      draft:        { type: :boolean,                   default: default[:sub][:draft]                   },
      scope:        { enum: %w[everyone group private], default: default[:sub][:scope]                   },
      notice:       { type: :boolean,                   default: default[:sub][:notice]                  },
      type:         { enum: %w[md Rmd json]                                                              },
      dry_run:      { type: :boolean,                   default: false,                  loadable: false },
      upload:       { enum: %w[all standard],           default: default[:sub][:upload]                  },
    }.with_indifferent_access
  eval_option(:sub)
  def sub(path = nil)
    check_token
    if 'json' == options[:type] || (!options[:type] && path && File.extname(path) =~ /^\.json$/i)
      if path
        info = load_info_json(path)
      else
        begin
          info = JSON.load(STDIN)
        rescue
          error "load from STDIN failed. may be invalid JSON"
          exit 1
        end
      end
      path = File.expand_path(info[:body], File.dirname(path))
      opts = options.dup.deep_merge!(info.reject { |key, _| 'body' == key })
    else
      opts = options
    end

    check_title = proc do 
      if opts[:title].blank?
        STDERR.puts "ERROR: title is missing"
        help('sub')
        exit 1
      end
    end

    if path
      dir = File.dirname(path)
      unless File.exist?(path)
        error "ERROR: file not exist - #{path}"
        exit 1
      end
      body = File.read(path)
      unless opts[:type]
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
      dir = Dir.pwd
      case opts[:type]
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
    if 'group' != opts[:scope] && opts[:groups]
      error "ERROR: option \"scope\" should be \"group\" when group(s) are specified"
      help('sub')
      exit 1
    end
    if 'group' == opts[:scope] && (!opts[:groups] || opts[:groups].empty?)
      error "ERROR: should specify group(s) when scope is \"group\""
      help('sub')
      exit 1
    end

    opts[:teams].each do |team|
      body = upload_and_substitute_images(team, body, dir)
      json = {
        title:  opts[:title],
        body:   body,
        draft:  opts[:draft],
        scope:  opts[:scope],
        tags:   opts[:tags],
        groups: opts[:groups],
        notice: opts[:notice],
      }.compact.to_json

      say 'submitting' + (path ? ": #{path}" : '')
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
      teams = args.empty? ? @default[:print][:groups][:teams] : args
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
    @default = DocPost.default
    @options_table = DocPost.options_table
    super(args, options, config)
  end

  def load_info_json(path)
    unless File.exist?(path)
      error "file not exist: #{path}"
      exit 1
    end
    begin
      info = File.open(path) { |f| JSON.load(f).with_indifferent_access }
    rescue
      error "load failed. may be invalid JSON: #{path}"
      exit 1
    end
    unless info.key?(:body)
      error "should contain \"body\" key: #{path}"
      exit 1
    end
    info.reject { |key, _| 'body' == key }.each do |key, value|
      unless @options_table[:sub].key?(key)
        error "#{path} has invalid key: #{key}"
        exit 1
      end
      h = @options_table[:sub][key]
      is_key_invalid = false
      if h.key?(:loadable) && !h[:loadable]
        is_key_invalid = true
      elsif h.key?(:type)
        type_to_class = { boolen:  [TrueClass, FalseClass],
                          string:  [String],
                          numeric: [Numeric],
                          array:   [Array],
                          hash:    [Hash]
                        }
        is_correct_type = type_to_class[h[:type]].inject(false) do |ret, klass|
          ret ||= info[key].instance_of?(klass)
        end
        unless is_correct_type
          error "the value of \"#{key}\" should be #{h[:type]}"
          exit 1
        end
      elsif h.key?(:enum)
        unless h[:enum].instance_of?(Array) && h[:enum].include?(option_from_file[key])
          error "the value of \"#{key}\" should be #{h[:enum].to_s}}"
          exit 1
        end
      else
        is_key_invalid = true
      end
      if is_key_invalid
        error "invalid key \"#{key}\" in #{path}"
        exit 1
      end
    end
    info
  end

  def check_token
    return if load_token.present?
    error 'token is not registered'
    help('set')
    exit 1
  end

  def load_token
    path = @conf[:path][:token]
    if path.blank?
      error 'token path is empty'
      exit 1
    end
    unless File.exist?(path)
      error "token file not found: #{path}"
      exit 1
    end
    begin
      token = File.open(path) { |f| JSON.load(f).with_indifferent_access }
    rescue
      # error handling
    end
    token[:token]
  end

  def request(uri, klass, dry_run = false)
    uri = URI.parse(uri) if uri.instance_of?(String)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    
    request = klass.new(uri.request_uri)
    request['Content-Type'] = 'application/json'
    request['X-DocBaseToken'] = load_token
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

  def upload_and_substitute_images(team, body, dir)
    body = body.clone
    # to do: normalize path
    paths = body.scan(/!\[[^\[\]]*\]\(([^\(\)]*)\)/).flatten.uniq 
    paths.each do |path|
      original_path = path.clone
      uri = URI.parse(path)
      should_upload = false
      case uri
      when URI::HTTP, URI::HTTPS
        should_upload = true if 'all' == options[:upload]
      when URI::FTP
        should_upload = true
      when URI::Generic
        should_upload = true
        path = File.expand_path(path, dir)
      else
        error "cannot upload the following image: #{path}"
        exit 1
      end
      next unless should_upload
      content = nil
      say "reading and uploading: #{path} ... "
      open(path) { |f| content = f.read }
      json = {
        name:    File.basename(path),
        content: Base64.strict_encode64(content)
      }.to_json
      response = post("https://api.docbase.io/teams/#{team}/attachments", json)
      say "done (remaining quota: #{response['x-ratelimit-remaining']}/#{response['x-ratelimit-limit']})"
      body.gsub!(/!\[([^\[\]]*)\]\(#{original_path}\)/, JSON.parse(response.body)['markdown'])
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

