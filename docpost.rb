#!/usr/bin/env ruby

require 'thor'
require 'base64'
require 'net/http'
require 'uri'
require 'open-uri'
require 'json'
require 'fileutils'
require 'pathname'
require 'active_support'
require 'active_support/core_ext'

MaxCharNum = 50000
AlertCharNum = MaxCharNum - 100

class DocPost < Thor
  class << self
    attr_reader :conf, :default, :options_table

    private

    def load_config(path)
      conf = File.exist?(path) ? File.open(path) { |f| JSON.load(f) } : { }
      conf.with_indifferent_access
    end

    def eval_option(cmd)
      @options_table[cmd].each do |h|
        next if h.key?(:cmdline) && (false == h[:cmdline])
        h = h.clone
        h.delete(:loadable)
        o = h.delete(:option)
        option(o, h)
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
                 upload:
                   { list_markdown: false,
                   }
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

  class_option :version, :type => :boolean
  map '--version' => :version

  desc 'sub [FILE] [options]', 'Submit (r)markdown text to DocBase (read from STDIN when FILE is unspecified)'
  # for available parameters, see https://help.docbase.io/posts/92980
  # option priority: 1. options in JSON 2. options from a command line 3. in document (i.e. R Markdown title) 4. default
  @options_table[:sub] = [
    { option: :teams,   type: :array,                     default: default[:sub][:teams]                   },
    { option: :title,   type: :string,                    default: ''                                      },
    { option: :body,    type: :string,                                                     cmdline:  false },
    { option: :tags,    type: :array,                     default: default[:sub][:tag]                     },
    { option: :groups,  type: :array,                     default: default[:sub][:groups]                  },
    { option: :draft,   type: :boolean,                   default: default[:sub][:draft]                   },
    { option: :scope,   enum: %w[everyone group private], default: default[:sub][:scope]                   },
    { option: :notice,  type: :boolean,                   default: default[:sub][:notice]                  },
    { option: :type,    enum: %w[md Rmd json],                                             loadable: false },
    { option: :type,    enum: %w[md Rmd],                                                  cmdline:  false },
    { option: :mode,    enum: %w[force ask quit],         default: 'ask'                                   },
    { option: :dry_run, type: :boolean,                   default: false,                  loadable: false },
    { option: :upload,  enum: %w[full standard],          default: default[:sub][:upload]                  },
  ]
  eval_option(:sub)
  def sub(path = nil)
    check_token
    path, opts = sub_get_options(path, options)

    check_title = proc do 
      if opts[:title].blank?
        error "title is missing"
        help('sub')
        exit 1
      end
    end

    if path
      dir = File.dirname(path)
      unless File.exist?(path)
        error "file not exist: #{path}"
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
          error "cannot determine file type: #{path}"
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
      error "option \"scope\" should be \"group\" when group(s) are specified"
      help('sub')
      exit 1
    end
    if 'group' == opts[:scope] && (!opts[:groups] || opts[:groups].empty?)
      error "should specify group(s) when scope is \"group\""
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
      handle_response_code(response)
      handle_quota(response)
      puts
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
      handle_response_code(response)
      handle_quota(response)
      puts
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
        handle_response_code(response)
        handle_quota(response)
        puts
      end
    end
  end

  desc 'set token', 'Set token'
  def set(arg)
    unless 'token' == arg
      help('set')
      exit 1
    end
    token = ask("type new token:", :echo => false)
    if token.blank?
      error "invalid token"
      exit 1
    end
    path = @conf[:path][:token]
    begin
      File.open(path, 'w') do |f|
        f.puts JSON.pretty_generate({ token: token })
      end
    rescue
      error "failed to update token"
      exit 1
    end
    say "update succeeded"
  end

  desc 'remove token', 'Remove token'
  def remove(arg)
    path = @conf[:path][:token]
    FileUtils.rm(path) if File.exist?(path)
  end

  desc 'update database', 'Update teams and groups database'
  def update(arg)
  end

  desc 'upload {FILE,URI}S', 'Upload content to DocBase'
  @options_table[:upload] = [
    { option: :teams,         type: :array,   default: default[:upload][:teams]                         },
    { option: :list_markdown, type: :boolean, default: default[:upload][:list_markdown], aliases: :'-l' },
  ]
  eval_option(:upload)
  def upload(*path_list)
    if path_list.empty?
      help('upload')
      exit 1
    end
    markdown_list = []
    options[:teams].each do |team|
      path_list.each do |path|
        response = upload_file(team, path)
        handle_response_code(response)
        markdown = JSON.parse(response.body)['markdown']
        markdown_list.push(markdown)
        say "markdown: "
        say markdown, :green
        handle_quota(response)
        puts
      end
    end
    say "all files uploaded"
    say
    if options[:list_markdown]
      say 'markdown list:'
      markdown_list.each do |markdown|
        say markdown, :green
      end
    end
  end

  desc 'version', 'Show version'
  def version
    puts '0.1'
  end

  no_commands do

    def initialize(args = [], options = { }, config = { })
      @conf = DocPost.conf
      @default = DocPost.default
      @options_table = DocPost.options_table
      super(args, options, config)
    end

    def sub_get_options(path, options)
      if 'json' == options[:type] || (!options[:type] && path && File.extname(path) =~ /^\.json$/i)
        if path
          new_options = load_options_json(:sub, path)
        else
          begin
            new_options = JSON.load(STDIN)
          rescue
            error "load from STDIN failed. may be invalid JSON"
            exit 1
          end
        end
        new_path = File.expand_path(new_options[:body], File.dirname(path))
        new_options = options.dup.deep_merge!(new_options.reject { |key, _| 'body' == key })
      else
        new_path = path
        new_options = options
      end
      [new_path, new_options]
    end

    def load_options_json(cmd, path)
      unless File.exist?(path)
        error "file not exist: #{path}"
        exit 1
      end
      begin
        opts = File.open(path) { |f| JSON.load(f).with_indifferent_access }
      rescue
        error "load failed. may be invalid JSON: #{path}"
        exit 1
      end
      unless opts.key?(:body)
        error "should contain \"body\" key: #{path}"
        exit 1
      end

      opts.each do |key, value|
        error_invalid_key = proc do
          error "invalid key \"#{key}\" in #{path}"
          exit 1
        end
        a = @options_table[cmd].select { |h| key == h[:option].to_s && !(h[:loadable] && false == h[:loadable]) }
        error_invalid_key.call if a.empty?
        h = a.shift
        unless a.empty?
          error "duplicate option: #{key}"
          exit 1
        end
        if h.key?(:type)
          type_to_class = { boolen:  [TrueClass, FalseClass],
                            string:  [String],
                            numeric: [Numeric],
                            array:   [Array],
                            hash:    [Hash]
                          }
          is_correct_type = type_to_class[h[:type]].inject(false) do |ret, klass|
            ret ||= opts[key].instance_of?(klass)
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
          error "cannot handle key \"#{key}\""
          exit 1
        end
      end
      opts
    end

    def check_token
      return if load_token.present?
      error 'token is not registered'
      help('set')
      exit 1
    end

    def load_token
      path = @conf[:path][:token]
      if path.present? && File.exist?(path)
        begin
          token = File.open(path) { |f| JSON.load(f).with_indifferent_access }
        rescue
          error "failed to load token"
          exit 1
        end
        return token[:token] if token.present?
      end
      error "token is not set"
      help('set')
      exit 1
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

    def upload_file(team, path, name: nil)
      name ||= File.basename(path)
      say "reading and uploading: #{path} ... "
      content = nil
      open(path) { |f| content = f.read }
      json = {
        name:    name,
        content: Base64.strict_encode64(content)
      }.to_json
      response = post("https://api.docbase.io/teams/#{team}/attachments", json)
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
        response = upload(team, path)
        say "done (remaining quota: #{response['x-ratelimit-remaining']}/#{response['x-ratelimit-limit']})"
        body.gsub!(/!\[([^\[\]]*)\]\(#{original_path}\)/, JSON.parse(response.body)['markdown'])
      end
      body
    end

    def handle_response_code(response)
      case response.code.to_i
      when 200
      when 201
        say 'successfully uploaded'
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
    end

    def handle_quota(response)
      say "remaining quota: #{response['x-ratelimit-remaining']}/#{response['x-ratelimit-limit']}, to be reset at: #{Time.at(response['x-ratelimit-reset'].to_i)}"
    end

  end
end

if $PROGRAM_NAME == __FILE__
  DocPost.start(ARGV)
end

