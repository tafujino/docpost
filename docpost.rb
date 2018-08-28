#!/usr/bin/env ruby

require 'thor'
require 'base64'
require 'net/http'
require 'uri'
require 'open-uri'
require 'json'
require 'yaml'
require 'fileutils'
require 'open3'
require 'pathname'
require 'active_support'
require 'active_support/core_ext'
require 'stringio'
require 'tmpdir'
require 'tempfile'

MAX_CHAR_NUM  = 50000
UUID_CHAR_NUM = 36

class DocPost < Thor
  class << self
    attr_reader :conf, :default, :options_table, :path

    private

    def load_config(path)
      conf = File.exist?(path) ? YAML.load_file(path) : { }
      conf.with_indifferent_access
    end

    def eval_options(cmd)
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
  @conf = {
    default:
      {
        submit:
          {
            scope:  'private',
            tags:   [],
            draft:  false,
            notice: true,
            upload: 'standard',
          },
      },
    groups:
      {
        name:
          { }
      },
    path:
      {
        conf:     @docpost_dir + 'conf.yaml',
        R:        nil,
        token:    @docpost_dir + 'token.yaml',
        database: @docpost_dir + 'database.yaml',
      }
  }.with_indifferent_access

  # should forbid from loading keys undefined in the above
  @conf.deep_merge!(load_config(conf[:path][:conf]))
  @default = @conf[:default]
  @options_table = { }.with_indifferent_access

  class_option :mode, enum: %w[force ask reluctant], default: 'ask', aliases: :'-m'

  desc 'database {update, clear, status}', 'Update, clear or show status of teams and groups database'
  def database(arg)
  end

  desc 'log', 'Show log'
  def log
  end

  # for teams retrieval,  see https://help.docbase.io/posts/92977
  # for groups retrieval, see https://help.docbase.io/posts/92978
  desc 'print {teams, groups [TEAM ...]}', 'Print list of teams or groups'
  def print(*args)
    if args.empty?
      help('print')
      exit 1
    end

    if File.exist?(@path[:database])
      begin
        db = YAML.load_file(@path[:database])
      rescue
        error "loading database failed: #{@path[:database]}"
        exit 1
      end
    else
      db = { }
    end
    db = db.with_indifferent_access

    check_token_existence
    target = args.shift
    case target
    when 'teams'
      should_use_api = !db.key?(:teams)
      if should_use_api
        response = get('https://api.docbase.io/teams')
        handle_response_code(response)
        db[:teams] = JSON.parse(response.body)
      end
      db[:teams].each do |h|
        say "domain = #{h['domain']}, name = #{h['name']}"
      end
      say
      if should_use_api
        handle_quota(response)
        say
      end
    when 'groups'
      teams = args.empty? ? @default[:print][:groups][:teams] : args
      unless teams
        error 'no team is specified'
        exit 1
      end
      db[:groups] = { } unless db.key?(:groups)
      teams.each do |team|
        say "team: #{team}"
        should_use_api = !db[:groups].key?(team)
        if should_use_api
          response = get("https://api.docbase.io/teams/#{team}/groups")
          handle_response_code(response)
          db[:groups][team] = JSON.parse(response.body)
        end
        text_list = db[:groups][team].map do |h|
          names = @groups_name[h['id']]
          [h['id'].to_s + (names ? " (#{names.join(', ')})" : ''), h['name']]
        end
        label_len = text_list.map(&:first).map(&:size).max
        text_list.each do |label, desc|
          say label + ' ' * (label_len - label.size) + ': ' + desc
        end
        say
        if should_use_api
          handle_quota(response)
          say
        end
      end
    else
      help('print')
      exit 1
    end
    FileUtils.mkpath(File.dirname(@path[:database]))
    YAML.dump(db.to_hash, File.open(@path[:database], 'w'))
  end

  desc 'submit [FILE] [options]', 'Submit (R) Markdown text to DocBase (read from STDIN when FILE is unspecified)'
  # for available parameters, see https://help.docbase.io/posts/92980
  # option priority: 1. options in YAML 2. options from a command line 3. in document (i.e. R Markdown title) 4. default
  @options_table[:submit] = [
    { option: :teams,   type: :array,                     default: default[:submit][:teams]                   },
    { option: :title,   type: :string,                    default: ''                                         },
    { option: :body,    type: :string,                                                        cmdline:  false },
    { option: :tags,    type: :array,                     default: default[:submit][:tag]                     },
    { option: :groups,  type: :array,                     default: default[:submit][:groups]                  },
    { option: :draft,   type: :boolean,                   default: default[:submit][:draft]                   },
    { option: :scope,   enum: %w[everyone group private], default: default[:submit][:scope]                   },
    { option: :notice,  type: :boolean,                   default: default[:submit][:notice]                  },
    { option: :type,    enum: %w[md Rmd yaml],                                                loadable: false },
    { option: :type,    enum: %w[md Rmd],                                                     cmdline:  false },
    { option: :dry_run, type: :boolean,                   default: false,                     loadable: false },
    { option: :upload,  enum: %w[full standard],          default: default[:submit][:upload]                  },
  ]
  eval_options(:submit)
  def submit(path = nil)
    check_token_existence
    path, opts = submit_get_options(path, options)

    if 'group' != opts[:scope] && opts[:groups]
      error 'option "scope" should be "group" when group(s) are specified'
      help('submit')
      exit 1
    end
    if 'group' == opts[:scope] && (!opts[:groups] || opts[:groups].empty?)
      error 'should specify group(s) when scope is "group"'
      help('submit')
      exit 1
    end

    if opts[:groups]
      opts[:groups].map! do |group|
        if group =~ /^\d/
          group
        else
          v = @groups_dict[group]
          unless v
            error "cannot find group: #{group}"
            exit 1
          end
          v
        end
      end
    end

    body, dir, title = submit_get_body(path, opts[:type], opts[:title])
    opts[:teams].each do |team|
      body = upload_and_substitute_contents(team, body, dir, dry_run: opts[:dry_run])
      if body.size >= MAX_CHAR_NUM
        ask_continue("the number of letters after embedding contents is >= #{MAX_CHAR_NUM}.")
      end
      json = {
        title:  title,
        body:   body,
        draft:  opts[:draft],
        scope:  opts[:scope],
        tags:   opts[:tags],
        groups: opts[:groups],
        notice: opts[:notice],
      }.compact.to_json

      say '(dry_run) ' if opts[:dry_run]
      say 'submitting' + (path ? ": #{path}" : '') + ' ... '
      response = post("https://api.docbase.io/teams/#{team}/posts", json, opts[:dry_run])
      if opts[:dry_run]
        say " done"
      else
        handle_response_code(response)
        handle_quota(response)
      end
      say
    end
  end

  desc 'token {set, clear, status}', 'Set, clear or show status of token'
  def token(arg)
    case arg
    when 'set'
      token = ask('type new token:', :echo => false)
      if token.blank?
        error 'invalid token'
        exit 1
      end
      path = @path[:token]
      begin
        token_dir = File.dirname(path)
        FileUtils.mkpath(token_dir)
        FileUtils.chmod(0700, token_dir)
        YAML.dump({ token: token }, File.open(path, 'w'))
        FileUtils.chmod(0600, path)
      rescue
        error "failed to update token: #{path}"
        exit 1
      end
      say 'update succeeded'
    when 'clear'
      path = @path[:token]
      FileUtils.rm(path) if File.exist?(path)
    when 'status'
      check_token_permission
      path = @path[:token]
      if path.present? && File.exist?(path)
        begin
          raise unless YAML.load_file(path).key?(:token)
          say 'token is registered'
        rescue
          say 'token file may be invalid'
        end
      else
        say 'token is not registered'
      end
      say
    else
      help('token')
      exit 1
    end
  end

  desc 'upload [{FILE,URI} ...]', 'Upload content to DocBase (read from STDIN when FILE or URI is unspecified)'
  @options_table[:upload] = [
    { option: :teams,            type: :array,   default: default[:upload][:teams]                            },
    { option: :name,             type: :string,  default: ''                                 , aliases: :'-n' },
  ]
  eval_options(:upload)
  def upload(*path_list)
    if path_list.empty?
      h = { content: STDIN.read }
      h[:name] = options[:name] if options[:name]
      upload_list = [h]
    else
      upload_list = path_list.map { |path| { path: path } }
      error 'option "--name" is valid only when content is read from STDIN' if options[:name].present? # only warn, not abort
    end
    markdown_list = []
    if !options[:teams] || options[:teams].empty?
      error "no team is specified"
      exit 1
    end
    options[:teams].each do |team|
      say "#{team}:"
      markdown_list = upload_contents(team, upload_list)
      markdown_list.each do |markdown|
        say markdown, :green
      end
      say
    end
  end

  desc 'version', 'Show version'
  def version
    say '0.1'
  end

  no_commands do

    def initialize(args = [], options = { }, config = { })
      @conf = DocPost.conf
      @path = @conf[:path]
      @default = DocPost.default
      init_groups_name
      @options_table = DocPost.options_table
      check_token_permission
      super(args, options, config)
    end

    def config_file_error(msg)
      error msg + "\nmodify #{@path[:conf]}"
      exit 1
    end

    def init_groups_name
      # should check default value for groups contains only groups name or numbers
      if DocPost.conf.key?(:groups_name)
        @groups_name = DocPost.conf[:groups_name].map do |k, v|
          [k, v.instance_of?(Array) ? v : [v]]
        end.to_h.with_indifferent_access
      else
        @groups_name = { }
      end
      @groups_dict = { }
      @groups_name.each do |k, v|
        v.each do |name|
          config_file_error "group names cannot begin with a number: \"#{name}\"" if name =~ /^\d/
          config_file_error "group name is duplicate: \"#{name}\"" if @groups_dict.key?(name)
          @groups_dict[name] = k
        end
      end
    end

    def submit_get_options(path, options)
      if 'yaml' == options[:type] || (!options[:type] && path && File.extname(path) =~ /^\.ya?ml$/i)
        if path
          new_options = load_options_yaml(:submit, path)
        else
          begin
            new_options = YAML.load(STDIN)
          rescue
            error 'load from STDIN failed. may be invalid YAML'
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

    def submit_get_body(in_path, opt_type, opt_title)
      check_title = proc do
        if opt_title.blank?
          error 'title is missing'
          help('submit')
          exit 1
        end
      end

      if in_path
        in_path = Pathname.new(in_path)
        dir = File.dirname(in_path)
        unless File.exist?(in_path)
          error "file not exist: #{in_path}"
          exit 1
        end
        body = File.read(in_path)
        unless opt_type
          ext = File.extname(in_path)
          case ext
          when /^\.md$/i
            file_type = 'md'
            check_title.call
            return body, dir, opt_title
          when /^\.Rmd$/i
            file_type = 'Rmd'
            out_path = in_path.sub_ext('.md')
            opt_title = extract_title_from_rmarkdown(File.read(in_path)) if opt_title.blank?
            check_title.call
            render_rmarkdown(in_path)
            body = File.read(out_path)
            return body, dir, opt_title
          else
            error "cannot determine file type: #{path}"
            exit 1
          end
        end
      else
        case opt_type
        when 'Rmd'
          body = STDIN.read
          opt_title = extract_title_from_rmarkdown(body) if opt_title.blank?
          check_title.call
          Dir.mktmpdir do |dir|
            in_file  = Tempfile.new(['', '.Rmd'], tempdir = dir)
            out_file = Tempfile.new(['', '.md'],  tempdir = dir)
            File.write(in_file, body)
            render_rmarkdown(in_file.path)
            body = File.read(out_file)
            return body, dir, opt_title
          end
        when 'md'
          check_title.call
          return STDIN.read, Dir.pwd, opt_title
        else
          check_title.call
          say 'supposing file type is Markdown ... '
          return STDIN.read, Dir.pwd, opt_title
        end
      end
    end

    def extract_title_from_rmarkdown(body)
      is_in_yaml = false
      sio_yaml = StringIO.open('', 'w')
      StringIO.open(body) do |sio_body|
        sio_body.each do |line|
          line.chomp!
          next if line.empty?
          if line =~ /^\-\-\-/
            if is_in_yaml
              break
            else
              is_in_yaml = true
            end
          else
            sio_yaml.puts line if is_in_yaml
          end
        end
      end
      YAML.load(sio_yaml.string).with_indifferent_access[:title]
    end

    def render_rmarkdown(path, verbose: true)
      r_cmd = <<EOS
library("rmarkdown")
render("#{path}", md_document(pandoc_args="--wrap=preserve"))
EOS
      ret = nil
      Open3.popen3("#{@path[:R]} --slave --vanilla") do |i, o, e, w|
        i.puts r_cmd
        i.close
        o.each { |line| puts        line; STDOUT.flush } if verbose
        e.each { |line| STDERR.puts line; STDERR.flush } if verbose
        ret = w.value
      end
      ret
    end

    def load_options_yaml(cmd, path)
      unless File.exist?(path)
        error "file not exist: #{path}"
        exit 1
      end
      begin
        opts = YAML.load_file(path).with_indifferent_access
      rescue
        error "load failed. may be invalid YAML: #{path}"
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
        a = @options_table[cmd].select do |h|
          key == h[:option].to_s && !(h[:loadable] && false == h[:loadable])
        end
        error_invalid_key.call if a.empty?
        h = a.shift
        unless a.empty?
          error "duplicate option: #{key}"
          exit 1
        end
        if h.key?(:type)
          type_to_class = {
            boolean: [TrueClass, FalseClass],
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
          unless h[:enum].include?(value)
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

    def check_permission(path, mode, desc)
      return unless path.present?
      return unless File.exist?(path)
      permission = ('%o' % File.stat(path).mode)[-3, 3]
      mode_oct_str = mode.to_s(8)
      unless mode_oct_str == permission
        error "currently #{desc} is set to mode #{permission}"
        begin
          FileUtils.chmod(mode, path)
          say "changed to mode #{mode_oct_str}: #{path}"
        rescue
          error "unable to change permission: #{path}"
          exit 1
        end
      end
    end

    def check_token_permission
      check_permission(@path[:token].dirname, 0700, 'token file directory')
      check_permission(@path[:token],         0600, 'token file')
    end

    def load_token
      check_token_permission
      path = @path[:token]
      if path.present? && File.exist?(path)
        begin
          token = YAML.load_file(path).with_indifferent_access
        rescue
          error 'failed to load token'
          exit 1
        end
        return token[:token] if token.present?
      end
      error 'token is not set'
      help('set')
      exit 1
    end

    def check_token_existence
      return if load_token.present?
      error 'token is empty'
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

    def upload_contents(team, upload_list, dry_run: false)
      # upload_list is an array where each element is either { path: ... } or { content: ..., name: ... }
      say '(dry_run) ' if dry_run
      upload_list.map! do |entry|
        unless entry.key?(:content)
          unless entry.key?(:path)
            error 'fatal error. both path and content are not specified when uploading'
            exit 1
          end
          entry[:name] ||= File.basename(entry[:path])
          begin
            open(entry[:path]) { |f| entry[:content] = f.read }
          rescue
            error "reading #{entry[:path]} failed"
            exit 1
          end
        end
        entry[:name] = 'upload_content' if entry[:name].blank?
        entry[:name] = Pathname.new(entry[:name])
        case entry[:name].extname
        when /^\.jpe?g$/i, /^\.png$/i, /^\.gif$/i, /^\.svg$/i, /^\.pdf$/i, /^\.txt$/i
          has_added_text_ext = false
        else
          say 'supposing file type is plain text ... '
          ext = entry[:name].extname + '.txt'
          entry[:name] = entry[:name].sub_ext(ext)
          has_added_text_ext = true
        end
        {
          payload:
            {
              name:    entry[:name].to_s,
              content: Base64.strict_encode64(entry[:content])
            },
          has_added_text_ext: has_added_text_ext
        }
      end
      return [] if dry_run
      response = post("https://api.docbase.io/teams/#{team}/attachments",
                      upload_list.map { |entry| entry[:payload] }.to_json)
      handle_response_code(response)
      handle_quota(response)
      markdown_list = JSON.parse(response.body).map { |entry| entry["markdown"] }
      has_added_text_ext_list = upload_list.map { |entry| entry[:has_added_text_ext] }
      markdown_list = markdown_list.zip(has_added_text_ext_list).map do |markdown, has_added_text_ext|
        markdown.gsub!(/^\[!\[txt\]\((.+)\)\s(.+)\.txt\]\((.+)\)$/, '[![txt](\1) \2](\3)') if has_added_text_ext
        markdown
      end
      markdown_list
    end

    def upload_and_substitute_contents(team, body, dir, dry_run: false)
      contents = body.scan(/\!?\[(.+)\]\((.+)\)/).group_by(&:last).map do |k, v|
        [k, v.map(&:first)]
      end.to_h
      expected_body_size = body.size
      contents = contents.map do |path, labels|
        uri = URI.parse(path)
        case uri
        when URI::HTTP, URI::HTTPS, URI::FTP
          next unless 'full' == options[:upload]
          upload_path = path
        when URI::Generic
          upload_path = File.expand_path(path, dir)
        else
          error "cannot determine the location of the following content: #{path}"
          exit 1
        end
        expected_body_size += UUID_CHAR_NUM - Pathname.new(path).basename.sub_ext('').to_s.size
        {
          original_path: path,
          upload_path:   upload_path,
          labels:        labels,
        }
      end.compact
      return if contents.empty?
      if expected_body_size >= MAX_CHAR_NUM
        ask_continue("the expected number of letters after embedding contents is >= #{MAX_CHAR_NUM}.")
      end
      say 'uploading contents within the document ... '
      if dry_run
        say 'done'
        return body
      end
      markdown_list = upload_contents(team,
                                      contents.map { |entry| { path: entry[:upload_path] } },
                                      dry_run: dry_run)
      markdown_list.zip(contents).each do |markdown, entry|
        entry[:labels].each do |label|
          markdown_with_original_caption = markdown.gsub(/( |\[)([^\[\]]*)\]\(([^\(\)]*)\)$/,
                                                         "\\1#{label}](\\3)")
          r = Regexp.compile('!?' + Regexp.escape("[#{label}](#{entry[:original_path]})"))
          body.gsub!(r, markdown_with_original_caption)
        end
      end
      body
    end

    def handle_response_code(response)
      case response.code.to_i
      when 200
      when 201
        say 'uploaded'
      when 204
        say 'removed'
      when 400
        error 'invalid request'
        exit 1
      when 403
        error 'invalid token or non-existent team is specified'
        exit 1
      when 404
        error 'accessed to non-existent URL'
        exit 1
      when 413
        error 'request entry too large'
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
      say "remaining quota: #{response['x-ratelimit-remaining']}/#{response['x-ratelimit-limit']}, "
      say "to be reset at: #{Time.at(response['x-ratelimit-reset'].to_i)}"
    end

    def ask_continue(msg)
      case options[:mode]
      when 'force'
        should_continue = true
      when 'ask'
        should_continue = yes?(msg + ' continue?')
      when 'reluctant'
        should_continue = false
      else
        error "invalid mode: #{mode}"
        exit 1
      end
      unless should_continue
        error 'aborted'
        exit 1
      end
    end

  end
end

if $PROGRAM_NAME == __FILE__
  DocPost.start(ARGV)
end
