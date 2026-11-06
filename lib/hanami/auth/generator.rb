# frozen_string_literal: true

require "erb"
require "hanami/cli"
require "securerandom"

module Hanami
  module Auth
    # Raised when an app or slice already has authentication for a different model.
    #
    # @api private
    class ExistingAuthenticationError < Hanami::CLI::Error
      def initialize(location:, existing:, model:)
        super(<<~TEXT.chomp)
          #{location} already has authentication for #{existing}, and it can only have one model's.
          Generate #{model} authentication into a slice instead: hanami generate auth #{model} --slice=NAME
        TEXT
      end
    end

    # Writes the authentication code into an app or slice.
    #
    # Files under `templates/base/` are written relative to the app's `app/` dir or the slice's root;
    # `templates/migrate/` holds the migrations. Changes to existing files (Gemfile, settings, routes
    # and so on) are made by small, idempotent text injections, which skip any change already present.
    #
    # @api private
    class Generator
      TEMPLATES = File.join(__dir__, "templates")

      DEFAULT_MODEL = "user"

      # Gems the generated code needs, added to the Gemfile when missing.
      GEMS = {
        "argon2" => %(gem "argon2", "~> 2.3"),
        "dry-operation" => %(gem "dry-operation", ">= 1.0.1"),
        "dry-validation" => %(gem "dry-validation", "~> 1.11"),
        "i18n" => %(gem "i18n", "~> 1.14")
      }.freeze

      TEST_FRAMEWORKS = {"rspec" => "spec", "minitest" => "test"}.freeze

      ROUTES = <<~RUBY
        resource :session, only: %i[new create destroy]
        resources :passwords, only: %i[new create edit update]
      RUBY

      attr_reader :fs, :inflector, :out, :app_namespace, :slice

      # @param model [String] the singular name of the authenticated model, e.g. "user" or "admin"
      # @param test_framework [String, nil] "rspec", "minitest", or nil to skip tests
      def initialize(fs:, inflector:, out:, app_namespace:, model: DEFAULT_MODEL, slice: nil, force: false,
                     test_framework: nil, turbo: false)
        @fs = fs
        @inflector = inflector
        @out = out
        @app_namespace = app_namespace
        @model = inflector.underscore(inflector.singularize(model))
        @slice = slice
        @force = force
        @test_framework = test_framework
        @turbo = turbo
        @gemfile_changed = false
      end

      def call
        check_existing_authentication

        generate_files
        generate_translations
        generate_migrations
        generate_tests if test_framework

        inject_gems
        ensure_operation_base
        ensure_result_monads
        inject_settings
        inject_session_secrets
        inject_sessions_config
        inject_action_include
        inject_view_context
        inject_routes
        inject_layout_head if turbo?
      end

      def gemfile_changed? = @gemfile_changed

      def print_next_steps
        out.puts <<~TEXT

          Authentication generated. Next:

            1. Run the migrations:   bundle exec hanami db migrate
            #{"2. Add #{models}:".ljust(25)}bundle exec hanami console
                                     > #{container}["repos.#{model}_repo"].create(email_address: "you@example.com", password: "a long password")
            3. Sign in at #{sign_in_path}

          Every #{namespace} action now requires a signed-in #{model}. Opt an action out with:

            class Home < #{namespace}::Action
              allow_unauthenticated_access
            end

          In production, set SESSION_SECRET (at least 64 characters; generate one with
          `ruby -rsecurerandom -e 'puts SecureRandom.hex(64)'`) and configure SMTP for password reset emails.
        TEXT
      end

      # Template context

      def namespace = slice? ? inflector.camelize(slice) : app_namespace
      def slice? = !slice.nil?
      def turbo? = @turbo
      def force? = @force
      attr_reader :test_framework

      # Model naming. The default "user" model keeps plain names (`users`, `sessions`); any other
      # model prefixes its sessions table (`admins`, `admin_sessions`), so a slice's model can share a
      # database with the app's.
      attr_reader :model
      def models = inflector.pluralize(model)
      def model_class = inflector.camelize(model)
      def models_class = inflector.camelize(models)
      def foreign_key = "#{model}_id"
      def sessions_table = model == DEFAULT_MODEL ? "sessions" : "#{model}_sessions"
      def sessions_class = inflector.camelize(sessions_table)
      def session_repo = "#{inflector.singularize(sessions_table)}_repo"
      def session_repo_class = inflector.camelize(session_repo)

      # Prefixes minitest class names so tests for several models or slices don't collide.
      def test_class_prefix = [(namespace if slice?), (model_class unless model == DEFAULT_MODEL)].compact.uniq.join

      # Where the generated components are resolved from, in tests and the console.
      def container = slice? ? "#{namespace}::Slice" : "Hanami.app"

      # URL paths, for tests and messages.
      def path_prefix
        return "" unless slice?

        routes = fs.exist?("config/routes.rb") ? fs.read("config/routes.rb") : ""
        routes[/^\s*slice :#{slice}\b.*?at: ["']([^"']*)["']/, 1]&.chomp("/") || "/#{slice}"
      end

      def sign_in_path = "#{path_prefix}/session/new"
      def session_path = "#{path_prefix}/session"
      def new_password_path = "#{path_prefix}/passwords/new"
      def passwords_path = "#{path_prefix}/passwords"

      # Extra arguments for the test helper's `sign_in_as`, which defaults to the app's sign-in path.
      def sign_in_args = slice? ? %(, path: "#{session_path}") : ""

      # Returns the route name for use in templates. Routes inside a `slice` block take the slice name
      # after any `new_`/`edit_` prefix: `new_session` becomes `new_admin_session`.
      def route(name)
        return name.to_sym unless slice?

        action, base = name.to_s.match(/\A(?:(new|edit)_)?(.+)\z/).captures
        [action, slice, base].compact.join("_").to_sym
      end

      def env_key = "#{inflector.underscore(namespace)}.authentication.session"

      # Names this app's or slice's token in the Rack session, which the app and its slices share.
      def token_key = inflector.underscore(namespace)

      def home_path = path_prefix.empty? ? "/" : path_prefix

      def cookie_key = "#{inflector.underscore(app_namespace)}.session"

      private

      def base_path = slice? ? fs.join("slices", slice) : "app"

      # The app's own files (settings, app config) always live at the root.
      def app_file(*path) = fs.join(*path)

      # An app or slice has one Authentication module, and one set of session and password actions and
      # routes, so a second model there would get its tables and repos but nothing that uses them.
      # Running again for the same model is fine.
      def check_existing_authentication
        path = fs.join(base_path, "authentication.rb")
        return if !fs.exist?(path) || fs.exist?(fs.join(base_path, "repos", "#{model}_repo.rb"))

        raise ExistingAuthenticationError.new(
          location: slice? ? "The #{slice} slice" : "app/",
          existing: fs.read(path)[/def current_(?!session\b)(\w+)\(request\)/, 1] || "another model",
          model:
        )
      end

      def generate_files
        each_template("base") do |relative_path, source|
          create(fs.join(base_path, expand_path(relative_path)), render(source))
        end
      end

      # The app's translations live in its root config/i18n, and a slice's in its own.
      def generate_translations
        dir = slice? ? fs.join(base_path, "config", "i18n") : fs.join("config", "i18n")
        create(fs.join(dir, "authentication.en.yml"), render(read_template("i18n/authentication.en.yml.erb")))
      end

      def generate_migrations
        dir = migrations_dir
        timestamp = Time.now # local time, as `hanami generate migration` uses

        {
          "create_models" => "create_#{models}",
          "create_sessions" => "create_#{sessions_table}",
          "create_rate_limits" => "create_rate_limits"
        }
          .each_with_index do |(template, name), index|
            existing = Dir.glob(File.join(dir, "*_#{name}.rb")).first
            if existing && !force?
              skipped(existing)
              next
            end

            version = (timestamp + index).strftime("%Y%m%d%H%M%S")
            path = existing || fs.join(dir, "#{version}_#{name}.rb")
            fs.write(path, render(read_template("migrate/#{template}.rb.erb")))
          end
      end

      # Slices with their own DB config keep their own migrations; otherwise migrations are shared
      # with the app.
      def migrations_dir
        slice_db = fs.join(base_path, "config", "db")
        slice? && fs.directory?(slice_db) ? fs.join(slice_db, "migrate") : fs.join("config", "db", "migrate")
      end

      def generate_tests
        root = TEST_FRAMEWORKS.fetch(test_framework)

        each_template(test_framework) do |relative_path, source|
          relative_path = relative_path.sub("authentication_", "#{model}_authentication_") unless model == DEFAULT_MODEL
          shared = relative_path.start_with?("support/")
          path = slice? && !shared ? fs.join(root, "slices", slice, relative_path) : fs.join(root, relative_path)
          create(path, render(source))
        end
      end

      def inject_gems
        inject("Gemfile") do |content|
          missing = GEMS.reject { |name, _| content.match?(/^\s*gem ["']#{name}["']/) }.values
          next if missing.empty?

          @gemfile_changed = true
          if content.match?(/^group /)
            fs.inject_line_before("Gemfile", /^group /, "#{missing.join("\n")}\n\n")
          else
            fs.append("Gemfile", "\n#{missing.join("\n")}")
          end
        end
      end

      # The generated operations subclass the app's (or slice's) Operation, which `hanami new` and
      # `hanami generate slice` only create when dry-operation was already bundled.
      def ensure_operation_base
        path = fs.join(base_path, "operation.rb")
        return if fs.exist?(path)

        parent = slice? && fs.exist?(app_file("app", "operation.rb")) ? "#{app_namespace}::Operation" : "Dry::Operation"
        fs.write(path, render(read_template("operation.rb.erb")).sub("PARENT", parent))
      end

      # Actions pattern match on operation results with `Success` and `Failure`. `hanami new` includes
      # them in the app's base action when dry-operation is bundled; add them if not.
      def ensure_result_monads
        path = app_file("app", "action.rb")

        inject(path, "#{app_namespace}::Action class") do |content|
          next if content.include?("Dry::Monads[:result]")

          fs.inject_line_at_block_top(
            path, /class Action < Hanami::Action/,
            "# Provide `Success` and `Failure` for pattern matching on operation results",
            "include Dry::Monads[:result]"
          )
          fs.inject_line_after(path, %(require "hanami/action"), %(require "dry/monads")) if content.include?(%(require "hanami/action"))
        end
      end

      def inject_settings
        path = app_file("config", "settings.rb")

        inject(path, "Settings class") do |content|
          next if content.include?("setting :session_secret")

          fs.inject_line_at_block_top(
            path, /class Settings < Hanami::Settings/,
            "# Signs and encrypts the session cookie, and signs password reset tokens.",
            "setting :session_secret, constructor: Types::String.constrained(min_size: 64)",
            ""
          )
        end
      end

      def inject_session_secrets
        %w[development test].each do |env|
          path = app_file(".env.#{env}")
          line = "SESSION_SECRET=#{SecureRandom.hex(64)}"

          if !fs.exist?(path)
            fs.write(path, "# Local #{env} secret only. Set your own SESSION_SECRET in production.\n#{line}\n")
          elsif !fs.read(path).match?(/^SESSION_SECRET=/)
            fs.append(path, line)
          end
        end
      end

      def inject_sessions_config
        path = app_file("config", "app.rb")

        inject(path, "App class") do |content|
          if content.match?(/config\.actions\.sessions\s*=/)
            next if content.include?("settings.session_secret")

            notice "config/app.rb already configures sessions; make sure they're enabled with a secret."
            next
          end

          fs.inject_line_at_block_top(path, /class App < Hanami::App/, <<~RUBY)
            config.actions.sessions = :cookie, {
              key: "#{cookie_key}",
              secret: settings.session_secret,
              expire_after: 60 * 60 * 24 * 30, # 30 days, as long as sessions last in the database
              same_site: "Lax",
              httponly: true,
              secure: Hanami.env?(:production)
            }
          RUBY
        end
      end

      def inject_action_include
        path = fs.join(base_path, "action.rb")

        inject(path, "#{namespace}::Action class") do |content|
          next if content.match?(/^\s*include Authentication\b/)

          # Place it after the class's existing includes, if it has any.
          indent = content[/^(\s*)class Action < /, 1] or next missing("#{namespace}::Action class")
          include_line = /^#{indent}  include /

          if content.match?(include_line)
            fs.inject_line_after_last(path, include_line, "#{indent}  include Authentication")
          else
            fs.inject_line_at_block_top(path, /class Action < /, "include Authentication")
          end
        end
      end

      def inject_view_context
        path = fs.join(base_path, "views", "context.rb")

        inject(path, "Views::Context class") do |content|
          next if content.include?("def current_#{model}")

          fs.inject_line_at_class_bottom(
            path, /class Context < /,
            after_body(content, /class Context < /, render(read_template("context_methods.rb.erb")))
          )
        end
      end

      def inject_routes
        slice_routes = fs.join(base_path, "config", "routes.rb")

        if slice? && !fs.exist?(slice_routes)
          inject_slice_routes_block
        else
          path = slice? ? slice_routes : app_file("config", "routes.rb")

          inject(path, "Routes class") do |content|
            next if content.match?(/resource :session\b/)

            fs.inject_line_at_class_bottom(path, /class Routes < Hanami::Routes/, after_body(content, /class Routes < /, ROUTES))
          end
        end
      end

      def inject_slice_routes_block
        path = app_file("config", "routes.rb")
        slice_block = /^\s*slice :#{slice}\b.*do\s*$/

        inject(path, "Routes class") do |content|
          if content.match?(slice_block)
            next if fs.block_contains?(path, slice_block, "resource :session")

            fs.inject_line_at_block_bottom(path, slice_block, after_body(content, slice_block, ROUTES))
          else
            next if content.match?(/slice :#{slice}\b/)

            fs.inject_line_at_class_bottom(
              path, /class Routes < Hanami::Routes/,
              after_body(content, /class Routes < /, "slice :#{slice}, at: \"/#{slice}\" do\n#{ROUTES.gsub(/^/, "  ")}end")
            )
          end
        end
      end

      def inject_layout_head
        layout = fs.join(base_path, "templates", "layouts", "app.html.erb")
        layout = app_file("app", "templates", "layouts", "app.html.erb") unless fs.exist?(layout)

        inject(layout, "</head> in #{layout}") do |content|
          next if content.include?("content_for :head") || content.include?("content_for(:head)")

          indent = content[%r{^(\s*)</head>}, 1] or next missing("</head> in #{layout}")
          fs.inject_line_before(layout, "</head>", "#{indent}  <%= content_for :head %>")
        end
      end

      # Helpers

      def each_template(dir)
        root = File.join(TEMPLATES, dir)
        Dir.glob("**/*.erb", base: root).sort.each do |relative|
          yield relative.delete_suffix(".erb"), File.read(File.join(root, relative))
        end
      end

      def read_template(path) = File.read(File.join(TEMPLATES, path))

      # Expands `%name%` placeholders in template paths, e.g. `repos/%model%_repo.rb`.
      def expand_path(path) = path.gsub(/%(\w+)%/) { public_send(Regexp.last_match(1)) }

      def render(source)
        ERB.new(source, trim_mode: "-").result(binding)
      end

      def create(path, content)
        return skipped(path) if fs.exist?(path) && !force?

        fs.create(path, content, force: force?)
      end

      # Yields a file's content, to make changes to it through `fs`. Reports, rather than raises, a
      # file or target that isn't there, since the app may have been changed from how `hanami new`
      # left it.
      def inject(path, target = path)
        return missing(path) unless fs.exist?(path)

        yield fs.read(path)
      rescue Dry::Files::MissingTargetError
        missing(target)
      end

      # Separates lines added to the bottom of a class or block from the body already there.
      def after_body(content, opening, lines)
        content.match?(/#{opening}.*\n\s*end\b/) ? lines : "\n#{lines}"
      end

      def skipped(path) = out.puts("Skipped #{path} (already exists)")

      def notice(message) = out.puts("Notice: #{message}")

      def missing(what)
        out.puts "Warning: couldn't find #{what}; skipping that change. See the hanami-auth README to make it by hand."
        nil
      end
    end
  end
end
