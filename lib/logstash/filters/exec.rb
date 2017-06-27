# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "shellwords"
require "childprocess"
require "tempfile"
require "bundler"

ChildProcess.posix_spawn = true

class LogStash::Filters::Exec < LogStash::Filters::Base
  config_name "exec"

  config :message, :validate => :string, :default => "Hello World!", :required => true
  config :cmd, :validate => :string
  config :timeout, :validate => :number, :default => 60 * 60 * 60 # 1 hr
  config :target, :validate => :string, :default => "[@metadata][cmd_response]", :required => true
  config :directory, :validate => :string

  public
  def register
  end

  public
  def filter(event)
    directory = event.sprintf(@directory) if @directory
    cmd = Shellwords.split(event.sprintf(@cmd))

    process = ChildProcess.build(*cmd)

    stderr = Tempfile.new("stderr")
    stdout = Tempfile.new("stdout")

    process.io.stdout = stdout
    process.io.stderr = stderr

    process.cwd = directory if @directory

    Bundler.with_clean_env do
      process.start
      process.poll_for_exit(timeout)
    end

    stderr.rewind
    stdout.rewind

    response = {
      "exit_code" => process.exit_code,
      "stderr" => stderr.read,
      "stdout" => stdout.read,
      "directory" => directory,
      "cmd" => @cmd
    }

    @logger.debug("Command ran successfully", :cmd => @cmd, :directory => directory)

    event.set(@target, response)
    filter_matched(event)
  rescue => e
    response = {
      "exit_code" => 1,
      "stderr" => stderr.read,
      "directory" => directory,
      "cmd" => @cmd,
      "stdout" => stdout.read,
      "exception" => {
        "name" => e.class.name,
        "message" => e.message
      }
    }

    @logger.debug("Command failed", :cmd => cmd, :directory => directory, :message => e.message, :class => e.class.name)

    event.set(@target, response)
    filter_matched(event)
  ensure
    stdout.close if stdout
    stderr.close if stderr
  end
end
